#!/usr/bin/env python3
"""
conn_inventory.py
=================
Liao's first "eye" for active defense: take a point-in-time inventory of the
host's network connections and flag the suspicious ones for the analyst to
review.

This answers the C2 / exfiltration questions from the threat model:
"What is this machine talking to, and should it be?"

DESIGN NOTE — why this is host-aware but trust-skeptical:
A truly compromised host can lie about its own connections (a rootkit can hide
sockets). So this tool is honest about its source: it reports what the OS will
admit to, tags that source, and — crucially — never declares "all clear." A
clean-looking inventory is reported as "nothing flagged FROM THIS VANTAGE,"
not "you are safe." That distinction is baked into the output. Corroborate
anything serious from off-host (your router / Cloudflare logs).

Pythonista / iOS friendly: standard library only. iOS sandboxes process and
socket enumeration heavily, so this tool has graded data sources and degrades
LOUDLY rather than silently:

  1. psutil, if available (richest: per-connection PID + remote addr)  -- desktop
  2. `netstat` / `ss` via subprocess, if available                    -- desktop
  3. parse a pasted netstat/ss dump from another machine              -- iOS path

On iOS (Pythonista) you will most often use source (3): run netstat on a real box
(or pull connection logs from your router/Cloudflare) and feed the text in.

ok-dict return shape: {"ok": bool, ...}. Menu-return in console mode.
AUTHORIZED USE ONLY — your own hosts.
"""

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone


# --------------------------------------------------------------------------
# Heuristics / baselines. These encode the threat-model detection signals.
# Tune the allowlists to YOUR environment — that's what turns noise into signal.
# --------------------------------------------------------------------------

# RFC1918 + loopback + link-local: connections that stay local are low-interest.
_PRIVATE_PATTERNS = [
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^::1$"),
    re.compile(r"^fe80:", re.I),
    re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"^\*$"),
]

# Ports that, as a REMOTE destination, often indicate something worth a look.
# Not inherently evil — context decides. Liao reasons over these; the tool flags.
_SUSPICIOUS_REMOTE_PORTS = {
    23: "telnet (cleartext; rare for legit modern egress)",
    445: "SMB egress (lateral movement / exfil staging)",
    1080: "SOCKS proxy (tunneling)",
    3389: "RDP egress (remote control)",
    4444: "common C2 / Metasploit default",
    5555: "common backdoor / ADB",
    6667: "IRC (legacy C2 channel)",
    8333: "bitcoin p2p (cryptojacking indicator)",
    9001: "Tor ORPort",
    9050: "Tor SOCKS",
    9051: "Tor control",
}

# Destination ports that are normal for outbound traffic (lowers their interest).
_COMMON_EGRESS_PORTS = {53, 80, 123, 443, 587, 993, 995, 22}


def _is_private(ip):
    return any(p.match(ip or "") for p in _PRIVATE_PATTERNS)


def _now():
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Source parsers — each returns a list of normalized connection dicts:
#   {"proto","local_addr","local_port","remote_addr","remote_port",
#    "state","pid","process"}
# --------------------------------------------------------------------------

def _split_addr_port(token):
    """Split '1.2.3.4:443' or '[::1]:443' or '*.*' into (addr, port|None)."""
    token = token.strip()
    if token in ("*", "*.*", ""):
        return ("*", None)
    # IPv6 bracket form
    m = re.match(r"^\[(.+)\]:(\d+|\*)$", token)
    if m:
        addr, port = m.group(1), m.group(2)
        return (addr, int(port) if port.isdigit() else None)
    # Trailing :port  (also handles netstat's a.b.c.d.port with last dot)
    if ":" in token:
        addr, _, port = token.rpartition(":")
        return (addr, int(port) if port.isdigit() else None)
    if "." in token:
        addr, _, port = token.rpartition(".")
        return (addr, int(port) if port.isdigit() else None)
    return (token, None)


def from_psutil():
    """Richest source: per-connection remote addr + owning PID/process."""
    try:
        import psutil
    except ImportError:
        return None

    conns = []
    for c in psutil.net_connections(kind="inet"):
        if not c.raddr:
            continue  # listening or unconnected; we care about active talkers
        proc = None
        if c.pid:
            try:
                proc = psutil.Process(c.pid).name()
            except Exception:
                proc = None
        conns.append({
            "proto": "tcp" if c.type == 1 else "udp",
            "local_addr": c.laddr.ip if c.laddr else None,
            "local_port": c.laddr.port if c.laddr else None,
            "remote_addr": c.raddr.ip,
            "remote_port": c.raddr.port,
            "state": c.status,
            "pid": c.pid,
            "process": proc,
        })
    return conns


def from_netstat_text(text):
    """
    Parse pasted `netstat -an` / `netstat -anp` / `ss -tunap` output.
    This is the iOS path: run the command on a real host, paste the text here.
    Best-effort and forgiving — skips lines it can't parse.
    """
    conns = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("active", "proto")):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].lower()
        if not (proto.startswith("tcp") or proto.startswith("udp")):
            continue

        # Find the two address tokens (local, remote). Layouts vary by OS, so
        # locate tokens that look like addr:port or addr.port.
        addr_tokens = [
            p for p in parts
            if (":" in p or re.search(r"\.\d+$", p)) and not p.isalpha()
        ]
        if len(addr_tokens) < 2:
            continue
        local_addr, local_port = _split_addr_port(addr_tokens[0])
        remote_addr, remote_port = _split_addr_port(addr_tokens[1])

        state = None
        for tok in parts:
            if tok.upper() in (
                "ESTABLISHED", "LISTEN", "TIME_WAIT", "CLOSE_WAIT",
                "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK",
            ):
                state = tok.upper()
                break

        # ss/netstat -p sometimes append users:(("proc",pid=NNN,...))
        pid = proc = None
        m = re.search(r'"([^"]+)",pid=(\d+)', line) or re.search(
            r"(\w[\w.-]*)/(\d+)\s*$", line
        )
        if m:
            proc, pid = m.group(1), int(m.group(2))

        conns.append({
            "proto": proto[:3],
            "local_addr": local_addr,
            "local_port": local_port,
            "remote_addr": remote_addr,
            "remote_port": remote_port,
            "state": state,
            "pid": pid,
            "process": proc,
        })
    return conns


def from_system_command():
    """Try to run netstat/ss locally (desktop only; iOS will have neither)."""
    for cmd in (["ss", "-tunap"], ["netstat", "-an"]):
        if shutil.which(cmd[0]):
            try:
                out = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                ).stdout
                if out.strip():
                    return from_netstat_text(out)
            except (subprocess.SubprocessError, OSError):
                continue
    return None


# --------------------------------------------------------------------------
# Flagging — apply threat-model detection signals to each connection.
# --------------------------------------------------------------------------

def _flag_connection(conn):
    """Return a list of reason strings for why this conn is interesting."""
    reasons = []
    raddr = conn.get("remote_addr")
    rport = conn.get("remote_port")

    if raddr is None or _is_private(raddr):
        return reasons  # local/loopback/listening — not egress of interest

    if rport in _SUSPICIOUS_REMOTE_PORTS:
        reasons.append(f"suspicious remote port {rport}: "
                       f"{_SUSPICIOUS_REMOTE_PORTS[rport]}")

    # Non-standard egress port to a public IP — worth a human glance.
    if rport is not None and rport not in _COMMON_EGRESS_PORTS \
            and rport not in _SUSPICIOUS_REMOTE_PORTS:
        if rport >= 1024:
            reasons.append(f"egress to uncommon high port {rport} "
                           f"(verify the owning process)")

    # Established connection with no identifiable process is a classic
    # rootkit/injection tell — but only when we HAD process data to begin with.
    if conn.get("state") == "ESTABLISHED" and conn.get("pid") is None \
            and conn.get("_had_pid_source"):
        reasons.append("established connection with no owning process "
                       "(possible hidden/injected process)")

    return reasons


def take_inventory(source="auto", netstat_text=None):
    """
    Build the connection inventory and flag suspicious egress.

    source: "auto" | "psutil" | "command" | "text"
    netstat_text: required when source == "text" (the iOS paste path)

    Returns ok-dict:
        {
          "ok": bool,
          "collected_at": iso8601,
          "source": str,            # where the data came from
          "source_trusted": bool,   # False => corroborate off-host
          "total": int,
          "flagged": [ {conn..., "reasons": [...]}, ... ],
          "egress": [ conn, ... ],  # all public-destination connections
          "note": str,              # ALWAYS present; never implies "all clear"
          "error": str | None,
        }
    """
    conns = None
    used = None
    had_pid_source = False

    if source in ("auto", "psutil"):
        conns = from_psutil()
        if conns is not None:
            used, had_pid_source = "psutil", True

    if conns is None and source in ("auto", "command"):
        conns = from_system_command()
        if conns is not None:
            used = "system-command"

    if conns is None and source in ("auto", "text"):
        if netstat_text:
            conns = from_netstat_text(netstat_text)
            used = "pasted-text"

    if conns is None:
        return {
            "ok": False,
            "collected_at": _now(),
            "source": None,
            "source_trusted": False,
            "total": 0,
            "flagged": [],
            "egress": [],
            "note": "NO DATA SOURCE AVAILABLE. On iOS, run netstat/ss on a real "
                    "host (or pull router/Cloudflare logs) and pass the text in "
                    "via source='text'. Empty result is NOT an all-clear.",
            "error": "no_source",
        }

    egress = []
    flagged = []
    for c in conns:
        c["_had_pid_source"] = had_pid_source
        if c.get("remote_addr") and not _is_private(c["remote_addr"]):
            egress.append({k: v for k, v in c.items() if k != "_had_pid_source"})
        reasons = _flag_connection(c)
        if reasons:
            row = {k: v for k, v in c.items() if k != "_had_pid_source"}
            row["reasons"] = reasons
            flagged.append(row)

    note = (
        f"Inventory from '{used}'. {len(flagged)} connection(s) flagged out of "
        f"{len(egress)} public-egress / {len(conns)} total. "
        "This reflects only what this vantage point can see — a compromised "
        "host can hide sockets. NOT an all-clear; corroborate anything serious "
        "from off-host (router / Cloudflare)."
    )

    return {
        "ok": True,
        "collected_at": _now(),
        "source": used,
        "source_trusted": used == "psutil" or used == "system-command",
        "total": len(conns),
        "flagged": flagged,
        "egress": egress,
        "note": note,
        "error": None,
    }


def format_human(report):
    """Render the inventory for quick reading / Obsidian / pasting to Liao."""
    lines = []
    lines.append("# Connection Inventory")
    lines.append(f"Collected: {report['collected_at']}  |  "
                 f"Source: {report['source']}  |  "
                 f"Trusted vantage: {report['source_trusted']}")
    lines.append("")
    if not report["ok"]:
        lines.append(f"** {report['note']}")
        return "\n".join(lines)

    if report["flagged"]:
        lines.append(f"## FLAGGED ({len(report['flagged'])})")
        for c in report["flagged"]:
            who = c.get("process") or (f"pid {c['pid']}" if c.get("pid") else "unknown proc")
            lines.append(
                f"- {c['proto']} {c.get('remote_addr')}:{c.get('remote_port')} "
                f"[{c.get('state') or '?'}] ({who})"
            )
            for r in c["reasons"]:
                lines.append(f"    ! {r}")
    else:
        lines.append("## FLAGGED (0)")
        lines.append("  Nothing flagged from this vantage. NOT an all-clear "
                     "(see note).")
    lines.append("")
    lines.append(f"_Note: {report['note']}_")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Console runner — menu-return convention (never exits to shell mid-session).
# --------------------------------------------------------------------------

def _console():
    while True:
        print("\n=== Liao :: Connection Inventory ===")
        print("1) Auto-collect (psutil / netstat on this host)")
        print("2) Paste netstat/ss text from another host")
        print("3) Raw JSON of last auto-collect")
        print("0) Back")
        choice = input("> ").strip()

        if choice == "1":
            rep = take_inventory(source="auto")
            print("\n" + format_human(rep))
        elif choice == "2":
            print("Paste netstat/ss output, then a line with only END:")
            buf = []
            while True:
                ln = input()
                if ln.strip() == "END":
                    break
                buf.append(ln)
            rep = take_inventory(source="text", netstat_text="\n".join(buf))
            print("\n" + format_human(rep))
        elif choice == "3":
            rep = take_inventory(source="auto")
            print(json.dumps(rep, indent=2))
        elif choice == "0":
            return
        else:
            print("?")


def main():
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--json":
        print(json.dumps(take_inventory(source="auto"), indent=2))
    else:
        _console()


if __name__ == "__main__":
    main()
