#!/usr/bin/env python3
"""
log_parser.py  —  Access / auth log threat detection
=====================================================
Liao's proactive eye. The other tools answer "is something wrong right now?";
this one reads the HISTORY your systems already record and surfaces the attack
patterns buried in it — so Liao can spot an intrusion you didn't already
suspect.

TWO MODES:
  * WEB  (analyze)      — Apache/nginx/Cloudflare access lines (HTTP status).
  * AUTH (analyze_auth) — Linux auth.log / journal lines (SSH, sudo, sessions).

WEB — WHAT IT FINDS:
  - Brute force      : many auth failures / 401s / 403s from one IP
  - Endpoint scanning: one IP hitting many distinct paths (esp. 404s) fast
  - Sensitive probing: requests to admin/config/.env/.git-style paths
  - Error floods     : a spike of 5xx (possible exploitation attempts)
  - Noisy talkers    : the IPs generating the most traffic overall

AUTH — WHAT IT FINDS:
  - Per-event stream : accepted/failed logins, sessions, sudo, user/group adds
  - Brute force      : >= threshold failed auth events from one source IP

WHAT IT DOES NOT DO:
  It flags PATTERNS and the IPs behind them. It does not declare intent — a
  flagged IP is a candidate. Feed those IPs to rep_lookup.py to corroborate,
  then hand the picture to Liao in the Project for the verdict.

WEB INPUT formats handled:
  - Common Log Format / Combined (Apache, nginx default):
        1.2.3.4 - - [10/Oct/2025:13:55:36 +0000] "GET /admin HTTP/1.1" 401 12
  - Cloudflare / generic lines: best-effort — extracts the first IP, an HTTP
    status if present, and a path if present, and still scores them.

AUTH INPUT (ISO8601 journal/rsyslog, confirmed on the droplet 2026-10):
        2026-10-26T13:08:01.221838+00:00 host sshd[756299]: Accepted publickey
        for alice from 192.0.2.10 port 57019 ssh2: ED25519 ...

Pythonista / iOS friendly: standard library only. ok-dict shapes. Menu-return.
AUTHORIZED USE — your own logs.

--- TIMELINE RETROFIT (2026-10-26) ---
WEB findings now carry event_time / first_seen / last_seen (from the CLF
timestamp, when present) + time_source. AUTH mode emits a full per-event stream,
each entry timestamped from the ISO line prefix (time_source="event"), which is
the primary feed ioc_timeline.py consumes from this eye.
"""

import json
import re
from collections import defaultdict, Counter
from datetime import datetime, timezone


# --------------------------------------------------------------------------
# Tunable thresholds. These turn raw counts into "worth flagging."
# Lower them for quiet sites, raise them for busy ones.
# --------------------------------------------------------------------------
THRESHOLDS = {
    "auth_fail_per_ip": 10,      # >= this many 401/403 or failed auths => brute force
    "distinct_paths_per_ip": 20, # >= this many unique paths => scanning
    "notfound_per_ip": 15,       # >= this many 404s => enumeration
    "server_errors_total": 10,   # >= this many 5xx overall => error flood
    "top_talkers": 5,            # how many busiest IPs to list
}

# Paths that are juicy targets — a request to one of these is worth noting even
# once. Extend freely for your stack.
_SENSITIVE_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"/\.env", r"/\.git", r"/wp-admin", r"/wp-login", r"/admin",
        r"/phpmyadmin", r"/\.aws", r"/config", r"/backup", r"/\.ssh",
        r"/actuator", r"/server-status", r"/xmlrpc\.php", r"/shell",
        r"/cgi-bin", r"/\.well-known/.*\.php", r"eval\(", r"/etc/passwd",
    ]
]

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
# Combined Log Format: IP ... [timestamp] ... "METHOD path PROTO" status size
_CLF = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?\[(?P<ts>[^\]]+)\].*?"(?P<method>[A-Z]+)\s+'
    r'(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})'
)

# ISO8601-prefixed journal / rsyslog line (auth.log):
#   2026-10-26T13:08:01.221838+00:00 host proc[pid]: message
_ISO_SYSLOG = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<proc>[\w./\-]+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<msg>.*)$'
)
_FROM_IP = re.compile(r"\bfrom (\d{1,3}(?:\.\d{1,3}){3})\b")
_FOR_USER = re.compile(r"\bfor (?:invalid )?(?:user )?(\S+)")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _parse_clf_ts(ts):
    """'10/Oct/2025:13:55:36 +0000' -> ISO8601, or None."""
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except (ValueError, TypeError):
        return None


def _parse_iso_ts(ts):
    """ISO8601 line prefix -> normalized ISO8601, or None."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return None


# ==========================================================================
# WEB MODE
# ==========================================================================

def parse_line(line):
    """
    Best-effort parse of one web log line into:
      {"ip", "method", "path", "status", "ts"}  (any field may be None)
    Returns None if no IP at all (can't attribute it).
    """
    m = _CLF.search(line)
    if m:
        return {
            "ip": m.group("ip"),
            "method": m.group("method"),
            "path": m.group("path"),
            "status": int(m.group("status")),
            "ts": _parse_clf_ts(m.group("ts")),
        }
    # Fallback: pull first IP, and a status code if one looks present.
    ip_m = _IPV4.search(line)
    if not ip_m:
        return None
    status = None
    s_m = re.search(r"\b([1-5]\d{2})\b", line)
    if s_m:
        status = int(s_m.group(1))
    path = None
    p_m = re.search(r'"(?:[A-Z]+)\s+(\S+)', line) or re.search(r"\s(/\S*)", line)
    if p_m:
        path = p_m.group(1)
    return {"ip": ip_m.group(0), "method": None, "path": path,
            "status": status, "ts": None}


def analyze(log_text):
    """
    Run all WEB detections over raw log text.

    Returns ok-dict:
        {
          "ok", "mode": "web", "analyzed_at",
          "lines_total", "lines_parsed",
          "findings": [ {"type","ip","detail","severity",
                         "event_time","first_seen","last_seen","time_source"}, ... ],
          "suspect_ips": [ip, ...],
          "top_talkers": [ {ip,count}, ... ],
          "summary", "error",
        }
    """
    lines = log_text.splitlines()
    if not any(l.strip() for l in lines):
        return {
            "ok": False, "mode": "web", "analyzed_at": _now(), "lines_total": 0,
            "lines_parsed": 0, "findings": [], "suspect_ips": [],
            "top_talkers": [],
            "summary": "NO LOG DATA RECEIVED. An empty parse is not an "
                       "all-clear — it means there was nothing to look at.",
            "error": "empty_input",
        }

    hits = Counter()                         # ip -> total requests
    auth_fail = Counter()                    # ip -> 401/403 count
    notfound = Counter()                     # ip -> 404 count
    paths_by_ip = defaultdict(set)           # ip -> set of paths
    sensitive = defaultdict(list)            # ip -> [sensitive paths hit]
    ip_times = defaultdict(list)             # ip -> [event_time, ...]
    server_errors = 0
    parsed = 0

    for line in lines:
        rec = parse_line(line)
        if not rec:
            continue
        parsed += 1
        ip = rec["ip"]
        hits[ip] += 1
        st = rec["status"]
        path = rec["path"]
        if rec.get("ts"):
            ip_times[ip].append(rec["ts"])

        if st in (401, 403):
            auth_fail[ip] += 1
        if st == 404:
            notfound[ip] += 1
        if st is not None and 500 <= st <= 599:
            server_errors += 1
        if path:
            paths_by_ip[ip].add(path)
            for pat in _SENSITIVE_PATTERNS:
                if pat.search(path):
                    sensitive[ip].append(path)
                    break

    def _span_ip(ip):
        ts = sorted(t for t in ip_times.get(ip, []) if t)
        if not ts:
            return {"event_time": None, "first_seen": None,
                    "last_seen": None, "time_source": None}
        return {"event_time": ts[-1], "first_seen": ts[0],
                "last_seen": ts[-1], "time_source": "event"}

    findings = []
    suspects = set()

    for ip, n in auth_fail.items():
        if n >= THRESHOLDS["auth_fail_per_ip"]:
            findings.append({"type": "brute_force", "ip": ip,
                             "detail": f"{n} auth failures (401/403)",
                             "severity": "high", **_span_ip(ip)})
            suspects.add(ip)

    for ip, paths in paths_by_ip.items():
        if len(paths) >= THRESHOLDS["distinct_paths_per_ip"]:
            findings.append({"type": "endpoint_scan", "ip": ip,
                             "detail": f"{len(paths)} distinct paths requested",
                             "severity": "medium", **_span_ip(ip)})
            suspects.add(ip)

    for ip, n in notfound.items():
        if n >= THRESHOLDS["notfound_per_ip"]:
            findings.append({"type": "enumeration", "ip": ip,
                             "detail": f"{n} x 404 (probing for hidden paths)",
                             "severity": "medium", **_span_ip(ip)})
            suspects.add(ip)

    for ip, paths in sensitive.items():
        uniq = sorted(set(paths))
        findings.append({"type": "sensitive_path_probe", "ip": ip,
                         "detail": f"hit sensitive paths: {', '.join(uniq[:6])}"
                                   + (" ..." if len(uniq) > 6 else ""),
                         "severity": "high", **_span_ip(ip)})
        suspects.add(ip)

    if server_errors >= THRESHOLDS["server_errors_total"]:
        findings.append({"type": "error_flood", "ip": None,
                         "detail": f"{server_errors} x 5xx server errors "
                                   "(possible exploitation attempts)",
                         "severity": "medium",
                         "event_time": None, "first_seen": None,
                         "last_seen": None, "time_source": None})

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 9))

    top = [{"ip": ip, "count": n} for ip, n in hits.most_common(
        THRESHOLDS["top_talkers"])]

    if findings:
        summary = (f"{len(findings)} pattern(s) flagged across {parsed} parsed "
                   f"line(s). Feed suspect IPs to rep_lookup, then bring the "
                   f"picture to Liao.")
    else:
        summary = (f"No threshold-crossing patterns across {parsed} parsed "
                   f"line(s). Not an all-clear — a low-and-slow attacker stays "
                   f"under these thresholds. Review top talkers anyway.")

    return {
        "ok": True,
        "mode": "web",
        "analyzed_at": _now(),
        "lines_total": len(lines),
        "lines_parsed": parsed,
        "findings": findings,
        "suspect_ips": sorted(suspects),
        "top_talkers": top,
        "summary": summary,
        "error": None,
    }


# ==========================================================================
# AUTH MODE
# ==========================================================================

def _classify_auth(proc, msg):
    """Map an auth.log message to (event_type, severity), or (None, None)."""
    p = (proc or "").lower()
    low = (msg or "").lower()
    if "accepted" in low and ("publickey" in low or "password" in low
                              or "key " in low):
        return ("login_accepted", "low")
    if low.startswith("failed ") or "failed password" in low \
            or "failed publickey" in low:
        return ("login_failed", "high")
    if "invalid user" in low:
        return ("login_failed", "high")
    if "authentication failure" in low or "auth failure" in low:
        return ("login_failed", "high")
    if "session opened" in low:
        return ("session_opened", "low")
    if "session closed" in low:
        return ("session_closed", "low")
    if "new session" in low and "logind" in p:
        return ("new_session", "low")
    if p.startswith("sudo") or "command=" in low:
        return ("sudo", "medium")
    if p.startswith("useradd") or "new user" in low:
        return ("user_add", "high")
    if p.startswith("groupadd") or "new group" in low:
        return ("group_add", "high")
    if "connection from" in low:
        return ("connection", "low")
    return (None, None)


def analyze_auth(log_text):
    """
    Parse Linux auth.log (ISO8601-prefixed) into a timestamped event stream
    plus brute-force clustering.

    Returns ok-dict:
        {
          "ok", "mode": "auth", "analyzed_at",
          "lines_total", "lines_parsed",
          "events": [ {type, severity, event_time, time_source, ip, user,
                       proc, pid, detail}, ... ],   # chronological
          "findings": [ {type:"brute_force", ip, detail, severity,
                         first_seen, last_seen, event_time, time_source}, ... ],
          "suspect_ips": [ip, ...],
          "summary", "error",
        }
    """
    lines = log_text.splitlines()
    if not any(l.strip() for l in lines):
        return {"ok": False, "mode": "auth", "analyzed_at": _now(),
                "lines_total": 0, "lines_parsed": 0, "events": [],
                "findings": [], "suspect_ips": [],
                "summary": "NO AUTH LOG DATA RECEIVED. An empty parse is not an "
                           "all-clear.", "error": "empty_input"}

    events = []
    failed_by_ip = defaultdict(list)     # ip -> [event_time, ...]
    parsed = 0

    for line in lines:
        m = _ISO_SYSLOG.match(line.strip())
        if not m:
            continue
        proc = m.group("proc") or ""
        msg = m.group("msg") or ""
        etype, sev = _classify_auth(proc, msg)
        if etype is None:
            continue
        parsed += 1
        et = _parse_iso_ts(m.group("ts"))
        ipm = _FROM_IP.search(msg)
        ip = ipm.group(1) if ipm else None
        um = _FOR_USER.search(msg)
        user = um.group(1) if um else None
        if user:
            user = re.sub(r"\(uid=.*$", "", user)   # strip liao(uid=1000)
        events.append({
            "type": etype,
            "severity": sev,
            "event_time": et,
            "time_source": "event" if et else None,
            "ip": ip,
            "user": user,
            "proc": proc,
            "pid": int(m.group("pid")) if m.group("pid") else None,
            "detail": msg[:160],
        })
        if etype == "login_failed" and ip:
            failed_by_ip[ip].append(et)

    findings = []
    suspects = set()
    for ip, times in failed_by_ip.items():
        if len(times) >= THRESHOLDS["auth_fail_per_ip"]:
            ts_sorted = sorted(t for t in times if t)
            findings.append({
                "type": "brute_force", "ip": ip,
                "detail": f"{len(times)} failed auth events",
                "severity": "high",
                "first_seen": ts_sorted[0] if ts_sorted else None,
                "last_seen": ts_sorted[-1] if ts_sorted else None,
                "event_time": ts_sorted[-1] if ts_sorted else None,
                "time_source": "event" if ts_sorted else None,
            })
            suspects.add(ip)

    # Chronological order; unparseable times sink to the end.
    events.sort(key=lambda e: (e["event_time"] is None, e["event_time"] or ""))

    if findings:
        summary = (f"{len(findings)} auth cluster(s) flagged across {parsed} "
                   f"auth events. Feed suspect IPs to rep_lookup.")
    else:
        summary = (f"{parsed} auth events parsed, no brute-force clusters "
                   f"(>= {THRESHOLDS['auth_fail_per_ip']} fails/IP). Not an "
                   f"all-clear — review the event stream.")

    return {
        "ok": True, "mode": "auth", "analyzed_at": _now(),
        "lines_total": len(lines), "lines_parsed": parsed,
        "events": events, "findings": findings,
        "suspect_ips": sorted(suspects),
        "summary": summary, "error": None,
    }


# ==========================================================================
# FORMATTERS
# ==========================================================================

def format_human(report):
    """Render a WEB report."""
    lines = ["# Log Analysis (web)"]
    lines.append(f"Analyzed: {report['analyzed_at']}")
    lines.append(f"Lines: {report['lines_parsed']} parsed / "
                 f"{report['lines_total']} total")
    lines.append("")
    if not report["ok"]:
        lines.append(f"** {report['summary']}")
        return "\n".join(lines)

    lines.append(f"**{report['summary']}**")
    lines.append("")
    if report["findings"]:
        lines.append(f"## FINDINGS ({len(report['findings'])})")
        for f in report["findings"]:
            who = f["ip"] or "(site-wide)"
            lines.append(f"- [{f['severity'].upper()}] {f['type']} — {who}")
            lines.append(f"    {f['detail']}")
            if f.get("last_seen"):
                lines.append(f"    seen {f['first_seen']} -> {f['last_seen']}")
    else:
        lines.append("## FINDINGS (0)")
        lines.append("  Nothing crossed thresholds (see summary caveat).")
    lines.append("")
    if report["suspect_ips"]:
        lines.append("## SUSPECT IPs (run these through rep_lookup)")
        for ip in report["suspect_ips"]:
            lines.append(f"  {ip}")
        lines.append("")
    lines.append("## TOP TALKERS")
    for t in report["top_talkers"]:
        lines.append(f"  {t['ip']}  —  {t['count']} requests")
    return "\n".join(lines)


def format_auth(report):
    """Render an AUTH report."""
    lines = ["# Auth Log Analysis"]
    lines.append(f"Analyzed: {report['analyzed_at']}")
    lines.append(f"Events: {report['lines_parsed']} parsed / "
                 f"{report['lines_total']} lines")
    lines.append("")
    if not report["ok"]:
        lines.append(f"** {report['summary']}")
        return "\n".join(lines)
    lines.append(f"**{report['summary']}**")
    lines.append("")
    if report["findings"]:
        lines.append(f"## FLAGGED ({len(report['findings'])})")
        for f in report["findings"]:
            lines.append(f"- [{f['severity'].upper()}] {f['type']} — {f['ip']}")
            lines.append(f"    {f['detail']}  "
                         f"({f['first_seen']} -> {f['last_seen']})")
        lines.append("")
    if report["suspect_ips"]:
        lines.append("## SUSPECT IPs (run through rep_lookup)")
        for ip in report["suspect_ips"]:
            lines.append(f"  {ip}")
        lines.append("")
    lines.append(f"## EVENT STREAM ({len(report['events'])})")
    for e in report["events"]:
        who = e.get("user") or "?"
        ip = e.get("ip") or "-"
        sev = (e.get("severity") or "?")[0].upper()
        lines.append(f"  {e['event_time'] or '?'}  [{sev}] "
                     f"{e['type']:<16} {who}@{ip}")
    return "\n".join(lines)


# ==========================================================================
# CONSOLE / CLI
# ==========================================================================

def _read_block():
    print("Paste lines, then a line with only END:")
    buf = []
    while True:
        ln = input()
        if ln.strip() == "END":
            break
        buf.append(ln)
    return "\n".join(buf)


def _console():
    while True:
        print("\n=== Liao :: Log Parser ===")
        print("1) Paste WEB access log text")
        print("2) Read a WEB access log file by path")
        print("3) Paste AUTH log text (auth.log / journal)")
        print("4) Read an AUTH log file by path")
        print("5) Raw JSON (web, from paste)")
        print("6) Raw JSON (auth, from paste)")
        print("0) Back")
        choice = input("> ").strip()

        if choice == "1":
            print("\n" + format_human(analyze(_read_block())))
        elif choice == "2":
            path = input("Path to web log file: ").strip()
            try:
                with open(path, "r", errors="replace") as f:
                    print("\n" + format_human(analyze(f.read())))
            except OSError as e:
                print(f"Could not read file: {e}")
        elif choice == "3":
            print("\n" + format_auth(analyze_auth(_read_block())))
        elif choice == "4":
            path = input("Path to auth log file: ").strip()
            try:
                with open(path, "r", errors="replace") as f:
                    print("\n" + format_auth(analyze_auth(f.read())))
            except OSError as e:
                print(f"Could not read file: {e}")
        elif choice == "5":
            print(json.dumps(analyze(_read_block()), indent=2))
        elif choice == "6":
            print(json.dumps(analyze_auth(_read_block()), indent=2))
        elif choice == "0":
            return
        else:
            print("?")


def main():
    import sys
    argv = sys.argv[1:]
    want_json = "--json" in argv
    want_auth = "--auth" in argv
    paths = [a for a in argv if not a.startswith("--")]
    if paths:
        try:
            with open(paths[0], "r", errors="replace") as f:
                text = f.read()
        except OSError as e:
            print(f"Could not read file: {e}")
            return
        if want_auth:
            rep = analyze_auth(text)
            print(json.dumps(rep, indent=2) if want_json else format_auth(rep))
        else:
            rep = analyze(text)
            print(json.dumps(rep, indent=2) if want_json else format_human(rep))
    else:
        _console()


if __name__ == "__main__":
    main()
