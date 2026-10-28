#!/usr/bin/env python3
"""
proc_inventory.py - read-only process-inventory parser for owned hosts.

Part of the Liao defensive toolkit. Parses pasted/saved output of
    ps -eo pid,ppid,user,lstart,stat,pcpu,pmem,args
(or enumerates the LOCAL host via psutil when available), rebuilds the
parent/child tree, and flags process-hygiene anomalies for operator review.

SCOPE: run only against hosts in owned_assets.md. This tool is read-only - it
parses text and reads the local process table; it never touches the network.

House contract:
  * functions return ok-dicts: {"ok": bool, ..., "error": str|None}
  * format_human() renderer
  * --json CLI flag
  * _console() menu loop, 0 = Back
  * empty/failed input is reported loudly, never as an all-clear

Timeline contract (shared with fim.py / dns_parser.py / log_parser.py):
  record["event_time"]  : ISO8601 UTC string or None
  record["time_source"] : "event" | "mtime" | "collection" | "inherited" | None
  aggregate first_seen / last_seen

Join key: record["pid"] - ioc_timeline.py links conn_inventory connections
(which already carry pid) to their owning process here (see index_by_pid()).

stdlib only. No pandas. Targets Pythonista on iOS.
"""

import sys
import os
import re
import json
from datetime import datetime, timezone

SCHEMA_VERSION = "proc_inventory/1"

# ---- classification tables -------------------------------------------------

# world-writable / tmp dirs: a binary executing from here is a persistence smell
SUSPICIOUS_EXEC_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")

SHELL_BASENAMES = {
    "sh", "bash", "dash", "zsh", "ash", "ksh", "fish", "csh", "tcsh", "busybox",
}

# service / daemon users where an interactive-shell child is a webshell / RCE smell
SERVICE_USERS = {
    "www-data", "nginx", "apache", "apache2", "httpd", "daemon",
    "mysql", "postgres", "redis", "mongodb", "tomcat", "tomcat8", "nobody",
}

# command basenames that denote a user-facing service master/worker
SERVICE_CMDS = {
    "nginx", "apache2", "httpd", "lighttpd", "php-fpm", "php-fpm7", "php-fpm8",
    "mysqld", "postgres", "redis-server", "caddy", "haproxy",
}

_PS_HEADER_RE = re.compile(r"^\s*PID\s+PPID\s+USER\b", re.IGNORECASE)
_LSTART_FMT = "%a %b %d %H:%M:%S %Y"


# ---- low-level field helpers ----------------------------------------------

def _parse_lstart(tokens5):
    """ps lstart is always 5 whitespace-collapsed tokens. Droplet prints UTC."""
    s = " ".join(tokens5)
    try:
        dt = datetime.strptime(s, _LSTART_FMT).replace(tzinfo=timezone.utc)
        return dt.isoformat(), s
    except (ValueError, TypeError):
        return None, s


def _is_bracketed(command):
    c = (command or "").strip()
    return c.startswith("[") and c.endswith("]")


def _clean_exe(command):
    """argv0 -> (exe token, basename). Kernel-thread bracket names kept whole."""
    if not command:
        return None, None
    c = command.strip()
    first = c.split()[0]
    if first.startswith("[") and (first.endswith("]") or c.endswith("]")):
        return first, first                      # [kworker/9:9] stays intact
    tok = first.rstrip(":")                       # nginx rewrites argv0 to 'nginx:'
    base = tok.rsplit("/", 1)[-1]
    return tok, base


def _which_dir(exe):
    for d in SUSPICIOUS_EXEC_DIRS:
        if exe.startswith(d):
            return d
    return "?"


def _is_serviceish(rec):
    if rec.get("user") in SERVICE_USERS:
        return True
    return (rec.get("exe_base") or "") in SERVICE_CMDS


def _trunc(s, n):
    s = s or ""
    return s if len(s) <= n else s[:n - 1] + "\u2026"


# ---- ps line / text parsing -----------------------------------------------

def _parse_ps_line(line):
    """Return (record, None) or (None, error_str). Fixed cols = 11, args = rest."""
    toks = line.split()
    if len(toks) < 11:
        return None, "too few fields (%d, need >=11)" % len(toks)
    try:
        pid = int(toks[0])
        ppid = int(toks[1])
    except ValueError:
        return None, "pid/ppid not integers"
    user = toks[2]
    lstart_toks = toks[3:8]
    stat = toks[8]
    try:
        cpu = float(toks[9])
        mem = float(toks[10])
    except ValueError:
        return None, "cpu/mem not floats (column misalignment?)"
    command = " ".join(toks[11:]) if len(toks) > 11 else ""
    event_time, lstart_raw = _parse_lstart(lstart_toks)
    exe, exe_base = _clean_exe(command)
    rec = {
        "pid": pid,
        "ppid": ppid,
        "user": user,
        "event_time": event_time,
        "time_source": "event" if event_time else None,
        "stat": stat,
        "cpu": cpu,
        "mem": mem,
        "command": command,
        "exe": exe,
        "exe_base": exe_base,
        "is_kernel_thread": _is_bracketed(command),
        "lstart_raw": lstart_raw,
        "notes": [] if event_time else ["lstart unparseable"],
    }
    return rec, None


def _finalize(records, source, parse_errors, extra=None):
    """Shared assembly: tree, flags, time span, ok-dict."""
    if not records:
        res = {
            "ok": False,
            "error": "no process records parsed (input had no usable ps rows)",
            "source": source,
            "schema": SCHEMA_VERSION,
            "records": [],
            "parse_errors": parse_errors,
            "count": 0,
            "flagged_pids": [],
            "first_seen": None,
            "last_seen": None,
        }
        if extra:
            res.update(extra)
        return res
    _build_tree(records)
    flagged = _flag_all(records)
    first_seen, last_seen = _time_span(records)
    res = {
        "ok": True,
        "error": None,
        "source": source,
        "schema": SCHEMA_VERSION,
        "records": records,
        "parse_errors": parse_errors,
        "count": len(records),
        "flagged_pids": flagged,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }
    if extra:
        res.update(extra)
    return res


def parse_ps_text(text, source="paste"):
    if text is None or not text.strip():
        return {
            "ok": False,
            "error": "empty input - no ps output to parse",
            "source": source,
            "schema": SCHEMA_VERSION,
            "records": [],
            "parse_errors": [],
            "count": 0,
            "flagged_pids": [],
            "first_seen": None,
            "last_seen": None,
        }
    records, parse_errors = [], []
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if _PS_HEADER_RE.match(line):
            continue
        rec, err = _parse_ps_line(line)
        if err:
            parse_errors.append({"line_no": i, "line": line.strip(), "error": err})
            continue
        records.append(rec)
    return _finalize(records, source, parse_errors)


def parse_ps_file(path):
    if not path:
        return {"ok": False, "error": "no path given", "source": "file",
                "schema": SCHEMA_VERSION, "records": [], "parse_errors": [],
                "count": 0, "flagged_pids": [], "first_seen": None,
                "last_seen": None}
    try:
        with open(os.path.expanduser(path), "r", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        return {"ok": False, "error": "cannot read %s: %s" % (path, e),
                "source": "file", "schema": SCHEMA_VERSION, "records": [],
                "parse_errors": [], "count": 0, "flagged_pids": [],
                "first_seen": None, "last_seen": None, "path": path}
    res = parse_ps_text(text, source="file")
    res["path"] = path
    return res


# ---- psutil source (LOCAL host only) --------------------------------------

def collect_psutil():
    source = "psutil"
    try:
        import psutil
    except Exception as e:
        return {"ok": False,
                "error": "psutil unavailable: %s - use pasted ps or a saved dump" % e,
                "source": source, "schema": SCHEMA_VERSION, "records": [],
                "parse_errors": [], "count": 0, "flagged_pids": [],
                "first_seen": None, "last_seen": None}
    records, errors = [], []
    attrs = ["pid", "ppid", "username", "status", "cpu_percent",
             "memory_percent", "cmdline", "name", "exe", "create_time"]
    for p in psutil.process_iter(attrs, ad_value=None):
        info = p.info
        try:
            pid = int(info.get("pid"))
            ppid = int(info.get("ppid") or 0)
        except (TypeError, ValueError):
            errors.append({"pid": info.get("pid"), "error": "bad pid/ppid"})
            continue
        cmdline = info.get("cmdline")
        if cmdline:
            command = " ".join(cmdline)
        else:
            nm = info.get("name") or ""
            command = "[%s]" % nm if nm and not nm.startswith("[") else nm
        ct = info.get("create_time")
        if ct:
            event_time = datetime.fromtimestamp(ct, tz=timezone.utc).isoformat()
            tsrc = "event"
        else:
            event_time, tsrc = None, None
        exe, exe_base = _clean_exe(command)
        exe_field = info.get("exe")
        if exe_field:                              # psutil gives a real path; prefer it
            exe = exe_field
            exe_base = exe_field.rsplit("/", 1)[-1]
        mem = info.get("memory_percent")
        rec = {
            "pid": pid,
            "ppid": ppid,
            "user": info.get("username") or "?",
            "event_time": event_time,
            "time_source": tsrc,
            "stat": info.get("status"),
            "cpu": info.get("cpu_percent"),
            "mem": round(mem, 2) if mem is not None else None,
            "command": command,
            "exe": exe,
            "exe_base": exe_base,
            "is_kernel_thread": _is_bracketed(command),
            "lstart_raw": None,
            "notes": [],
        }
        records.append(rec)
    caveat = ("psutil reads the LOCAL host (the device running Pythonista), "
              "NOT necessarily the droplet. For the droplet, paste ps over SSH.")
    return _finalize(records, source, errors, extra={"source_caveat": caveat})


# ---- tree + anomaly flags -------------------------------------------------

def _build_tree(records):
    by_pid = {r["pid"]: r for r in records}
    for r in records:
        r["children"] = []
    for r in records:
        p = by_pid.get(r["ppid"])
        if p is not None and p is not r:
            p["children"].append(r["pid"])
    for r in records:
        anc, seen = [], {r["pid"]}
        ppid = r["ppid"]
        truncated = False
        while ppid and ppid != 0:
            if ppid in seen:                       # cycle = forged ppid
                truncated = True
                break
            anc.append(ppid)
            seen.add(ppid)
            p = by_pid.get(ppid)
            if p is None:                          # parent not in this dump
                truncated = True
                break
            ppid = p["ppid"]
            if len(anc) > 128:
                truncated = True
                break
        r["ancestry"] = anc
        r["ancestry_truncated"] = truncated
    for r in records:
        r["children"].sort()
        r["ancestry_str"] = _render_chain(r, by_pid)


def _render_chain(rec, by_pid):
    parts = ["%s(%d)" % (rec.get("exe_base") or "?", rec["pid"])]
    for pid in rec.get("ancestry", []):
        p = by_pid.get(pid)
        name = (p.get("exe_base") if p else None) or "?"
        parts.append("%s(%d)" % (name, pid))
    if rec.get("ancestry_truncated"):
        parts.append("...(parent not in dump / cycle)")
    return " <- ".join(parts)


def _flag_record(rec, by_pid):
    flags = []
    exe = rec.get("exe") or ""
    cmd = rec.get("command") or ""

    if any(exe.startswith(d) for d in SUSPICIOUS_EXEC_DIRS):
        flags.append({"code": "exec_from_world_writable", "severity": "high",
                      "detail": "executable path in %s" % _which_dir(exe)})

    if "(deleted)" in cmd:
        flags.append({"code": "deleted_executable", "severity": "high",
                      "detail": "on-disk binary removed while process runs"})

    if rec["is_kernel_thread"]:
        legit = rec["pid"] == 2 or 2 in rec.get("ancestry", [])
        if not legit:
            flags.append({"code": "masquerade_kernel_thread", "severity": "high",
                          "detail": "bracketed name but not a descendant of kthreadd(2)"})

    if _is_serviceish(rec):
        shell_kids = [cpid for cpid in rec.get("children", [])
                      if (by_pid.get(cpid) or {}).get("exe_base") in SHELL_BASENAMES]
        if shell_kids:
            flags.append({"code": "service_shell_child", "severity": "high",
                          "detail": "service user/daemon spawned shell child pid(s) %s"
                                    % ",".join(str(x) for x in shell_kids)})

    rec["flags"] = flags
    return flags


def _flag_all(records):
    by_pid = {r["pid"]: r for r in records}
    flagged = [r["pid"] for r in records if _flag_record(r, by_pid)]
    return sorted(flagged)


def _time_span(records):
    times = [r["event_time"] for r in records if r["event_time"]]
    if not times:
        return None, None
    return min(times), max(times)                  # fixed-width +00:00 => lexical == chrono


# ---- join helpers for ioc_timeline.py -------------------------------------

def index_by_pid(records):
    """pid(int) -> record. ioc_timeline.py uses this to attach conn_inventory
    rows (which carry pid) to their owning process."""
    return {r["pid"]: r for r in records}


def owning_process(records, pid):
    return index_by_pid(records).get(pid)


# ---- rendering ------------------------------------------------------------

def _source_grade_line(result):
    src = result.get("source")
    if src == "psutil":
        return ("source grade: LOCAL live via psutil - this is the device running "
                "Pythonista, NOT the droplet. Paste ps over SSH for the droplet.")
    if src == "file":
        return ("source grade: saved ps dump (%s) - trust = integrity of the host "
                "it was collected on, at collection time." % result.get("path", "?"))
    return ("source grade: pasted ps - operator-collected over SSH; trust = that "
            "host's integrity at collection time. A rootkitted host can hide rows in ps.")


def format_human(result):
    lines = []
    src = result.get("source", "?")

    if not result.get("ok"):
        lines.append("[proc_inventory] FAILED - %s" % (result.get("error") or "unknown error"))
        lines.append("source: %s" % src)
        pe = result.get("parse_errors") or []
        if pe:
            lines.append("parse errors: %d" % len(pe))
            for e in pe[:5]:
                lines.append("  L%s: %s  <- %s" % (e.get("line_no", "?"),
                             _trunc(e.get("line", ""), 60), e.get("error")))
        lines.append("=> NOT an all-clear. No usable process inventory produced.")
        return "\n".join(lines)

    recs = result["records"]
    flagged = [r for r in recs if r.get("flags")]
    nflags = sum(len(r["flags"]) for r in recs)
    sev = "CLEAN" if not flagged else "REVIEW"
    lines.append("BLUF: %s - %d processes, %d flagged for review (%d anomal%s). source=%s."
                 % (sev, len(recs), len(flagged), nflags,
                    "y" if nflags == 1 else "ies", src))

    if flagged:
        top = min(flagged, key=lambda x: x["pid"])
        lines.append("Most urgent: pid %d (%s) - %s"
                     % (top["pid"], top.get("exe_base") or _trunc(top["command"], 24),
                        top["flags"][0]["code"]))
    else:
        lines.append("Most urgent: nothing flagged - this is a candidate screen, "
                     "not a guarantee. Corroborate off-host.")

    lines.append(_source_grade_line(result))
    if result.get("source_caveat"):
        lines.append("caveat: %s" % result["source_caveat"])
    lines.append("start-time span: %s .. %s"
                 % (result.get("first_seen") or "n/a", result.get("last_seen") or "n/a"))

    pe = result.get("parse_errors") or []
    if pe:
        lines.append("!! %d line(s) failed to parse - inventory is INCOMPLETE:" % len(pe))
        for e in pe[:5]:
            lines.append("   L%s: %s  <- %s" % (e.get("line_no", "?"),
                         _trunc(e.get("line", ""), 60), e.get("error")))
        if len(pe) > 5:
            lines.append("   ... +%d more" % (len(pe) - 5))

    if flagged:
        lines.append("")
        lines.append("FLAGGED (candidates for review, NOT verdicts):")
        for r in sorted(flagged, key=lambda x: x["pid"]):
            lines.append("  pid %d  user=%s  %s" % (r["pid"], r["user"], r.get("exe_base") or ""))
            lines.append("    cmd: %s" % _trunc(r["command"], 100))
            lines.append("    tree: %s" % r["ancestry_str"])
            lines.append("    started: %s (%s)" % (r.get("event_time") or "unknown",
                                                    r.get("time_source")))
            for f in r["flags"]:
                lines.append("    [%s] %s - %s" % (f["severity"].upper(), f["code"], f["detail"]))

    lines.append("")
    lines.append("Next: for any flag, corroborate off-host - fim.py baseline on the "
                 "binary, conn_inventory egress on the same pid. Don't trust this host's ps alone.")
    return "\n".join(lines)


def format_tree(result, max_cmd=48):
    """Full ASCII process tree (offered from the console)."""
    if not result.get("ok"):
        return format_human(result)
    recs = result["records"]
    by_pid = {r["pid"]: r for r in recs}
    present = set(by_pid)
    roots = sorted(r["pid"] for r in recs
                   if r["ppid"] == 0 or r["ppid"] not in present)
    out = ["process tree (source=%s):" % result.get("source")]

    def walk(pid, depth):
        r = by_pid[pid]
        mark = " *FLAG*" if r.get("flags") else ""
        out.append("%s%d %s %s%s" % ("  " * depth, pid, r["user"],
                                     _trunc(r["command"], max_cmd), mark))
        for c in r.get("children", []):
            if c in by_pid:
                walk(c, depth + 1)

    for root in roots:
        walk(root, 0)
    return "\n".join(out)


# ---- console + CLI --------------------------------------------------------

def _read_pasted_block():
    print("Paste `ps -eo pid,ppid,user,lstart,stat,pcpu,pmem,args` output.")
    print("Finish with a line containing only:  EOF")
    buf = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "EOF":
            break
        buf.append(line)
    return "\n".join(buf)


def _show(result):
    print()
    print(format_human(result))
    if result.get("ok"):
        if input("\nshow full tree? [y/N] ").strip().lower() == "y":
            print()
            print(format_tree(result))
    if input("\nshow JSON? [y/N] ").strip().lower() == "y":
        print(json.dumps(result, indent=2))


def _console():
    while True:
        print("\n=== proc_inventory ===")
        print("1) Parse pasted ps output")
        print("2) Parse saved ps dump (file path)")
        print("3) Enumerate LOCAL host via psutil")
        print("0) Back")
        choice = input("> ").strip()
        if choice == "0":
            return
        if choice == "1":
            res = parse_ps_text(_read_pasted_block(), source="paste")
        elif choice == "2":
            res = parse_ps_file(input("path to ps dump: ").strip())
        elif choice == "3":
            res = collect_psutil()
        else:
            print("?")
            continue
        _show(res)


def main(argv):
    args = argv[1:]
    if "--help" in args or "-h" in args:
        print(__doc__)
        print("usage: proc_inventory.py [--file PATH | --psutil | --stdin] [--json]")
        print("       proc_inventory.py            # interactive console")
        return 0
    want_json = "--json" in args
    args = [a for a in args if a != "--json"]

    res = None
    if "--file" in args:
        i = args.index("--file")
        res = parse_ps_file(args[i + 1] if i + 1 < len(args) else "")
    elif "--psutil" in args:
        res = collect_psutil()
    elif "--stdin" in args or "--paste" in args:
        res = parse_ps_text(sys.stdin.read(), source="paste")

    if res is None:
        _console()
        return 0

    print(json.dumps(res, indent=2) if want_json else format_human(res))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
