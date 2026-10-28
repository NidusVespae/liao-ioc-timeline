#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
log_integrity.py  —  Liao read-only log-integrity auditor.

Scope: OWNED ASSETS ONLY. Parses a section-marked text dump that YOU collected
from YOUR OWN host. It takes NO network action and NEVER executes, decodes, or
expands anything it reads. Flags are review candidates, not verdicts.

Principle: evasion is a signal. A gap in the record belongs on the incident
timeline, so every gap, regression, restart, reboot and rotation becomes a
timestamped record.

What it does:
  * Gap / regression analysis of auth.log and syslog leading timestamps,
    including across the rotation boundary (.1 -> current) and up to the
    moment of collection (log "went dark").
  * Logging-service state (journald, rsyslog, auditd), auditd status,
    journald storage + --verify result, boot list, logrotate state,
    wtmp/btmp/lastlog, and shell-history redirection.
  * Snapshots a baseline (JSON) and diffs later dumps against it: in-place
    truncation (same inode, smaller), replaced logs, restarts, counter jumps,
    early rotation, new gaps. Reviewed flags can be acknowledged.

Stdlib only (runs in Pythonista). stat lines accepted in THREE formats:
  old (space)  : <epoch> <owner> <octal> <path>
  pipe (5)     : <epoch>|<owner>|<octal>|<filetype>|<path>
  extended (7) : <epoch>|<owner>|<octal>|<filetype>|<size>|<inode>|<path>

Exit codes (batch):  0 clean · 1 flagged/drift · 2 error · 3 incomplete input/vantage
"""

import sys
import os
import re
import json
import gzip
import base64
import hashlib
from datetime import datetime, timezone

VERSION = "1.0.0"
BASELINE_DEFAULT = "~/Documents/liao_logintegrity_baseline.json"

EXPECTED_SECTIONS = [
    "meta", "log_files", "log_timestamps", "journal", "services",
    "audit", "logrotate", "login_records", "shell_history",
]

# ---- calibration (from a real Ubuntu 24.04 VPS dump, 2026-10) ------------- #
# auth.log: CRON every 10 min -> median spacing 480s, max observed 601s.
# syslog:   a chatty app logs every ~2s -> median 2s, max observed 63s.
TS_FILES = ("/var/log/auth.log", "/var/log/syslog")
GAP_THRESHOLDS = {"/var/log/auth.log": 1800, "/var/log/syslog": 600}
GAP_DEFAULT = 1800
GAP_HIGH = 6 * 3600              # gap longer than this -> high
MAX_GAP_RECORDS = 50             # per file; more are summarized
# rsyslog writes some lines a few seconds out of order (44 in the real dump).
# Backward steps up to this many seconds are counted, not flagged.
REGRESSION_TOLERANCE = 120
OVERLAP_SLACK = 60               # gap "overlaps" a restart within this slack
BOOT_GAP_THRESHOLD = 300         # downtime between boots worth a note
ROTATION_TOD_TOLERANCE = 300     # rotation this far off the timer's time-of-day
EMPTY_GRACE = 1800               # empty key log right after rotation is ok
PKG_CORRELATE = 600              # restart within this of apt/dpkg activity

LOGGING_UNITS = ("systemd-journald", "rsyslog", "auditd")
# key log -> writer unit (None: written by login machinery, always expected)
KEY_LOGS = {
    "/var/log/auth.log": "rsyslog",
    "/var/log/syslog": "rsyslog",
    "/var/log/audit/audit.log": "auditd",
    "/var/log/wtmp": None,
    "/var/log/lastlog": None,
}
PKG_LOGS = ("/var/log/apt/history.log", "/var/log/dpkg.log")

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

COLLECT_CMD = r"""#!/bin/sh
# liao log-integrity collector v1 (READ-ONLY). Run as root on the target.
# Reads metadata, timestamps and status only. Never rotates, vacuums, edits or
# restarts anything.   sudo sh ~/collect_logintegrity.sh > ~/logint.txt
# sudo needed: log_timestamps, journal, audit, shell_history (other homes).
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; LC_ALL=C; export LC_ALL
TZ=UTC; export TZ
xstat() { for f in "$@"; do if [ -e "$f" ] || [ -L "$f" ]; then
  stat -c "%Y|%U|%a|%F|%s|%i|%n" "$f"
  [ -L "$f" ] && echo "--- link:$f -> $(readlink "$f")"
  else echo "--- missing:$f"; fi; done; return 0; }

echo "===SECTION meta==="
echo "host:$(hostname)"
echo "collected_utc:$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "collector_uid:$(id -u)"
echo "boot_id:$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
echo "uptime_s:$(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
echo "collector:logintegrity-v1"

echo "===SECTION log_files==="
for f in /var/log/* /var/log/*/*; do
  { [ -f "$f" ] || [ -L "$f" ]; } && xstat "$f"
done

echo "===SECTION log_timestamps==="
for f in /var/log/auth.log /var/log/syslog; do
  echo "--- file:$f"
  [ -e "$f" ] || { echo "--- missing"; continue; }
  [ -r "$f" ] || { echo "--- unreadable"; continue; }
  echo "--- lines:$(wc -l < "$f")"
  [ -r "$f.1" ] && echo "--- prev_last:$(tail -n 1 "$f.1" | cut -c1-200)"
  echo "--- first:$(head -n 1 "$f" | cut -c1-200)"
  echo "--- last:$(tail -n 1 "$f" | cut -c1-200)"
  awk '{t=$1; sub(/\.[0-9]+/, "", t); print t}' "$f" | uniq -c
done

echo "===SECTION journal==="
echo "--- boots:"
journalctl --list-boots --no-pager 2>&1
echo "--- disk_usage:$(journalctl --disk-usage 2>&1 | tail -n 1)"
st=$( { systemd-analyze cat-config systemd/journald.conf 2>/dev/null || cat /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null; } | grep -E '^[[:space:]]*Storage=' | tail -n 1)
echo "--- storage_setting:${st:-<default>}"
if [ -d /var/log/journal ]; then echo "--- persistent_dir:yes"; else echo "--- persistent_dir:no"; fi
v=$(journalctl --verify 2>&1); rc=$?
echo "--- verify_rc:$rc"
echo "--- verify_pass:$(echo "$v" | grep -c '^PASS')"
echo "--- verify_fail:$(echo "$v" | grep -c '^FAIL')"
echo "$v" | grep '^FAIL' | head -n 20 | cut -c1-200 | sed 's/^/--- fail:/'

echo "===SECTION services==="
for u in systemd-journald rsyslog auditd; do
  echo "--- unit:$u"
  echo "is_active=$(systemctl is-active "$u" 2>&1 | head -n 1)"
  echo "is_enabled=$(systemctl is-enabled "$u" 2>&1 | head -n 1)"
  systemctl show "$u" --no-pager -p LoadState,ActiveState,SubState,ActiveEnterTimestamp,InactiveEnterTimestamp,NRestarts 2>&1
done

echo "===SECTION audit==="
if command -v auditctl >/dev/null 2>&1; then
  echo "--- source:auditctl"; auditctl -s 2>&1; echo "--- rc:$?"
else echo "--- source:none (auditctl not installed)"; fi
xstat /var/log/audit/audit.log

echo "===SECTION logrotate==="
xstat /var/lib/logrotate/status
echo "--- timer:"
systemctl show logrotate.timer --no-pager -p ActiveState,LastTriggerUSec,NextElapseUSecRealtime 2>&1
echo "--- status:"
cat /var/lib/logrotate/status 2>&1

echo "===SECTION login_records==="
xstat /var/log/wtmp /var/log/btmp /var/log/lastlog
[ -e /var/lib/lastlog/lastlog2.db ] && xstat /var/lib/lastlog/lastlog2.db

echo "===SECTION shell_history==="
HRE='HIST(FILE|SIZE|FILESIZE|CONTROL|IGNORE)=|unset[[:space:]].*HIST|set[[:space:]]+\+o[[:space:]]+history'
getent passwd | awk -F: '$7!="" && $7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1":"$6":"$7}' |
while IFS=: read -r u h s; do
  echo "--- user:$u home:$h shell:$s"
  xstat "$h/.bash_history"
  [ -e "$h/.zsh_history" ] && xstat "$h/.zsh_history"
  for f in "$h/.bashrc" "$h/.profile" "$h/.bash_profile" "$h/.bash_login"; do
    [ -f "$f" ] && grep -HnE "$HRE" "$f" 2>/dev/null
  done
done
echo "--- system:"
for f in /etc/profile /etc/bash.bashrc /etc/profile.d/*; do
  [ -f "$f" ] && grep -HnE "$HRE" "$f" 2>/dev/null
done

echo "===END==="
"""

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _iso(epoch):
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _epoch_from_iso(s):
    """ISO8601 with offset (or Z / naive=UTC) -> int epoch, else None."""
    if not s:
        return None
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = re.sub(r"\.\d+", "", s, count=1)          # drop fractional seconds
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return int(d.timestamp())


_SYSTEMD_TS_RE = re.compile(r"(\d{4}-\d\d-\d\d)\s+(\d\d:\d\d:\d\d)(?:\s+([A-Za-z]+))?")


def _epoch_from_systemd(s):
    """'Thu 2026-10-22 22:58:08 UTC' -> (epoch, non_utc_zone_or_None)."""
    m = _SYSTEMD_TS_RE.search(s or "")
    if not m:
        return None, None
    try:
        d = datetime.strptime(m.group(1) + " " + m.group(2), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None, None
    zone = m.group(3)
    odd = zone if zone and zone.upper() not in ("UTC", "GMT") else None
    return int(d.replace(tzinfo=timezone.utc).timestamp()), odd


def _epoch_from_rotate(s):
    """logrotate status '2026-10-25-0:0:0' (or '2026-10-25') -> epoch (UTC assumed)."""
    m = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})(?:-(\d{1,2}):(\d{1,2}):(\d{1,2}))?$", (s or "").strip())
    if not m:
        return None
    try:
        vals = [int(x) if x is not None else 0 for x in m.groups()]
        return int(datetime(*vals, tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


def _hms(sec):
    sec = int(round(sec))
    neg = sec < 0
    sec = abs(sec)
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    out = ("%dd" % d if d else "") + ("%dh" % h if h else "") + ("%dm" % m if m else "")
    out = out + ("%ds" % s if s or not out else "")
    return ("-" if neg else "") + out


def _key_id(key):
    return hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:16]


def _norm_boot(b):
    b = (b or "").strip().lower().replace("-", "")
    return b if re.match(r"^[0-9a-f]{32}$", b) else None


def _resolve_path(p, default=None, for_write=False):
    """Expand ~; a bare filename resolves to ./name if it exists there,
    otherwise ~/Documents/name (Pythonista's working area)."""
    p = os.path.expanduser((p or default or "").strip())
    if not p:
        return p
    if os.path.isabs(p) or os.sep in p:
        return p
    if os.path.exists(p) and not for_write:
        return os.path.abspath(p)
    docs = os.path.expanduser("~/Documents")
    if os.path.isdir(docs) or for_write:
        return os.path.join(docs, p)
    return os.path.abspath(p)


def parse_stat_line(ln):
    """Accept old-space, 5-field pipe, and 7-field extended pipe. Return dict or None."""
    if "|" in ln:
        parts = ln.split("|")
        if not parts[0].strip().isdigit():
            return None
        if len(parts) >= 7 and parts[4].strip().isdigit() and parts[5].strip().isdigit():
            path = "|".join(parts[6:]).strip()
            if path.startswith("/"):
                return {"epoch": int(parts[0]), "owner": parts[1].strip(), "perms": parts[2].strip(),
                        "ftype": parts[3].strip(), "size": int(parts[4]), "inode": int(parts[5]),
                        "path": path}
        if len(parts) >= 5:
            path = "|".join(parts[4:]).strip()
            if path.startswith("/"):
                return {"epoch": int(parts[0]), "owner": parts[1].strip(), "perms": parts[2].strip(),
                        "ftype": parts[3].strip(), "size": None, "inode": None, "path": path}
        return None
    toks = ln.split(None, 3)
    if len(toks) == 4 and toks[0].isdigit() and toks[3].strip().startswith("/"):
        return {"epoch": int(toks[0]), "owner": toks[1], "perms": toks[2], "ftype": None,
                "size": None, "inode": None, "path": toks[3].strip()}
    return None


def _is_empty(st):
    if st.get("size") is not None:
        return st["size"] == 0
    return "empty" in (st.get("ftype") or "").lower()


def _is_link(st):
    return "symbolic link" in (st.get("ftype") or "").lower()


# --------------------------------------------------------------------------- #
# section splitting + generic blocks
# --------------------------------------------------------------------------- #

def split_sections(text):
    sections, order, buf = {}, [], []
    cur = None
    complete = False
    saw_marker = False
    preamble = []
    for ln in text.splitlines():
        s = ln.strip()
        if s == "===END===":
            complete = True
            continue
        m = re.match(r"^===SECTION\s+(\S+)===$", s)
        if m:
            saw_marker = True
            if cur is not None:
                sections[cur] = buf
            cur = m.group(1)
            order.append(cur)
            buf = []
            continue
        if cur is None:
            if s:
                preamble.append(ln)
        else:
            buf.append(ln)
    if cur is not None:
        sections[cur] = buf
    return sections, order, complete, saw_marker, preamble


def _stat_block(lines):
    """xstat output -> (stats{path:st}, links{path:target}, missing[list], rest[lines])."""
    stats, links, missing, rest = {}, {}, [], []
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("--- link:"):
            body = s[len("--- link:"):]
            if " -> " in body:
                p, t = body.split(" -> ", 1)
                links[p.strip()] = t.strip()
            continue
        if s.startswith("--- missing:"):
            missing.append(s[len("--- missing:"):].strip())
            continue
        st = parse_stat_line(s)
        if st:
            stats[st["path"]] = st
        else:
            rest.append(ln)
    for p, t in links.items():
        if p in stats:
            stats[p]["link"] = t
    return stats, links, missing, rest


# --------------------------------------------------------------------------- #
# section parsers
# --------------------------------------------------------------------------- #

def _parse_meta(lines):
    m = {}
    for ln in lines:
        s = ln.strip()
        if ":" in s:
            k, v = s.split(":", 1)
            m[k.strip()] = v.strip()
    return m


_TS_LINE_RE = re.compile(r"^\s*(\d+)\s+(\S+)\s*$")
_TS_EMPTY_RE = re.compile(r"^\s*(\d+)\s*$")


def _parse_timestamps(lines):
    files, cur = {}, None
    for ln in lines:
        s = ln.rstrip("\n")
        st = s.strip()
        if st.startswith("--- file:"):
            cur = st[len("--- file:"):].strip()
            files[cur] = {"path": cur, "state": "ok", "lines": None, "prev_last": None,
                          "first": None, "last": None, "stamps": [], "unparsed": 0,
                          "blank": 0, "total": 0}
            continue
        if cur is None or not st:
            continue
        f = files[cur]
        if st == "--- missing":
            f["state"] = "missing"
        elif st == "--- unreadable":
            f["state"] = "unreadable"
        elif st.startswith("--- lines:"):
            v = st[len("--- lines:"):].strip()
            f["lines"] = int(v) if v.isdigit() else None
        elif st.startswith("--- prev_last:"):
            f["prev_last"] = st[len("--- prev_last:"):].strip()
        elif st.startswith("--- first:"):
            f["first"] = st[len("--- first:"):].strip()
        elif st.startswith("--- last:"):
            f["last"] = st[len("--- last:"):].strip()
        else:
            m = _TS_LINE_RE.match(s)
            if m:
                n = int(m.group(1))
                f["total"] += n
                e = _epoch_from_iso(m.group(2))
                if e is None:
                    f["unparsed"] += n
                else:
                    f["stamps"].append(e)
                continue
            m = _TS_EMPTY_RE.match(s)
            if m:
                f["blank"] += int(m.group(1))
                f["total"] += int(m.group(1))
                continue
            f["unparsed"] += 1
    return files


def _lead_epoch(line):
    if not line:
        return None
    return _epoch_from_iso(line.split()[0])


_BOOT_RE = re.compile(
    r"^\s*(-?\d+)\s+([0-9a-fA-F-]{32,36})\s+\S+\s+(\d{4}-\d\d-\d\d\s+\d\d:\d\d:\d\d)(?:\s+(\S+))?"
    r"\s+\S+\s+(\d{4}-\d\d-\d\d\s+\d\d:\d\d:\d\d)")


def _parse_journal(lines):
    j = {"boots": [], "disk_usage": None, "storage": None, "persistent_dir": None,
         "verify_rc": None, "verify_pass": None, "verify_fail": None, "fail_paths": [],
         "boot_unparsed": [], "odd_zone": None}
    mode = None
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("--- boots:"):
            mode = "boots"
            continue
        if s.startswith("--- "):
            mode = None
            k, _, v = s[4:].partition(":")
            v = v.strip()
            if k == "disk_usage":
                j["disk_usage"] = v
            elif k == "storage_setting":
                j["storage"] = v
            elif k == "persistent_dir":
                j["persistent_dir"] = v
            elif k in ("verify_rc", "verify_pass", "verify_fail"):
                j[k] = int(v) if re.match(r"^-?\d+$", v) else None
            elif k == "fail":
                m = re.search(r"(/\S+)", v)
                j["fail_paths"].append(m.group(1) if m else v)
            continue
        if mode == "boots":
            if s.startswith("IDX"):
                continue
            m = _BOOT_RE.match(s)
            if m:
                first, z1 = _epoch_from_systemd(m.group(3) + " " + (m.group(4) or ""))
                last, _ = _epoch_from_systemd(m.group(5) + " UTC")
                if z1:
                    j["odd_zone"] = z1
                j["boots"].append({"idx": int(m.group(1)), "boot_id": _norm_boot(m.group(2)),
                                   "first": first, "last": last})
            else:
                j["boot_unparsed"].append(s)
    j["boots"].sort(key=lambda b: b["idx"])
    return j


def _parse_services(lines):
    units, cur = {}, None
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("--- unit:"):
            cur = s[len("--- unit:"):].strip()
            units[cur] = {}
            continue
        if cur and "=" in s:
            k, v = s.split("=", 1)
            units[cur][k.strip()] = v.strip()
    return units


def _parse_audit(lines):
    stats, _, missing, rest = _stat_block(lines)
    a = {"source": None, "rc": None, "kv": {}, "stat": stats.get("/var/log/audit/audit.log"),
         "missing": missing}
    for ln in rest:
        s = ln.strip()
        if s.startswith("--- source:"):
            a["source"] = s[len("--- source:"):].strip()
        elif s.startswith("--- rc:"):
            a["rc"] = s[len("--- rc:"):].strip()
        else:
            toks = s.split(None, 1)
            if len(toks) == 2:
                a["kv"][toks[0]] = toks[1].strip()
    return a


_ROT_RE = re.compile(r'^"([^"]+)"\s+(\S+)\s*$')


def _parse_logrotate(lines):
    r = {"stat": None, "timer": {}, "entries": {}, "unparsed": [], "missing": []}
    stat_lines, mode = [], None
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s == "--- timer:":
            mode = "timer"
            continue
        if s == "--- status:":
            mode = "status"
            continue
        if mode is None:
            stat_lines.append(s)
        elif mode == "timer":
            if "=" in s:
                k, v = s.split("=", 1)
                r["timer"][k.strip()] = v.strip()
        else:
            if s.startswith("logrotate state"):
                continue
            m = _ROT_RE.match(s)
            if m:
                r["entries"][m.group(1)] = {"raw": m.group(2), "epoch": _epoch_from_rotate(m.group(2))}
            else:
                r["unparsed"].append(s)
    stats, _, missing, _ = _stat_block(stat_lines)
    r["stat"] = stats.get("/var/lib/logrotate/status")
    r["missing"] = missing
    return r


_HIST_GREP_RE = re.compile(r"^(/[^:]+):(\d+):(.*)$")
_HIST_VAR_RE = re.compile(r"\bHIST(FILE|SIZE|FILESIZE|CONTROL|IGNORE)=(\"[^\"]*\"|'[^']*'|[^\s;]*)")


def _parse_history(lines):
    users, cur, grep_lines, stat_lines = [], None, [], {}
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("--- user:"):
            m = re.match(r"^--- user:(\S+)\s+home:(\S*)\s+shell:(\S*)", s)
            cur = {"user": m.group(1), "home": m.group(2), "shell": m.group(3)} if m else \
                {"user": s[9:].split()[0], "home": "", "shell": ""}
            cur["stat_lines"] = []
            users.append(cur)
            continue
        if s == "--- system:":
            cur = None
            continue
        if s.startswith("--- link:") or s.startswith("--- missing:") or parse_stat_line(s):
            if cur is not None:
                cur["stat_lines"].append(s)
            continue
        m = _HIST_GREP_RE.match(s)
        if m:
            grep_lines.append({"path": m.group(1), "lineno": int(m.group(2)),
                               "content": m.group(3), "user": cur["user"] if cur else None})
    for u in users:
        st, links, missing, _ = _stat_block(u.pop("stat_lines"))
        u["files"], u["missing"] = st, missing
    return users, grep_lines


# --------------------------------------------------------------------------- #
# records / flags
# --------------------------------------------------------------------------- #

def _rec(section, kind, key, content="", path=None, unit=None, boot_id=None,
         event_time=None, time_source=None, data=None, **extra):
    r = {"section": section, "kind": kind, "key": key, "entry_id": _key_id(key),
         "path": path, "unit": unit, "boot_id": boot_id, "content": content,
         "event_time": event_time, "time_source": time_source,
         "data": data or {}, "flags": []}
    r.update(extra)
    return r


def _flag(rec, code, severity, detail):
    rec["flags"].append({"code": code, "severity": severity, "detail": detail})


def _ack_key(code, key, detail):
    return "%s|%s|%s" % (code, key, detail)


def _fail(msg):
    return {"ok": False, "error": msg, "records": [], "flagged": [], "info": [],
            "acknowledged": []}


def _overlaps(a, b, windows):
    hits = []
    for (ws, we, label) in windows:
        if ws is None:
            continue
        we = ws if we is None else we
        if a <= we + OVERLAP_SLACK and b >= ws - OVERLAP_SLACK:
            hits.append(label)
    return hits


def _rotated_siblings(path, files):
    """[(n, st)] for path.N / path.N.gz, sorted by N."""
    out = []
    pre = path + "."
    for p, st in files.items():
        if p.startswith(pre):
            m = re.match(r"^(\d+)(?:\.gz|\.xz|\.bz2|\.zst)?$", p[len(pre):])
            if m:
                out.append((int(m.group(1)), st))
    out.sort(key=lambda x: x[0])
    return out


def _rotation_period(path, files):
    """Median spacing of rotated-sibling mtimes when regular, else None.
    Returns (period, latest_interval)."""
    sib = [st["epoch"] for _, st in _rotated_siblings(path, files) if st.get("epoch")]
    if len(sib) < 4:
        return None, None
    diffs = [sib[i] - sib[i + 1] for i in range(len(sib) - 1)]
    older = sorted(diffs[1:])
    if not older or older[0] <= 0 or older[-1] / float(older[0]) > 1.25:
        return None, None
    return older[len(older) // 2], diffs[0]


def analyze_timestamps(path, f, threshold, coll, windows, boot_windows):
    """Return (records, cadence_summary)."""
    recs = []
    t = f["stamps"]
    gaps, small_regs, max_small = [], 0, 0
    big_regs = []
    hi = None
    for e in t:
        if hi is None:
            hi = e
            continue
        if e < hi:
            back = hi - e
            if back > REGRESSION_TOLERANCE:
                big_regs.append((hi, e, back))
            else:
                small_regs += 1
                max_small = max(max_small, back)
            continue
        gaps.append((e - hi, hi, e, "within file"))
        hi = e
    spacing = sorted(g[0] for g in gaps)
    cad = {"path": path, "stamps": len(t), "threshold": threshold,
           "first": _iso(t[0]) if t else None, "last": _iso(t[-1]) if t else None,
           "median": spacing[len(spacing) // 2] if spacing else None,
           "p99": spacing[min(len(spacing) - 1, int(len(spacing) * 0.99))] if spacing else None,
           "max": spacing[-1] if spacing else None,
           "small_regressions": small_regs, "max_small_regression": max_small,
           "big_regressions": len(big_regs), "unparsed": f["unparsed"]}

    # rotation boundary: last line of .1 -> first line of current
    pl, fl = _lead_epoch(f.get("prev_last")), (t[0] if t else _lead_epoch(f.get("first")))
    if pl is not None and fl is not None:
        if fl >= pl:
            gaps.append((fl - pl, pl, fl, "across rotation boundary (%s.1 -> %s)"
                         % (os.path.basename(path), os.path.basename(path))))
        elif pl - fl > REGRESSION_TOLERANCE:
            big_regs.append((pl, fl, pl - fl))
        cad["boundary_gap"] = fl - pl
    # went dark: last stamp -> collection
    if t and coll is not None and coll - t[-1] > 0:
        gaps.append((coll - t[-1], t[-1], coll, "no entries since then, up to collection (log went dark)"))
        cad["tail_gap"] = coll - t[-1]

    over = [g for g in gaps if g[0] > threshold]
    over.sort(key=lambda g: g[1])
    if len(over) > MAX_GAP_RECORDS:
        cad["gaps_suppressed"] = len(over) - MAX_GAP_RECORDS
        over = sorted(over, key=lambda g: -g[0])[:MAX_GAP_RECORDS]
        over.sort(key=lambda g: g[1])
    for secs, a, b, where in over:
        hits = _overlaps(a, b, windows)
        reboot = _overlaps(a, b, boot_windows)
        sev = "high" if (secs > GAP_HIGH or hits) else "medium"
        detail = "%s silent for %s (%s -> %s), %s; threshold %ss" % (
            os.path.basename(path), _hms(secs), _iso(a), _iso(b), where, threshold)
        if hits:
            detail += "; OVERLAPS " + ", ".join(hits)
        if reboot:
            detail += "; spans " + ", ".join(reboot)
        r = _rec("log_timestamps", "log_gap", "gap:%s:%d" % (path, a), path=path,
                 event_time=_iso(a), time_source="event", gap_end=_iso(b), gap_seconds=int(secs),
                 content=where)
        _flag(r, "log_gap", sev, detail)
        recs.append(r)
    for hi_e, e, back in big_regs:
        r = _rec("log_timestamps", "timestamp_regression", "regress:%s:%d" % (path, e), path=path,
                 event_time=_iso(e), time_source="event", data={"after": _iso(hi_e), "back_seconds": back})
        _flag(r, "timestamp_regression", "high",
              "%s jumps BACK %s: %s appears after %s (tolerance %ss)"
              % (os.path.basename(path), _hms(back), _iso(e), _iso(hi_e), REGRESSION_TOLERANCE))
        recs.append(r)
    if small_regs:
        r = _rec("log_timestamps", "regression_small", "regress_small:%s" % path, path=path,
                 event_time=_iso(t[-1]) if t else None, time_source="collection",
                 data={"count": small_regs, "max_back": max_small})
        _flag(r, "timestamp_regression", "info",
              "%d small backward step(s) in %s, max %ss (<= %ss tolerance; normal rsyslog reordering)"
              % (small_regs, os.path.basename(path), max_small, REGRESSION_TOLERANCE))
        recs.append(r)
    return recs, cad


# --------------------------------------------------------------------------- #
# top-level audit
# --------------------------------------------------------------------------- #

def audit(text, baseline_data=None, collected_at=None, gap_overrides=None):
    if text is None or not text.strip():
        return _fail("EMPTY INPUT: no dump text was provided.")
    sections, order, complete, saw_marker, preamble = split_sections(text)
    if not saw_marker:
        return _fail("NO SECTION MARKERS: input has no '===SECTION ...===' lines; "
                     "this is not a log-integrity dump.")

    notes, problems, records = [], [], []
    if preamble:
        notes.append("%d line(s) before the first section marker (ignored)." % len(preamble))
    missing = [s for s in EXPECTED_SECTIONS if s not in sections]
    extra = [s for s in order if s not in EXPECTED_SECTIONS]

    # ---- meta ----
    meta = _parse_meta(sections.get("meta", []))
    if collected_at:
        coll, coll_src = _epoch_from_iso(collected_at), "override"
    elif _epoch_from_iso(meta.get("collected_utc")):
        coll, coll_src = _epoch_from_iso(meta.get("collected_utc")), "meta"
    else:
        coll, coll_src = int(datetime.now(timezone.utc).timestamp()), "now (dump has no collected_utc)"
        problems.append("NO COLLECTION TIME in dump: 'went dark' and rotation checks use NOW, "
                        "which is wrong for an old dump. Pass --collected-at.")
    coll_iso = _iso(coll)
    host = meta.get("host")
    boot_id = _norm_boot(meta.get("boot_id"))
    cuid = meta.get("collector_uid")
    if cuid is not None and cuid != "0":
        problems.append("COLLECTOR NOT ROOT (uid %s): log timestamps, journal verify, auditctl and "
                        "other users' history are unreliable or empty." % cuid)

    # ---- log_files ----
    files, links, _, lf_rest = _stat_block(sections.get("log_files", []))
    if lf_rest:
        notes.append("%d unparsed line(s) in log_files." % len(lf_rest))
    if "log_files" in sections and not files:
        problems.append("LOG_FILES EMPTY: no stat lines — file sizes/inodes NOT examined.")
    if files and all(st.get("inode") is None for st in files.values()):
        notes.append("log_files has no size/inode (old stat format): truncation compare limited to "
                     "'empty' file types.")

    # ---- services (needed for windows) ----
    units = _parse_services(sections.get("services", []))
    windows, svc_state = [], {}
    sys_broken = False
    for u in LOGGING_UNITS:
        d = units.get(u)
        if d is None:
            continue
        ia = d.get("is_active", "")
        if "not been booted with systemd" in ia or "Failed to connect" in ia:
            sys_broken = True
        ae, z1 = _epoch_from_systemd(d.get("ActiveEnterTimestamp"))
        ie, z2 = _epoch_from_systemd(d.get("InactiveEnterTimestamp"))
        if z1 or z2:
            notes.append("%s timestamps not in UTC (%s); treated as UTC." % (u, z1 or z2))
        svc_state[u] = {"is_active": ia, "is_enabled": d.get("is_enabled", ""),
                        "load": d.get("LoadState", ""), "active_enter": ae, "inactive_enter": ie,
                        "nrestarts": int(d["NRestarts"]) if d.get("NRestarts", "").isdigit() else None}
        if ia != "active" and ie is not None:
            windows.append((ie, coll, "%s inactive since %s" % (u, _iso(ie))))
        elif ie is not None and ae is not None and ae >= ie:
            windows.append((ie, ae, "%s stop/restart at %s" % (u, _iso(ie))))
    if "services" in sections:
        if sys_broken:
            problems.append("SERVICES NOT EXAMINED: systemctl could not talk to systemd.")
        miss_u = [u for u in LOGGING_UNITS if u not in units]
        if miss_u:
            problems.append("SERVICES INCOMPLETE: no data for %s." % ", ".join(miss_u))

    # ---- journal (boots needed for windows) ----
    jr = _parse_journal(sections.get("journal", []))
    boot_windows = []
    for prev, nxt in zip(jr["boots"], jr["boots"][1:]):
        if prev["last"] is not None and nxt["first"] is not None:
            boot_windows.append((prev["last"], nxt["first"], "reboot %s -> %s" % (_iso(prev["last"]), _iso(nxt["first"]))))

    # ---- log_timestamps ----
    thresholds = dict(GAP_THRESHOLDS)
    thresholds.update(gap_overrides or {})
    ts = _parse_timestamps(sections.get("log_timestamps", []))
    cadence = []
    if "log_timestamps" in sections:
        for p in TS_FILES:
            f = ts.get(p)
            if f is None:
                problems.append("LOG_TIMESTAMPS: no block for %s — gaps NOT examined." % p)
                continue
            if f["state"] != "ok":
                problems.append("LOG_TIMESTAMPS: %s is %s — gaps NOT examined." % (p, f["state"].upper()))
                continue
            if not f["stamps"]:
                problems.append("LOG_TIMESTAMPS: %s has no parseable timestamps — gaps NOT examined." % p)
                continue
            if f["unparsed"] > 0.5 * max(1, f["total"]):
                problems.append("LOG_TIMESTAMPS: %s is mostly non-ISO8601 (%d of %d lines) — "
                                "gap analysis unreliable." % (p, f["unparsed"], f["total"]))
            elif f["unparsed"]:
                notes.append("%s: %d line(s) without an ISO8601 lead timestamp (skipped)."
                             % (p, f["unparsed"]))
            if f["lines"] is not None and f["total"] < f["lines"]:
                notes.append("%s: %d timestamp lines < wc -l %d — file SHRANK during collection?"
                             % (p, f["total"], f["lines"]))
            th = thresholds.get(p, thresholds.get(os.path.basename(p), GAP_DEFAULT))
            recs, cad = analyze_timestamps(p, f, th, coll, windows, boot_windows)
            records.extend(recs)
            cadence.append(cad)

    # ---- log file records + key-log checks ----
    rot = _parse_logrotate(sections.get("logrotate", []))
    lr_stats, _, lr_missing, _ = _stat_block(sections.get("login_records", []))
    audit_sec = _parse_audit(sections.get("audit", []))
    # dedicated sections were stat'ed later and win over log_files; a mismatch
    # between the two reads (type/inode) is itself worth noting.
    all_files = dict(files)
    for src in (lr_stats, {audit_sec["stat"]["path"]: audit_sec["stat"]} if audit_sec["stat"] else {}):
        for p, st in src.items():
            old = files.get(p)
            if old and ((old.get("inode") is not None and st.get("inode") is not None
                         and old["inode"] != st["inode"]) or
                        (old.get("ftype") and st.get("ftype") and _is_link(old) != _is_link(st))):
                notes.append("%s changed DURING collection (log_files: %s inode %s; later read: %s inode %s)"
                             % (p, old.get("ftype"), old.get("inode"), st.get("ftype"), st.get("inode")))
            all_files[p] = st
    for p, st in sorted(files.items()):
        r = _rec("log_files", "log_file", "file:" + p, path=p, event_time=_iso(st["epoch"]),
                 time_source="mtime", data={k: st.get(k) for k in ("size", "inode", "owner", "perms", "ftype", "link")})
        records.append(r)
    absent = set(lr_missing) | set(audit_sec["missing"])
    for p, writer in KEY_LOGS.items():
        st = all_files.get(p)
        wstate = svc_state.get(writer, {}).get("is_active") if writer else "always"
        if st is None:
            if p in absent or ("log_files" in sections and files):
                r = _rec("log_files", "key_log", "keylog:" + p, path=p, event_time=coll_iso,
                         time_source="collection")
                if writer is None or wstate == "active":
                    _flag(r, "log_wiped_or_empty", "high",
                          "%s is MISSING while its writer (%s) is active" % (p, writer or "login/sshd"))
                    records.append(r)
            continue
        r = _rec("log_files", "key_log", "keylog:" + p, path=p, event_time=_iso(st["epoch"]),
                 time_source="mtime", data={"size": st.get("size"), "inode": st.get("inode")})
        if _is_link(st) or st.get("link"):
            tgt = st.get("link") or "?"
            _flag(r, "log_symlinked", "high",
                  "%s is a SYMLINK -> %s (writes go %s)" % (p, tgt, "nowhere" if tgt == "/dev/null" else "elsewhere"))
        elif _is_empty(st) and (writer is None or wstate == "active"):
            rt = rot["entries"].get(p, {}).get("epoch")
            if rt is not None and coll - rt < EMPTY_GRACE:
                _flag(r, "log_wiped_or_empty", "low",
                      "%s is 0 bytes but was rotated %s ago (likely just rotated)" % (p, _hms(coll - rt)))
            else:
                _flag(r, "log_wiped_or_empty", "high",
                      "%s is 0 bytes while its writer (%s) is active" % (p, writer or "login/sshd"))
        if r["flags"]:
            records.append(r)

    # ---- services: flags + timeline events ----
    pkg_times = [(p, all_files[p]["epoch"]) for p in PKG_LOGS if p in all_files]
    for u in LOGGING_UNITS:
        s = svc_state.get(u)
        if s is None:
            continue
        r = _rec("services", "service", "unit:" + u, unit=u,
                 event_time=_iso(s["active_enter"]) if s["active_enter"] else coll_iso,
                 time_source="event" if s["active_enter"] else "collection",
                 data={k: s[k] for k in ("is_active", "is_enabled", "load", "nrestarts")},
                 content="%s/%s" % (s["is_active"], s["is_enabled"]))
        if s["load"] == "not-found" or "No such file" in s["is_enabled"]:
            sev = "medium" if u == "auditd" else "high"
            _flag(r, "logging_service_down", sev, "%s is NOT INSTALLED (no %s trail at all)"
                  % (u, "audit" if u == "auditd" else "log"))
        elif s["is_active"] != "active" and not sys_broken:
            how = "enabled-but-inactive" if s["is_enabled"] in ("enabled", "static") else "inactive"
            _flag(r, "logging_service_down", "high", "%s is %s (%s, since %s)"
                  % (u, s["is_active"] or "?", how, _iso(s["inactive_enter"])))
        records.append(r)
        if s["inactive_enter"] is not None and s["active_enter"] is not None and s["active_enter"] >= s["inactive_enter"]:
            ev = _rec("services", "service_restart", "restart:%s:%d" % (u, s["inactive_enter"]), unit=u,
                      boot_id=boot_id, event_time=_iso(s["inactive_enter"]), time_source="event",
                      data={"back_up": _iso(s["active_enter"])})
            det = "%s stopped/restarted at %s (back %s); NRestarts does not count manual restarts" % (
                u, _iso(s["inactive_enter"]), _iso(s["active_enter"]))
            near = [p for p, e in pkg_times if abs(e - s["inactive_enter"]) <= PKG_CORRELATE]
            if near:
                det += "; coincides with package activity (%s mtime)" % ", ".join(os.path.basename(x) for x in near)
            if jr["boots"] and jr["boots"][-1]["first"] is not None:
                det += "; %s after boot" % _hms(s["inactive_enter"] - jr["boots"][-1]["first"])
            _flag(ev, "service_restart", "info", det)
            records.append(ev)

    # ---- audit ----
    if "audit" in sections:
        kv = audit_sec["kv"]
        if audit_sec["source"] is None or audit_sec["source"].startswith("none"):
            problems.append("AUDIT STATUS NOT EXAMINED: auditctl not available on host.")
        elif audit_sec["rc"] not in (None, "0") or "enabled" not in kv:
            problems.append("AUDIT STATUS FAILED (rc=%s): auditctl -s gave no usable output." % audit_sec["rc"])
        else:
            lost = int(kv.get("lost", "0").split()[0]) if kv.get("lost", "0").split()[0].isdigit() else None
            en = kv.get("enabled", "").split()[0]
            r = _rec("audit", "audit_status", "auditctl", event_time=coll_iso, time_source="collection",
                     data={"enabled": en, "lost": lost, "backlog": kv.get("backlog"),
                           "backlog_limit": kv.get("backlog_limit"), "failure": kv.get("failure")})
            if en == "0":
                _flag(r, "audit_disabled", "high", "auditctl reports enabled 0 — kernel audit is OFF")
            elif en == "2":
                _flag(r, "audit_locked", "info", "audit config is immutable (enabled 2) — good")
            if lost:
                _flag(r, "audit_lost_events", "medium", "kernel audit lost %d event(s) (backlog overflow "
                      "or rate limit) — records are missing" % lost)
            try:
                b, bl = int(kv.get("backlog", "0")), int(kv.get("backlog_limit", "0"))
                if bl and b > 0.8 * bl:
                    _flag(r, "audit_lost_events", "low", "audit backlog %d of %d (near overflow)" % (b, bl))
            except ValueError:
                pass
            records.append(r)

    # ---- journal ----
    if "journal" in sections:
        if jr["odd_zone"]:
            notes.append("journal boot list not in UTC (%s); treated as UTC." % jr["odd_zone"])
        if jr["boot_unparsed"]:
            notes.append("%d unparsed boot-list line(s): %r" % (len(jr["boot_unparsed"]), jr["boot_unparsed"][0][:80]))
        if not jr["boots"]:
            problems.append("JOURNAL BOOT LIST EMPTY: reboots NOT examined.")
        for b in jr["boots"]:
            r = _rec("journal", "boot", "boot:%s" % b["boot_id"], boot_id=b["boot_id"],
                     event_time=_iso(b["first"]), time_source="event",
                     data={"idx": b["idx"], "last_entry": _iso(b["last"])})
            records.append(r)
        if boot_id and jr["boots"] and jr["boots"][-1]["boot_id"] != boot_id:
            notes.append("meta boot_id %s does not match the newest journal boot %s."
                         % (boot_id, jr["boots"][-1]["boot_id"]))
        for prev, nxt in zip(jr["boots"], jr["boots"][1:]):
            if prev["last"] is None or nxt["first"] is None:
                continue
            down = nxt["first"] - prev["last"]
            r = _rec("journal", "reboot", "reboot:%s" % nxt["boot_id"], boot_id=nxt["boot_id"],
                     event_time=_iso(prev["last"]), time_source="event", gap_end=_iso(nxt["first"]),
                     gap_seconds=down, data={"from_boot": prev["boot_id"]})
            if down > BOOT_GAP_THRESHOLD:
                _flag(r, "boot_gap", "low", "host dark %s between boots (%s -> %s); corroborate the "
                      "shutdown: journalctl -b %d -n 30" % (_hms(down), _iso(prev["last"]), _iso(nxt["first"]), prev["idx"]))
            else:
                _flag(r, "reboot", "info", "reboot %s -> %s (%s dark); clean-shutdown sequence not in this "
                      "dump — corroborate with: journalctl -b %d -n 30" % (_iso(prev["last"]), _iso(nxt["first"]), _hms(down), prev["idx"]))
            records.append(r)
        # storage
        stv = (jr["storage"] or "").split("=", 1)[-1].strip().lower()
        r = _rec("journal", "journal_storage", "journal:storage", event_time=coll_iso, time_source="collection",
                 data={"storage": jr["storage"], "persistent_dir": jr["persistent_dir"],
                       "disk_usage": jr["disk_usage"]})
        if stv in ("volatile", "none"):
            _flag(r, "journal_volatile", "medium", "journald Storage=%s — journal is lost on reboot" % stv)
        elif stv in ("auto", "<default>", "") and jr["persistent_dir"] == "no":
            _flag(r, "journal_volatile", "medium", "Storage=auto and no /var/log/journal — journal is "
                  "effectively volatile (lost on reboot)")
        records.append(r)
        # verify
        vr = jr["verify_rc"]
        if vr is None:
            problems.append("JOURNAL VERIFY RESULT MISSING: integrity NOT examined.")
        elif vr == 99:
            problems.append("JOURNAL VERIFY NOT RUN (skipped): integrity NOT examined.")
        else:
            r = _rec("journal", "journal_verify", "journal:verify", event_time=coll_iso,
                     time_source="collection", data={"rc": vr, "pass": jr["verify_pass"],
                                                     "fail": jr["verify_fail"]})
            records.append(r)
            for fp in jr["fail_paths"]:
                base = os.path.basename(fp)
                fr = _rec("journal", "journal_verify_fail", "verify_fail:" + fp, path=fp,
                          event_time=coll_iso, time_source="collection")
                if base.endswith(".journal") and "@" not in base:
                    _flag(fr, "journal_verify_failed", "medium",
                          "ACTIVE journal file fails --verify (%s). Often a false positive while "
                          "journald is writing it; if it still fails once archived (renamed "
                          "system@...journal), treat as HIGH." % base)
                else:
                    _flag(fr, "journal_verify_failed", "high",
                          "ARCHIVED/set-aside journal file fails --verify (%s) — records may be "
                          "corrupted or edited" % base)
                records.append(fr)
            if (jr["verify_fail"] or 0) > len(jr["fail_paths"]):
                r2 = _rec("journal", "journal_verify_fail", "verify_fail:unlisted", event_time=coll_iso,
                          time_source="collection")
                _flag(r2, "journal_verify_failed", "high", "%d failing journal file(s) not listed (only "
                      "first 20 captured)" % (jr["verify_fail"] - len(jr["fail_paths"])))
                records.append(r2)
            if vr != 0 and not jr["verify_fail"]:
                notes.append("journalctl --verify rc=%s with 0 FAIL lines — re-run by hand to see why." % vr)

    # ---- logrotate ----
    rot_tod = None
    if "logrotate" in sections:
        lt, _ = _epoch_from_systemd(rot["timer"].get("LastTriggerUSec"))
        if lt is not None:
            rot_tod = lt % 86400
        if not rot["entries"]:
            problems.append("LOGROTATE STATUS EMPTY: rotation history NOT examined.")
        if rot["unparsed"]:
            notes.append("%d unparsed logrotate status line(s)." % len(rot["unparsed"]))
        for p, e in sorted(rot["entries"].items()):
            ep = e["epoch"]
            r = _rec("logrotate", "rotation", "rotate:" + p, path=p, event_time=_iso(ep),
                     time_source="event" if ep else None, data={"raw": e["raw"]})
            if ep is None:
                continue
            if ep > coll + 3600:
                _flag(r, "early_rotation", "low", "%s rotation time %s is in the FUTURE vs collection "
                      "(status file edited or clock jump?)" % (p, _iso(ep)))
            elif rot_tod is not None:
                off = abs((ep % 86400) - rot_tod)
                off = min(off, 86400 - off)
                if off > ROTATION_TOD_TOLERANCE:
                    _flag(r, "early_rotation", "low", "%s rotated at %s — off the logrotate.timer schedule "
                          "(%s UTC); manual 'logrotate -f'?" % (p, _iso(ep), _hms(rot_tod)))
            per, latest = _rotation_period(p, files)
            if per and latest is not None and latest < 0.5 * per:
                _flag(r, "early_rotation", "low", "%s: last rotation interval %s vs usual %s (from "
                      "rotated-file mtimes)" % (p, _hms(latest), _hms(per)))
                r["data"]["period"] = per
            records.append(r)

    # ---- login records (stat only; wipe check done via KEY_LOGS) ----
    if "login_records" in sections:
        for p, st in sorted(lr_stats.items()):
            records.append(_rec("login_records", "login_record", "login:" + p, path=p,
                                event_time=_iso(st["epoch"]), time_source="mtime",
                                data={"size": st.get("size"), "inode": st.get("inode")}))
        if not lr_stats:
            problems.append("LOGIN_RECORDS EMPTY: wtmp/btmp/lastlog NOT examined.")

    # ---- shell history ----
    if "shell_history" in sections:
        users, greps = _parse_history(sections.get("shell_history", []))
        if not users:
            problems.append("SHELL_HISTORY: no login-shell users listed — history NOT examined.")
        for u in users:
            hp = (u["home"].rstrip("/") or "") + "/.bash_history"
            st = u["files"].get(hp)
            r = _rec("shell_history", "history_file", "hist:" + hp, path=hp,
                     event_time=_iso(st["epoch"]) if st else coll_iso,
                     time_source="mtime" if st else "collection",
                     data={"user": u["user"], "size": st.get("size") if st else None,
                           "inode": st.get("inode") if st else None})
            if st is None:
                _flag(r, "history_missing", "info", "%s has a login shell but no ~/.bash_history "
                      "(never logged in, or deleted)" % u["user"])
            else:
                tgt = st.get("link")
                ft = (st.get("ftype") or "").lower()
                if _is_link(st) or tgt:
                    if tgt == "/dev/null":
                        _flag(r, "history_redirected", "high", "%s ~/.bash_history -> /dev/null" % u["user"])
                    else:
                        _flag(r, "history_redirected", "medium", "%s ~/.bash_history is a symlink -> %s"
                              % (u["user"], tgt or "?"))
                elif "character special" in ft:
                    _flag(r, "history_redirected", "high", "%s ~/.bash_history is a character device "
                          "(null-device copy)" % u["user"])
                elif _is_empty(st):
                    _flag(r, "history_empty", "low", "%s ~/.bash_history is 0 bytes" % u["user"])
            records.append(r)
        for g in greps:
            c = g["content"].strip()
            if c.startswith("#"):
                continue
            key = "histcfg:%s:%d" % (g["path"], g["lineno"])
            r = _rec("shell_history", "history_setting", key, path=g["path"], content=c[:160],
                     event_time=coll_iso, time_source="collection",
                     data={"user": g["user"], "lineno": g["lineno"]})
            where = "%s:%d" % (g["path"], g["lineno"])
            hit = False
            for m in _HIST_VAR_RE.finditer(c):
                var, val = m.group(1), m.group(2).strip("\"'")
                if var == "FILE" and val in ("/dev/null", ""):
                    _flag(r, "history_redirected", "high", "HISTFILE=%s in %s" % (val or "(empty)", where))
                    hit = True
                elif var in ("SIZE", "FILESIZE") and val == "0":
                    _flag(r, "history_redirected", "high", "HIST%s=0 in %s (history not kept)" % (var, where))
                    hit = True
                elif var == "IGNORE" and re.search(r"(^|:)\*($|:)", val):
                    _flag(r, "history_redirected", "high", "HISTIGNORE='%s' in %s ignores every command" % (val, where))
                    hit = True
                elif var == "CONTROL" and ("ignorespace" in val or "ignoreboth" in val):
                    _flag(r, "history_ignorespace", "info", "HISTCONTROL=%s in %s: commands typed with a "
                          "leading space are not recorded (stock Ubuntu)" % (val, where))
                    hit = True
            if re.search(r"\bunset\b[^#]*\bHISTFILE\b", c):
                _flag(r, "history_redirected", "high", "unset HISTFILE in %s" % where)
                hit = True
            if re.search(r"\bset\s+\+o\s+history\b", c):
                _flag(r, "history_redirected", "high", "'set +o history' in %s" % where)
                hit = True
            records.append(r)

    # ---- collect findings, apply acknowledgements ----
    acks = set((baseline_data or {}).get("acknowledged", []))
    flagged, info, acked = [], [], []
    for r in records:
        for f in r["flags"]:
            item = dict(f)
            item.update({"key": r["key"], "kind": r["kind"], "path": r["path"], "unit": r["unit"],
                         "boot_id": r["boot_id"], "event_time": r["event_time"],
                         "time_source": r["time_source"],
                         "ack_key": _ack_key(f["code"], r["key"], f["detail"])})
            for k in ("gap_end", "gap_seconds"):
                if k in r:
                    item[k] = r[k]
            if f["severity"] == "info":
                info.append(item)
            elif item["ack_key"] in acks:
                acked.append(item)
            else:
                flagged.append(item)
    flagged.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["code"], x["event_time"] or ""))
    info.sort(key=lambda x: x["event_time"] or "")
    sev = {"high": 0, "medium": 0, "low": 0}
    for f in flagged:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1

    timeline = sorted(
        [{"event_time": r["event_time"], "kind": r["kind"], "path": r["path"], "unit": r["unit"],
          "boot_id": r["boot_id"], "gap_end": r.get("gap_end"), "gap_seconds": r.get("gap_seconds"),
          "detail": (r["flags"][0]["detail"] if r["flags"] else r["content"])}
         for r in records if r["time_source"] == "event" and r["event_time"]],
        key=lambda x: x["event_time"])

    vantage_ok = complete and not missing and not problems
    return {
        "ok": True, "error": None, "version": VERSION, "host": host, "boot_id": boot_id,
        "complete": complete, "vantage_ok": vantage_ok,
        "sections_found": order, "sections_missing": missing, "sections_extra": extra,
        "problems": problems, "notes": notes,
        "collection_time": coll_iso, "collection_time_source": coll_src,
        "cadence": cadence, "record_count": len(records), "records": records,
        "flagged": flagged, "info": info, "acknowledged": acked, "severity_counts": sev,
        "timeline": timeline,
        "_files": files, "_svc": svc_state, "_rot": {p: e["epoch"] for p, e in rot["entries"].items()},
        "_audit_lost": next((r["data"].get("lost") for r in records if r["kind"] == "audit_status"), None),
        "_verify_fail": sorted(jr["fail_paths"]), "_boots": [b["boot_id"] for b in jr["boots"]],
    }


def _public(res):
    return {k: v for k, v in res.items() if not k.startswith("_")}


# --------------------------------------------------------------------------- #
# baseline / compare
# --------------------------------------------------------------------------- #

def build_baseline(text, path=None, collected_at=None, ack=False, gap_overrides=None):
    res = audit(text, collected_at=collected_at, gap_overrides=gap_overrides)
    if not res["ok"]:
        return {"ok": False, "path": None, "count": 0, "error": res["error"]}
    data = {
        "version": VERSION, "created": _now_iso(), "host": res["host"], "boot_id": res["boot_id"],
        "collection_time": res["collection_time"], "complete": res["complete"],
        "vantage_ok": res["vantage_ok"],
        "acknowledged": sorted(f["ack_key"] for f in res["flagged"]) if ack else [],
        "files": {p: {"size": st.get("size"), "inode": st.get("inode"), "mtime": st.get("epoch"),
                      "ftype": st.get("ftype"), "link": st.get("link")}
                  for p, st in res["_files"].items()},
        "services": {u: {"nrestarts": s["nrestarts"], "active_enter": s["active_enter"],
                         "inactive_enter": s["inactive_enter"], "is_active": s["is_active"],
                         "is_enabled": s["is_enabled"]} for u, s in res["_svc"].items()},
        "audit": {"lost": res["_audit_lost"]},
        "rotations": res["_rot"],
        "gaps": sorted(f["key"] for f in res["flagged"] + res["acknowledged"] if f["code"] == "log_gap"),
        "verify_fail": res["_verify_fail"],
        "boots": res["_boots"],
    }
    target = _resolve_path(path, BASELINE_DEFAULT, for_write=True)
    try:
        d = os.path.dirname(target)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(target, "w") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
    except Exception as e:
        return {"ok": False, "path": target, "count": 0, "error": "write failed: %s" % e}
    return {"ok": True, "path": target, "count": len(data["files"]),
            "acknowledged": len(data["acknowledged"]), "incomplete": not res["vantage_ok"],
            "problems": res["problems"] + (["no ===END=== terminator"] if not res["complete"] else [])
                        + (["missing sections: " + ", ".join(res["sections_missing"])]
                           if res["sections_missing"] else []),
            "error": None}


def _chg(code, severity, detail, event_time, time_source, path=None, unit=None, data=None):
    return {"code": code, "severity": severity, "detail": detail, "event_time": event_time,
            "time_source": time_source, "path": path, "unit": unit, "data": data or {}}


def compare(text, baseline_path=None, collected_at=None, gap_overrides=None):
    target = _resolve_path(baseline_path, BASELINE_DEFAULT)
    try:
        with open(target) as fh:
            base = json.load(fh)
    except Exception as e:
        return {"ok": False, "error": "cannot read baseline %s: %s" % (target, e)}
    res = audit(text, baseline_data=base, collected_at=collected_at, gap_overrides=gap_overrides)
    if not res["ok"]:
        return {"ok": False, "error": res["error"]}

    changes = []
    bcoll = _epoch_from_iso(base.get("collection_time")) or 0
    same_boot = base.get("boot_id") and base.get("boot_id") == res["boot_id"]
    F, BF = res["_files"], base.get("files", {})
    rot = res["_rot"]
    rot_paths = set(rot) | set(base.get("rotations", {}))

    def rotated_since(p):
        e = rot.get(p)
        return e is not None and e > bcoll

    # files
    for p, b in sorted(BF.items()):
        c = F.get(p)
        if c is None:
            if p in KEY_LOGS:
                changes.append(_chg("log_wiped_or_empty", "high", "%s existed in baseline, now MISSING" % p,
                                    res["collection_time"], "collection", path=p))
            continue
        if b.get("inode") is not None and c.get("inode") == b.get("inode") \
                and c.get("size") is not None and b.get("size") is not None and c["size"] < b["size"]:
            d = {"size_was": b["size"], "size_now": c["size"], "inode": c["inode"]}
            if rotated_since(p):
                changes.append(_chg("log_truncated", "info", "%s shrank in place %d -> %d after a rotation "
                                    "at %s (copytruncate)" % (p, b["size"], c["size"], _iso(rot[p])),
                                    _iso(c["epoch"]), "mtime", path=p, data=d))
            else:
                changes.append(_chg("log_truncated", "high", "%s SHRANK IN PLACE %d -> %d bytes, same inode %s, "
                                    "no rotation since baseline" % (p, b["size"], c["size"], c["inode"]),
                                    _iso(c["epoch"]), "mtime", path=p, data=d))
        elif b.get("inode") is not None and c.get("inode") is not None and c["inode"] != b["inode"]:
            moved = [sp for _, sp in [(n, st["path"]) for n, st in _rotated_siblings(p, F)]
                     if F[sp].get("inode") == b["inode"]]
            if rotated_since(p) or moved:
                changes.append(_chg("log_rotated", "info", "%s rotated (old inode %s %s)" % (
                    p, b["inode"], "now at " + moved[0] if moved else "compressed/removed"),
                    _iso(rot.get(p)) if rot.get(p) else _iso(c["epoch"]),
                    "event" if rot.get(p) else "mtime", path=p))
            elif p in KEY_LOGS or p in rot_paths:
                changes.append(_chg("log_replaced", "medium", "%s REPLACED: inode %s -> %s with no rotation "
                                    "recorded (deleted and recreated?)" % (p, b["inode"], c["inode"]),
                                    _iso(c["epoch"]), "mtime", path=p,
                                    data={"inode_was": b["inode"], "inode_now": c["inode"]}))
    # services
    for u, b in sorted(base.get("services", {}).items()):
        c = res["_svc"].get(u)
        if c is None:
            continue
        if b.get("nrestarts") is not None and c.get("nrestarts") is not None and c["nrestarts"] > b["nrestarts"]:
            changes.append(_chg("logging_service_down", "medium", "%s NRestarts %d -> %d (crashed and was "
                                "auto-restarted)" % (u, b["nrestarts"], c["nrestarts"]),
                                _iso(c["active_enter"]) if c["active_enter"] else res["collection_time"],
                                "event" if c["active_enter"] else "collection", unit=u))
        if b.get("active_enter") and c.get("active_enter") and c["active_enter"] != b["active_enter"]:
            if same_boot:
                changes.append(_chg("logging_service_restarted", "medium", "%s restarted since baseline "
                                    "(active since %s, was %s) on the same boot" % (
                                        u, _iso(c["active_enter"]), _iso(b["active_enter"])),
                                    _iso(c["inactive_enter"] or c["active_enter"]), "event", unit=u))
            else:
                changes.append(_chg("logging_service_restarted", "info", "%s restarted by reboot (active since %s)"
                                    % (u, _iso(c["active_enter"])), _iso(c["active_enter"]), "event", unit=u))
    # audit lost counter
    bl, cl = base.get("audit", {}).get("lost"), res["_audit_lost"]
    if bl is not None and cl is not None and cl > bl:
        changes.append(_chg("audit_lost_events", "medium", "audit lost counter %d -> %d" % (bl, cl),
                            res["collection_time"], "collection"))
    # rotations
    for p, ce in sorted(rot.items()):
        be = base.get("rotations", {}).get(p)
        if be is None or ce is None or ce == be:
            continue
        if ce < be:
            changes.append(_chg("early_rotation", "low", "%s rotation time went BACKWARDS %s -> %s "
                                "(status file edited?)" % (p, _iso(be), _iso(ce)), _iso(ce), "event", path=p))
            continue
        per, _ = _rotation_period(p, F)
        if per and (ce - be) < 0.5 * per:
            changes.append(_chg("early_rotation", "low", "%s rotated %s after the previous rotation; usual "
                                "interval %s" % (p, _hms(ce - be), _hms(per)), _iso(ce), "event", path=p))
        else:
            changes.append(_chg("log_rotated", "info", "%s rotated at %s" % (p, _iso(ce)), _iso(ce), "event", path=p))
    # new gaps, new verify failures, new boots
    bg = set(base.get("gaps", []))
    for f in res["flagged"]:
        if f["code"] == "log_gap" and f["key"] not in bg:
            changes.append(_chg("log_gap", f["severity"], "NEW since baseline: " + f["detail"],
                                f["event_time"], "event", path=f["path"],
                                data={"gap_end": f.get("gap_end"), "gap_seconds": f.get("gap_seconds")}))
    bv = set(base.get("verify_fail", []))
    for fp in res["_verify_fail"]:
        if fp not in bv:
            changes.append(_chg("journal_verify_failed", "high" if "@" in os.path.basename(fp) else "medium",
                                "NEW verify failure: %s" % fp, res["collection_time"], "collection", path=fp))
    bb = set(base.get("boots", []))
    for b in res["_boots"]:
        if b and b not in bb and bb:
            changes.append(_chg("reboot", "info", "boot %s not in baseline" % b, None, None))

    changes.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["event_time"] or ""))
    drift = [c for c in changes if c["severity"] != "info"]
    return {"ok": True, "error": None, "baseline": target, "baseline_time": base.get("collection_time"),
            "complete": res["complete"], "vantage_ok": res["vantage_ok"], "problems": res["problems"],
            "sections_missing": res["sections_missing"], "same_boot": bool(same_boot),
            "changes": changes, "drift_count": len(drift),
            "flagged": res["flagged"], "info": res["info"], "acknowledged": res["acknowledged"]}


# --------------------------------------------------------------------------- #
# human formatting
# --------------------------------------------------------------------------- #

_BANNER = "!" * 68


def _loud_block(res):
    L = []
    if not res.get("complete", True):
        L += [_BANNER, "!! INCOMPLETE INPUT: no '===END===' terminator — paste was truncated.",
              "!! Findings cover only what parsed; DO NOT treat as a full picture.", _BANNER]
    if res.get("sections_missing"):
        L += [_BANNER, "!! MISSING SECTIONS: " + ", ".join(res["sections_missing"]),
              "!! Those surfaces were NOT examined.", _BANNER]
    for p in res.get("problems", []):
        L += [_BANNER, "!! " + p, _BANNER]
    return L


def _finding_lines(items):
    out = []
    for f in items:
        tgt = f.get("unit") or f.get("path") or f.get("boot_id") or f.get("key")
        when = "@%s (%s)" % (f.get("event_time"), f.get("time_source"))
        if f.get("gap_end"):
            when += " -> %s [%s]" % (f["gap_end"], _hms(f.get("gap_seconds") or 0))
        out.append("  [%-6s] %-26s %s" % (f["severity"].upper(), f["code"], tgt))
        out.append("           %s" % when)
        out.append("           -> %s" % f["detail"])
    return out


def format_human(res, timeline_max=25):
    if not res.get("ok"):
        return "%s\n!! AUDIT FAILED: %s\n%s" % (_BANNER, res.get("error"), _BANNER)
    L = []
    sev = res["severity_counts"]
    nflag = len(res["flagged"])
    verdict = ("%d flagged (%d HIGH / %d MED / %d LOW)" % (nflag, sev["high"], sev["medium"], sev["low"])
               if nflag else "nothing flagged")
    L.append("LIAO LOG-INTEGRITY AUDIT  v%s   host=%s   collected=%s (%s)"
             % (VERSION, res["host"], res["collection_time"], res["collection_time_source"]))
    L.append("RESULT: %s   |   dump %s   |   vantage %s"
             % (verdict, "COMPLETE" if res["complete"] else "INCOMPLETE",
                "OK" if res["vantage_ok"] else "DEGRADED"))
    L.append("")
    L += _loud_block(res)
    if res["sections_extra"]:
        L.append("?? Unexpected sections (not parsed): " + ", ".join(res["sections_extra"]))
    L.append("Parsed %d records across %d sections." % (res["record_count"], len(res["sections_found"])))
    L.append("")
    if res["cadence"]:
        L.append("LOG CADENCE  (gap threshold per file; calibrate with --gap)")
        for c in res["cadence"]:
            L.append("  %-18s %6d stamps  median %-5s p99 %-6s max %-7s thr %-5s back-steps %d (max %ss)"
                     % (os.path.basename(c["path"]), c["stamps"], _hms(c["median"] or 0), _hms(c["p99"] or 0),
                        _hms(c["max"] or 0), _hms(c["threshold"]), c["small_regressions"] + c["big_regressions"],
                        c["max_small_regression"]))
            extra = []
            if "boundary_gap" in c:
                extra.append("rotation boundary %s" % _hms(c["boundary_gap"]))
            if "tail_gap" in c:
                extra.append("last entry %s before collection" % _hms(c["tail_gap"]))
            if c.get("gaps_suppressed"):
                extra.append("%d smaller over-threshold gaps not listed" % c["gaps_suppressed"])
            if extra:
                L.append("  %-18s %s" % ("", "; ".join(extra)))
        L.append("")
    if res["flagged"]:
        L.append("FLAGGED  (review candidates, NOT verdicts)")
        L += _finding_lines(res["flagged"])
        L.append("")
    if res["info"]:
        L.append("INFO  (context — not counted as flagged)")
        L += _finding_lines(res["info"])
        L.append("")
    if res["acknowledged"]:
        L.append("ACKNOWLEDGED in baseline (suppressed): %d" % len(res["acknowledged"]))
        for f in res["acknowledged"]:
            L.append("  ~ %s  %s" % (f["code"], f.get("unit") or f.get("path") or f["key"]))
        L.append("")
    tl = res.get("timeline") or []
    if tl:
        L.append("TIMELINE  (events, UTC; %d total%s)" % (len(tl), ", newest %d shown" % timeline_max
                                                          if len(tl) > timeline_max else ""))
        for e in tl[-timeline_max:]:
            tgt = e.get("unit") or (os.path.basename(e["path"]) if e.get("path") else None) or (e.get("boot_id") or "")[:12]
            span = " -> %s" % e["gap_end"] if e.get("gap_end") else ""
            L.append("  %s%s  %-15s %s" % (e["event_time"], span, e["kind"], tgt))
        L.append("")
    if res["notes"]:
        L.append("NOTES")
        for n in res["notes"]:
            L.append("  " + n)
        L.append("")
    if not res["flagged"]:
        if res["vantage_ok"]:
            L.append("Nothing flagged from this vantage.")
        else:
            L.append("Nothing flagged in what parsed — but the vantage is DEGRADED (see banners). "
                     "This is NOT an all-clear.")
    L.append("Vantage limit: reflects ONLY this dump, at collection time. A log that was edited "
             "smoothly (no gap, no shrink) is invisible here. Flags are leads, not verdicts.")
    return "\n".join(L)


def format_baseline(res):
    if not res["ok"]:
        return "%s\n!! BASELINE FAILED: %s\n%s" % (_BANNER, res["error"], _BANNER)
    L = ["BASELINE WRITTEN: %s" % res["path"],
         "  %d log files snapshotted; %d flag(s) acknowledged." % (res["count"], res["acknowledged"])]
    if res.get("incomplete"):
        L.append(_BANNER)
        L.append("!! WARNING: source dump vantage was DEGRADED — baseline is partial:")
        for p in res.get("problems", []):
            L.append("!!   " + p)
        L.append(_BANNER)
    L.append(_BANNER)
    L.append("!! COPY THIS BASELINE OFF-HOST NOW. A baseline that lives only on the")
    L.append("!! audited host can be edited by whatever you are hunting. Store a copy")
    L.append("!! somewhere the target cannot reach, and diff against that copy.")
    L.append(_BANNER)
    return "\n".join(L)


def format_compare(res):
    if not res["ok"]:
        return "%s\n!! COMPARE FAILED: %s\n%s" % (_BANNER, res["error"], _BANNER)
    L = ["COMPARE vs baseline: %s  (baseline collected %s; %s boot)"
         % (res["baseline"], res["baseline_time"], "same" if res["same_boot"] else "DIFFERENT"),
         "  dump %s | vantage %s | drift %d | current flags %d"
         % ("COMPLETE" if res["complete"] else "INCOMPLETE", "OK" if res["vantage_ok"] else "DEGRADED",
            res["drift_count"], len(res["flagged"])), ""]
    L += _loud_block(res)
    drift = [c for c in res["changes"] if c["severity"] != "info"]
    infos = [c for c in res["changes"] if c["severity"] == "info"]
    if drift:
        L.append("CHANGED since baseline  (review candidates)")
        for c in drift:
            L.append("  [%-6s] %-26s %s" % (c["severity"].upper(), c["code"], c.get("unit") or c.get("path") or ""))
            L.append("           @%s (%s)" % (c["event_time"], c["time_source"]))
            L.append("           -> %s" % c["detail"])
        L.append("")
    if infos:
        L.append("ALSO CHANGED  (expected churn — info)")
        for c in infos:
            L.append("  ~ %-22s %s  @%s" % (c["code"], c["detail"], c["event_time"]))
        L.append("")
    if not res["changes"]:
        L.append("No drift from this vantage vs the baseline.")
    if res["flagged"]:
        L.append("(Plain-audit flags still open: %d — run a normal audit for detail.)" % len(res["flagged"]))
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# install chunks (mobile terminals truncate long pastes)
# --------------------------------------------------------------------------- #

def collector_chunks(dest="~/collect_logintegrity.sh"):
    lines = COLLECT_CMD.rstrip("\n").split("\n")
    cuts = [i for i, ln in enumerate(lines) if ln.startswith('echo "===SECTION journal')
            or ln.startswith('echo "===SECTION logrotate')]
    bounds = [0] + [c - 1 for c in cuts] + [len(lines)]
    parts = [lines[bounds[i]:bounds[i + 1]] for i in range(len(bounds) - 1)]
    out = []
    for i, p in enumerate(parts):
        out.append("# chunk %d/%d  (wait for the $ prompt before the next)" % (i + 1, len(parts)))
        out.append("cat %s %s <<'EOF'" % (">" if i == 0 else ">>", dest))
        out.extend(p)
        out.append("EOF")
        out.append("")
    sha = hashlib.sha256(COLLECT_CMD.encode()).hexdigest()[:16]
    out.append("# verify: expect %d lines, hash %s, SYNTAX_OK" % (len(lines), sha))
    out.append("wc -l %s; sha256sum %s | cut -c1-16; sh -n %s && echo SYNTAX_OK" % (dest, dest, dest))
    out.append("# run in the background (survives a dropped SSH session; journal verify can take minutes):")
    out.append("sudo -v; sudo nohup sh %s > ~/logint.txt 2> ~/logint.err &" % dest)
    out.append("while pgrep -f collect_logintegrity >/dev/null; do sleep 15; done; "
               "wc -l ~/logint.txt; tail -1 ~/logint.txt")
    return "\n".join(out)


def tool_install_chunks(dest="~/log_integrity.py", lines_per_chunk=40):
    """This tool, gzip+base64'd into paste-safe chunks for installing on the droplet."""
    try:
        with open(os.path.abspath(__file__), "rb") as fh:
            raw = fh.read()
    except Exception as e:
        return "!! cannot read own source: %s" % e
    b64 = base64.b64encode(gzip.compress(raw, mtime=0)).decode()
    rows = [b64[i:i + 76] for i in range(0, len(b64), 76)]
    tmp = dest + ".b64"
    out, n = [], (len(rows) + lines_per_chunk - 1) // lines_per_chunk
    for i in range(n):
        out.append("# chunk %d/%d  (wait for the $ prompt before the next)" % (i + 1, n))
        out.append("cat %s %s <<'EOF'" % (">" if i == 0 else ">>", tmp))
        out.extend(rows[i * lines_per_chunk:(i + 1) * lines_per_chunk])
        out.append("EOF")
        out.append("")
    out.append("# assemble + verify: expect hash %s and version %s"
               % (hashlib.sha256(raw).hexdigest()[:16], VERSION))
    out.append("base64 -d %s | gunzip > %s && rm %s && sha256sum %s | cut -c1-16 && python3 %s --version"
               % (tmp, dest, tmp, dest, dest))
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# console + CLI
# --------------------------------------------------------------------------- #

def _read_paste():
    print("Paste the dump. Finish with a line containing only:  END")
    lines = []
    while True:
        try:
            ln = input()
        except EOFError:
            break
        if ln.strip() == "END":
            break
        lines.append(ln)
    return "\n".join(lines)


def _read_file(path):
    try:
        with open(_resolve_path(path), "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return None


def _console():
    while True:
        print("\n" + "=" * 52)
        print("LIAO LOG-INTEGRITY AUDIT  (read-only, owned scope)")
        print(" 1) Audit    — paste a dump")
        print(" 2) Audit    — from a file path")
        print(" 3) Baseline — build from a file path")
        print(" 4) Compare  — file path vs baseline")
        print(" 5) Collector — print the collection script")
        print(" 6) Collector — print paste-safe install chunks")
        print(" 7) Baseline + acknowledge all current flags (file path)")
        print(" 8) This tool — print install chunks for the droplet")
        print(" 0) Back")
        try:
            c = input("> ").strip()
        except EOFError:
            return
        if c == "0":
            return
        elif c == "1":
            print(format_human(audit(_read_paste())))
        elif c in ("2", "3", "4", "7"):
            p = input("dump path: ").strip()
            t = _read_file(p)
            if t is None:
                print("!! cannot read: %s" % p)
                continue
            if c == "2":
                print(format_human(audit(t)))
                continue
            b = input("baseline path [blank=default %s]: " % BASELINE_DEFAULT).strip() or None
            if c == "4":
                print(format_compare(compare(t, b)))
            else:
                print(format_baseline(build_baseline(t, b, ack=(c == "7"))))
        elif c == "5":
            print(COLLECT_CMD)
        elif c == "6":
            print(collector_chunks())
        elif c == "8":
            print(tool_install_chunks())
        else:
            print("?")


_HELP = """log_integrity.py v%s — Liao read-only log-integrity auditor

  interactive menu:    python3 log_integrity.py
  audit a file:        python3 log_integrity.py DUMP.txt [--json] [--baseline BASE.json]
  audit via stdin:     sudo sh collect_logintegrity.sh | python3 log_integrity.py --stdin [--json]
  build a baseline:    python3 log_integrity.py --build-baseline BASE.json [--ack] (DUMP.txt | --stdin)
  compare to baseline: python3 log_integrity.py --compare BASE.json (DUMP.txt | --stdin)
  print collector:     python3 log_integrity.py --collect | --collect-chunks
  install this tool:   python3 log_integrity.py --install-chunks   (paste-safe, for the droplet)
  options:             --json  --collected-at <ISO8601>  --gap auth.log=1800,syslog=600
                       --version  -h/--help
  --ack                acknowledge (suppress) every current flag in the new baseline
  --baseline B         apply B's acknowledgements to a plain audit

exit codes: 0 clean · 1 flagged/drift · 2 error · 3 incomplete input/vantage
""" % VERSION

VALUE_FLAGS = {"--compare", "--build-baseline", "--collected-at", "--baseline", "--gap"}


def _parse_gap_arg(s):
    out = {}
    for part in (s or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            k, v = k.strip(), v.strip()
            if v.isdigit():
                out[k if k.startswith("/") else "/var/log/" + k] = int(v)
    return out


def _exit_for(r, drift=0):
    if not r.get("ok"):
        return 2
    if not r.get("complete", True) or not r.get("vantage_ok", True):
        return 3
    return 1 if (r.get("flagged") or drift) else 0


def main(argv):
    args = argv[1:]
    if not args:
        _console()
        return 0
    if "-h" in args or "--help" in args:
        print(_HELP)
        return 0
    if "--version" in args:
        print(VERSION)
        return 0
    if "--collect" in args:
        print(COLLECT_CMD)
        return 0
    if "--collect-chunks" in args:
        print(collector_chunks())
        return 0
    if "--install-chunks" in args:
        print(tool_install_chunks())
        return 0

    def val(name):
        if name in args:
            i = args.index(name)
            if i + 1 < len(args) and not args[i + 1].startswith("--"):
                return args[i + 1]
        return None

    consumed = set()
    for i, a in enumerate(args):
        if a in VALUE_FLAGS and i + 1 < len(args):
            consumed.add(i + 1)
    pos = [a for i, a in enumerate(args) if not a.startswith("--") and i not in consumed]

    as_json = "--json" in args
    collected = val("--collected-at")
    gaps = _parse_gap_arg(val("--gap"))

    text = None
    if "--stdin" in args:
        text = sys.stdin.read()
    elif pos:
        text = _read_file(pos[0])
        if text is None:
            print("!! cannot read file: %s" % pos[0])
            return 2

    if "--build-baseline" in args:
        if text is None:
            text = sys.stdin.read()
        r = build_baseline(text, val("--build-baseline"), collected, ack="--ack" in args, gap_overrides=gaps)
        print(json.dumps(r, indent=2) if as_json else format_baseline(r))
        if not r["ok"]:
            return 2
        return 3 if r.get("incomplete") else 0

    if "--compare" in args:
        if text is None:
            text = sys.stdin.read()
        r = compare(text, val("--compare"), collected, gap_overrides=gaps)
        print(json.dumps(r, indent=2, default=str) if as_json else format_compare(r))
        return _exit_for(r, r.get("drift_count", 0))

    if text is None:
        _console()
        return 0

    base = None
    if val("--baseline"):
        try:
            with open(_resolve_path(val("--baseline"))) as fh:
                base = json.load(fh)
        except Exception as e:
            print("!! cannot read baseline %s: %s" % (val("--baseline"), e))
            return 2
    r = audit(text, baseline_data=base, collected_at=collected, gap_overrides=gaps)
    print(json.dumps(_public(r), indent=2, default=str) if as_json else format_human(r))
    return _exit_for(r)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
