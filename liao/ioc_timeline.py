#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ioc_timeline.py  —  Liao incident-timeline assembler (Option B).

WHAT IT IS
  The piece that ties the Liao "eyes" together. It calls each feeder's real
  function on a case folder, normalizes every output into ONE event schema,
  sorts it into a single chronological incident timeline, groups events that
  share an EXACT indicator into per-actor threads, tags each event with an
  incident-response phase, and lists blind spots and missing feeders LOUDLY.
  It also verifies its own toolkit against an off-host trust anchor.

WHAT IT IS NOT
  Read-and-assemble only. No network action except optional reputation
  enrichment (--enrich) and whatever the feeders themselves already do. It
  NEVER executes anything it reads and makes NO containment decisions. Flags
  are leads to verify, not verdicts.

SCOPE
  OWNED ASSETS ONLY (your server + your phone). Most telemetry comes from the
  droplet itself, which a compromised host can lie about; NextDNS is the only
  off-host source. Treat a clean-looking timeline as "nothing surfaced from
  these vantages," never "you are safe."

HOUSE PATTERN
  ok-dicts {"ok": bool, ..., "error": str|None}; format_human(); --json;
  menu-return _console() (0 = Back). Empty/partial/failed input is reported
  loudly. A missing feeder is a missing reading, never an all-clear. Lowercase
  severities; flag dicts {code, severity, detail}.
  Exit codes: 0 clean · 1 something flagged · 2 error · 3 incomplete coverage.

INPUT
  A case folder (see CASE_FILES). Droplet: /opt/liao/cases/<id>/ ;
  phone: ~/Documents/liao_cases/<id>/ . manifest.json records host + collection
  time per file and which tool produced it. Each feeder's input or --json
  output lives in the folder. --assemble <dir> assembles an existing folder;
  --collect <id> (droplet) runs collectors+feeders then assembles;
  --init-case prints the manual commands.

TRUST ANCHOR (lives OFF the droplet — phone/iCloud)
  --make-anchor <out> : hash every file under --src (default /opt/liao) into
                        anchor_manifest.json and copy *baseline*.json aside.
                        Run once right after a known-good deploy, move off-host.
  --verify-anchor <anchor> : compare the droplet's CURRENT hashes (from
                        --hashes sha256sum-file, a --case folder's recorded
                        hashes, or a live --src walk) against the anchor. Any
                        mismatch / missing / extra file is a HIGH anchor_mismatch
                        event and the BLUF declares the toolkit UNTRUSTED.

Stdlib only (runs in Pythonista). No pandas.
"""

import sys
import os
import re
import io
import json
import glob
import time
import shutil
import hashlib
import subprocess
from datetime import datetime, timezone

VERSION = "1.0.0"
SCHEMA_VERSION = "ioc_timeline/1"

# Feeders are sibling modules in /opt/liao or Pythonista Documents. Import each
# defensively so a missing feeder degrades to "source_unavailable" rather than
# killing the assembler.
_FEEDERS = {}
for _name in ("fim", "dns_parser", "log_parser", "conn_inventory", "rep_lookup",
              "proc_inventory", "persistence_audit", "account_audit", "log_integrity"):
    try:
        _FEEDERS[_name] = __import__(_name)
    except Exception as _e:               # noqa: BLE001  (we WANT to swallow and record)
        _FEEDERS[_name] = None

# --------------------------------------------------------------------------- #
# severities, phases, lanes, confidence
# --------------------------------------------------------------------------- #

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEV_NAMES = ("high", "medium", "low", "info")

# event_time confidence: event > mtime > inherited > collection
TIME_CONF = {"event": 0, "mtime": 1, "inherited": 2, "collection": 3, None: 9}

# Incident-response phases, ordered for display. EDIT THIS TABLE to retune.
PHASES = ("entry", "execution", "persistence", "privilege",
          "defense_evasion", "c2", "exfil", "context")

# Paths that, if a file is ADDED there, mean persistence (fim autostart adds).
AUTOSTART_HINTS = (
    "/cron", "crontab", "/etc/cron", "systemd/system", "/etc/init.d",
    "/etc/rc.local", "/etc/profile.d", ".ssh/authorized_keys", "launchagents",
    "launchdaemons", "/.bashrc", "/.zshrc", "/.profile", "/.bash_profile",
    "/etc/ld.so.preload",
)

# Users too ubiquitous to be a meaningful merge key (would create false threads
# by lumping every root/service action together). EDITABLE; add --self-users.
COMMON_USERS = {
    "root", "www-data", "nginx", "apache", "apache2", "httpd", "daemon",
    "mysql", "postgres", "redis", "mongodb", "nobody", "systemd-network",
    "systemd-resolve", "messagebus", "syslog", "_apt", "sshd",
}

CASE_FILES = [
    # (filename,       feeder_key,      how)
    ("ps.txt",          "proc",          "raw"),
    ("persist.txt",     "persistence",   "raw"),
    ("accounts.txt",    "accounts",      "raw"),
    ("logint.json",     "logintegrity",  "json"),
    ("logint.txt",      "logintegrity",  "raw"),
    ("auth.log",        "authlog",       "raw"),
    ("access.log",      "weblog",        "raw"),
    ("netstat.txt",     "conn",          "raw"),
    ("dns.json",        "dns",           "json-or-raw"),
    # fim*.json handled separately (one per host)
]

FEEDER_MODULE = {
    "proc": "proc_inventory", "persistence": "persistence_audit",
    "accounts": "account_audit", "logintegrity": "log_integrity",
    "authlog": "log_parser", "weblog": "log_parser", "conn": "conn_inventory",
    "dns": "dns_parser", "fim": "fim",
}
# Every feeder we EXPECT a healthy droplet case to carry (for "missing feeder").
EXPECTED_FEEDERS = ["proc", "persistence", "accounts", "logintegrity",
                    "authlog", "conn", "dns", "fim"]

# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def _now():
    return datetime.now(timezone.utc).isoformat()


def _epoch(iso):
    """ISO8601 -> epoch float, or None. Used only for sorting / windows."""
    if not iso:
        return None
    s = iso.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        s2 = re.sub(r"\.\d+", "", s, count=1)
        try:
            return datetime.fromisoformat(s2).timestamp()
        except ValueError:
            return None


# Secrets must NEVER reach output, a case file, or a log (test 7). The feeders
# keep keys in the keychain/env and out of their results, but we scrub anyway.
_SECRET_PATTERNS = [
    (re.compile(r"https?://[^\s\"']*nextdns[^\s\"']*", re.I), "<redacted-nextdns-url>"),
    (re.compile(r"(?i)\b(api[-_]?key|apikey|token|key)\s*[=:]\s*[A-Za-z0-9/_\-\.]{12,}"),
     r"\1=<redacted>"),
    (re.compile(r"\b[A-Fa-f0-9]{32,64}\b(?=\?|&|$)"), "<redacted-token>"),
]


def _scrub(obj):
    """Recursively redact anything that looks like a secret URL/key."""
    if isinstance(obj, str):
        s = obj
        for pat, repl in _SECRET_PATTERNS:
            s = pat.sub(repl, s)
        return s
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


def _flag_fields(f):
    """Normalize any feeder's flag dict -> (code, severity_lower, detail).
    persistence_audit uses {name, severity(UPPER), note}; the rest use
    {code, severity(lower), detail}."""
    code = f.get("code") or f.get("name") or "flag"
    detail = f.get("detail") or f.get("note") or ""
    sev = (f.get("severity") or "").strip().lower() or "info"
    if sev not in SEV_ORDER:
        sev = "info"
    return code, sev, detail


def _read(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _load_json(path):
    t = _read(path)
    if t is None:
        return None, "unreadable"
    try:
        return json.loads(t), None
    except ValueError as e:
        return None, "bad_json: %s" % e


# --------------------------------------------------------------------------- #
# normalized event
# --------------------------------------------------------------------------- #

_ACTOR_KEYS = ("ip", "domain", "pid", "user", "uid", "group", "path", "unit",
               "fp", "boot_id")


def _mkevent(host, source, kind, severity, event_time, time_source, detail,
             actors, raw_ref, end_time=None):
    severity = (severity or "info").lower()
    if severity not in SEV_ORDER:
        severity = "info"
    a = {k: None for k in _ACTOR_KEYS}
    for k, v in (actors or {}).items():
        if k in a and v not in (None, "", "*"):
            a[k] = v
    ev = {
        "event_id": None,
        "host": host or "unknown-host",
        "source": source,
        "kind": kind,
        "severity": severity,
        "event_time": event_time,
        "time_source": time_source,
        "end_time": end_time,
        "actors": a,
        "phase": None,
        "detail": detail or "",
        "raw_ref": raw_ref,
    }
    seed = "%s|%s|%s|%s|%s|%s" % (host, source, kind, event_time, raw_ref, detail[:80])
    ev["event_id"] = hashlib.sha1(seed.encode("utf-8", "replace")).hexdigest()[:12]
    ev["phase"] = _classify_phase(ev, kind)
    return ev


def _in_autostart(path):
    p = (path or "").lower()
    return any(h in p for h in AUTOSTART_HINTS)


def _classify_phase(ev, code):
    """One editable mapping, source-first then code. First match wins."""
    src = ev["source"]
    if src == "trust_anchor" or code == "anchor_mismatch":
        return "defense_evasion"
    if src == "dns":
        return "c2"
    if src == "conn":
        # suspicious egress -> c2; plain public egress -> context.
        return "c2" if ev["severity"] in ("high", "medium") else "context"
    if src == "proc":
        if code == "deleted_executable":
            return "defense_evasion"
        return "execution"
    if src == "persistence":
        return "persistence"
    if src == "fim":
        if code == "fim_added" and _in_autostart(ev["actors"].get("path")):
            return "persistence"
        return "context"
    if src == "accounts":
        if code in ("last_login", "root_login_recorded"):
            return "entry"
        return "privilege"
    if src == "authlog":
        if code == "sudo":
            return "privilege"
        if code in ("login_failed", "brute_force", "login_accepted"):
            return "entry"
        return "context"
    if src == "log_integrity":
        evasion = {"log_wiped_or_empty", "log_symlinked", "history_redirected",
                   "history_empty", "journal_verify_failed", "logging_service_down",
                   "audit_disabled", "audit_lost_events", "log_truncated",
                   "log_replaced", "timestamp_regression"}
        if code in evasion:
            return "defense_evasion"
        return "context"
    return "context"


# --------------------------------------------------------------------------- #
# union-find for actor threads
# --------------------------------------------------------------------------- #

class _UF:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def _merge_keys(ev, self_users):
    """Exact indicators this event contributes to actor-threading.
    pid is scoped to (host, boot); path to host. Common/self users excluded."""
    a = ev["actors"]
    host = ev["host"]
    keys = []
    if a.get("ip"):
        keys.append(("ip", a["ip"]))
    if a.get("domain"):
        keys.append(("domain", a["domain"]))
    if a.get("fp"):
        keys.append(("fp", a["fp"]))
    if a.get("unit"):
        keys.append(("unit", host, a["unit"]))
    if a.get("path"):
        keys.append(("path", host, a["path"]))
    if a.get("user") and a["user"] not in self_users:
        keys.append(("user", a["user"]))
    if a.get("pid") is not None:
        boot = a.get("boot_id") or "<unknown-boot>"
        keys.append(("pid", host, boot, a["pid"]))
    return keys


# --------------------------------------------------------------------------- #
# source-unavailable record
# --------------------------------------------------------------------------- #

def _unavail(feeder, fname, reason):
    return {"feeder": feeder, "file": fname, "host": None, "contributed": False,
            "reason": reason, "events": 0}


# --------------------------------------------------------------------------- #
# per-feeder adapters  ->  (events, coverage_dict)
# Each runs inside try/except at the call site; here they may still return a
# coverage dict with contributed=False when the feeder said ok=False.
# --------------------------------------------------------------------------- #

def _adapt_proc(mod, path, host, coll, proc_index_out):
    res = mod.parse_ps_file(path)
    if not res.get("ok"):
        return [], {"feeder": "proc_inventory", "file": os.path.basename(path),
                    "host": host, "contributed": False,
                    "reason": res.get("error") or "ok=False", "events": 0}
    recs = res.get("records", [])
    proc_index_out["records"] = recs
    proc_index_out["index"] = mod.index_by_pid(recs)
    evs = []
    for r in recs:
        if not r.get("flags"):
            continue
        code, sev, detail = _flag_fields(r["flags"][0])
        det = "%s (pid %s, %s) — %s" % (r.get("exe_base") or "?", r["pid"],
                                        r.get("user"), detail)
        if r.get("ancestry_str"):
            det += " | tree: " + r["ancestry_str"]
        evs.append(_mkevent(host, "proc", code, sev, r.get("event_time"),
                            r.get("time_source"), det,
                            {"pid": r["pid"], "user": r.get("user"),
                             "path": r.get("exe")},
                            "ps.txt#pid%s" % r["pid"]))
    return evs, {"feeder": "proc_inventory", "file": os.path.basename(path),
                 "host": host, "contributed": True, "reason": None,
                 "events": len(evs), "records": len(recs),
                 "parse_errors": len(res.get("parse_errors") or [])}


def _adapt_conn(mod, path, host, coll, proc_index):
    text = _read(path)
    if text is None:
        return [], _unavail("conn_inventory", os.path.basename(path), "unreadable")
    res = mod.take_inventory(source="text", netstat_text=text)
    if not res.get("ok"):
        return [], {"feeder": "conn_inventory", "file": os.path.basename(path),
                    "host": host, "contributed": False,
                    "reason": res.get("error") or res.get("note"), "events": 0}
    # snapshot time: prefer the manifest's collection time over "now".
    snap = coll or res.get("collected_at")
    index = (proc_index or {}).get("index") or {}
    evs = []
    flagged_ids = set()
    for c in res.get("flagged", []):
        reasons = "; ".join(c.get("reasons", []))
        pid = c.get("pid")
        actors = {"ip": c.get("remote_addr"), "pid": pid}
        det = "%s %s:%s [%s] %s" % (c.get("proto"), c.get("remote_addr"),
                                    c.get("remote_port"), c.get("state") or "?", reasons)
        proc = index.get(pid) if pid is not None else None
        if proc:
            det += " | owner: %s" % (proc.get("ancestry_str") or proc.get("exe_base"))
            actors["user"] = proc.get("user")
            actors["path"] = proc.get("exe")
        ev = _mkevent(host, "conn", "suspicious_egress", "medium", snap,
                     "collection", det, actors,
                     "netstat.txt#%s:%s" % (c.get("remote_addr"), c.get("remote_port")))
        evs.append(ev)
        flagged_ids.add((c.get("remote_addr"), c.get("remote_port")))
    # plain public egress (context, state lane) — only the ones not already flagged
    for c in res.get("egress", []):
        key = (c.get("remote_addr"), c.get("remote_port"))
        if key in flagged_ids:
            continue
        pid = c.get("pid")
        actors = {"ip": c.get("remote_addr"), "pid": pid}
        det = "%s %s:%s [%s]" % (c.get("proto"), c.get("remote_addr"),
                                 c.get("remote_port"), c.get("state") or "?")
        proc = index.get(pid) if pid is not None else None
        if proc:
            det += " | owner: %s" % (proc.get("ancestry_str") or proc.get("exe_base"))
            actors["user"] = proc.get("user")
            actors["path"] = proc.get("exe")
        evs.append(_mkevent(host, "conn", "public_egress", "info", snap,
                            "collection", det, actors,
                            "netstat.txt#%s:%s" % key))
    return evs, {"feeder": "conn_inventory", "file": os.path.basename(path),
                 "host": host, "contributed": True, "reason": None,
                 "events": len(evs), "trusted_vantage": res.get("source_trusted")}


def _adapt_persistence(mod, path, host, coll):
    text = _read(path)
    if text is None:
        return [], _unavail("persistence_audit", os.path.basename(path), "unreadable")
    res = mod.audit(text, collected_at=coll)
    if not res.get("ok"):
        return [], {"feeder": "persistence_audit", "file": os.path.basename(path),
                    "host": host, "contributed": False,
                    "reason": res.get("error"), "events": 0}
    evs = []
    for r in res.get("flagged", []):
        code, sev, detail = _flag_fields(r["flags"][0])
        actors = {"path": r.get("path"), "unit": r.get("unit"),
                  "user": r.get("user") or r.get("owner"), "fp": r.get("fp")}
        tgt = r.get("unit") or r.get("path") or ("crontab:" + (r.get("user") or ""))
        evs.append(_mkevent(host, "persistence", code, sev, r.get("event_time"),
                            r.get("time_source"), "%s — %s" % (tgt, detail),
                            actors, "persist.txt#%s" % r.get("entry_id")))
    cov = {"feeder": "persistence_audit", "file": os.path.basename(path),
           "host": host, "contributed": True, "reason": None, "events": len(evs),
           "incomplete": not res.get("complete")}
    if res.get("sections_missing"):
        cov["sections_missing"] = res["sections_missing"]
    return evs, cov


def _adapt_accounts(mod, path, host, coll):
    text = _read(path)
    if text is None:
        return [], _unavail("account_audit", os.path.basename(path), "unreadable")
    res = mod.audit(text, collected_at=coll)
    if not res.get("ok"):
        return [], {"feeder": "account_audit", "file": os.path.basename(path),
                    "host": host, "contributed": False,
                    "reason": res.get("error"), "events": 0}
    rhost = res.get("host") or host
    evs = []
    for f in res.get("flagged", []) + res.get("info", []):
        code = f.get("code")
        sev = (f.get("severity") or "info").lower()
        actors = {"user": f.get("user"), "uid": f.get("uid"),
                  "group": f.get("group"), "path": f.get("path")}
        tgt = f.get("user") or f.get("group") or f.get("path") or f.get("key")
        evs.append(_mkevent(rhost, "accounts", code, sev, f.get("event_time"),
                            f.get("time_source"), "%s — %s" % (tgt, f.get("detail")),
                            actors, "accounts.txt#%s" % f.get("key")))
    # last-login events (context/entry) carry a real event_time
    for r in res.get("records", []):
        if r.get("kind") == "last_login" and r.get("event_time"):
            actors = {"user": r.get("user"), "uid": r.get("uid"),
                      "ip": (r.get("data") or {}).get("from")}
            evs.append(_mkevent(rhost, "accounts", "last_login", "info",
                                r["event_time"], r.get("time_source"),
                                "%s last login: %s" % (r.get("user"), r.get("content")),
                                actors, "accounts.txt#%s" % r.get("key")))
    cov = {"feeder": "account_audit", "file": os.path.basename(path),
           "host": rhost, "contributed": True, "reason": None, "events": len(evs),
           "incomplete": not res.get("vantage_ok")}
    if res.get("sections_missing"):
        cov["sections_missing"] = res["sections_missing"]
    if res.get("problems"):
        cov["problems"] = res["problems"]
    return evs, cov


def _consume_logint_result(res, host):
    """Shared by logint.json (loaded) and logint.txt (freshly audited).
    Returns (events, blind_spots)."""
    rhost = res.get("host") or host
    evs, blinds = [], []
    for r in res.get("records", []):
        kind = r.get("kind")
        flags = r.get("flags") or []
        if flags:
            code, sev, detail = _flag_fields(flags[0])
        else:
            code, sev, detail = (kind, "info", r.get("content") or "")
        if code == "log_gap":
            blinds.append({"host": rhost, "start": r.get("event_time"),
                           "end": r.get("gap_end"),
                           "seconds": r.get("gap_seconds"), "detail": detail})
            continue
        if not r.get("event_time"):
            continue
        actors = {"path": r.get("path"), "unit": r.get("unit"),
                  "boot_id": r.get("boot_id")}
        src_kind = code if flags else kind
        evs.append(_mkevent(rhost, "log_integrity", src_kind, sev,
                            r.get("event_time"), r.get("time_source"),
                            detail, actors,
                            "logint#%s" % (r.get("key") or r.get("entry_id"))))
    # flagged items that weren't full records (e.g. flattened-only) — belt & braces
    seen = {e["raw_ref"] for e in evs}
    for f in res.get("flagged", []):
        if f.get("code") == "log_gap":
            win = {"host": rhost, "start": f.get("event_time"),
                   "end": f.get("gap_end"), "seconds": f.get("gap_seconds"),
                   "detail": f.get("detail")}
            if win not in blinds:
                blinds.append(win)
            continue
        ref = "logint#%s" % f.get("key")
        if ref in seen or not f.get("event_time"):
            continue
        actors = {"path": f.get("path"), "unit": f.get("unit"),
                  "boot_id": f.get("boot_id")}
        evs.append(_mkevent(rhost, "log_integrity", f.get("code"),
                            (f.get("severity") or "info").lower(),
                            f.get("event_time"), f.get("time_source"),
                            f.get("detail"), actors, ref))
    return evs, blinds


def _adapt_logint_json(path, host):
    res, err = _load_json(path)
    if err:
        return [], [], _unavail("log_integrity", os.path.basename(path), err)
    if not isinstance(res, dict) or not res.get("ok", True):
        return [], [], {"feeder": "log_integrity", "file": os.path.basename(path),
                        "host": host, "contributed": False,
                        "reason": (res or {}).get("error") or "not an ok result",
                        "events": 0}
    evs, blinds = _consume_logint_result(res, host)
    return evs, blinds, {"feeder": "log_integrity", "file": os.path.basename(path),
                         "host": res.get("host") or host, "contributed": True,
                         "reason": None, "events": len(evs),
                         "blind_spots": len(blinds),
                         "incomplete": not res.get("vantage_ok", True)}


def _adapt_logint_raw(mod, path, host, coll):
    text = _read(path)
    if text is None:
        return [], [], _unavail("log_integrity", os.path.basename(path), "unreadable")
    res = mod.audit(text, collected_at=coll)
    if not res.get("ok"):
        return [], [], {"feeder": "log_integrity", "file": os.path.basename(path),
                        "host": host, "contributed": False,
                        "reason": res.get("error"), "events": 0}
    evs, blinds = _consume_logint_result(res, host)
    return evs, blinds, {"feeder": "log_integrity", "file": os.path.basename(path),
                         "host": res.get("host") or host, "contributed": True,
                         "reason": None, "events": len(evs),
                         "blind_spots": len(blinds),
                         "incomplete": not res.get("vantage_ok", True)}


def _adapt_authlog(mod, path, host, coll):
    text = _read(path)
    if text is None:
        return [], _unavail("log_parser", os.path.basename(path), "unreadable")
    res = mod.analyze_auth(text)
    if not res.get("ok"):
        return [], {"feeder": "log_parser(auth)", "file": os.path.basename(path),
                    "host": host, "contributed": False,
                    "reason": res.get("error") or res.get("summary"), "events": 0}
    evs = []
    for f in res.get("findings", []):
        evs.append(_mkevent(host, "authlog", "brute_force", "high",
                            f.get("event_time"), f.get("time_source"),
                            "%s — %s" % (f.get("ip"), f.get("detail")),
                            {"ip": f.get("ip")}, "auth.log#bf:%s" % f.get("ip")))
    for i, e in enumerate(res.get("events", [])):
        if not e.get("event_time"):
            continue
        # sshd pid is NOT an attacker indicator -> do not thread on it.
        actors = {"ip": e.get("ip"), "user": e.get("user")}
        evs.append(_mkevent(host, "authlog", e.get("type"),
                            (e.get("severity") or "info").lower(),
                            e.get("event_time"), e.get("time_source"),
                            e.get("detail"), actors, "auth.log#ev%d" % i))
    return evs, {"feeder": "log_parser(auth)", "file": os.path.basename(path),
                 "host": host, "contributed": True, "reason": None,
                 "events": len(evs), "parsed": res.get("lines_parsed")}


def _adapt_weblog(mod, path, host, coll):
    text = _read(path)
    if text is None:
        return [], _unavail("log_parser", os.path.basename(path), "unreadable")
    res = mod.analyze(text)
    if not res.get("ok"):
        return [], {"feeder": "log_parser(web)", "file": os.path.basename(path),
                    "host": host, "contributed": False,
                    "reason": res.get("error") or res.get("summary"), "events": 0}
    evs = []
    for f in res.get("findings", []):
        code = f.get("type")
        # sensitive-path probe / brute force are entry; keep feeder=authlog-ish?
        # Use source 'authlog' phase rules by mapping brute_force; else web->entry.
        sev = (f.get("severity") or "info").lower()
        ev = _mkevent(host, "authlog", "brute_force" if code == "brute_force" else "login_failed",
                      sev, f.get("event_time"), f.get("time_source"),
                      "%s — %s" % (f.get("ip") or "(site)", f.get("detail")),
                      {"ip": f.get("ip")}, "access.log#%s:%s" % (code, f.get("ip")))
        evs.append(ev)
    return evs, {"feeder": "log_parser(web)", "file": os.path.basename(path),
                 "host": host, "contributed": True, "reason": None,
                 "events": len(evs), "parsed": res.get("lines_parsed")}


def _adapt_dns(mod, path, host, coll):
    text = _read(path)
    if text is None:
        return [], _unavail("dns_parser", os.path.basename(path), "unreadable")
    # dns.json may already be a dns_parser result, or raw NextDNS CSV/JSON.
    try:
        obj = json.loads(text)
    except ValueError:
        obj = None
    if isinstance(obj, dict) and "findings" in obj and "analyzed_at" in obj:
        res = obj
    else:
        res = mod.analyze_text(text)
    if not res.get("ok"):
        return [], {"feeder": "dns_parser", "file": os.path.basename(path),
                    "host": host, "contributed": False,
                    "reason": res.get("error") or res.get("summary"), "events": 0}
    evs = []
    for f in res.get("findings", []):
        det = "%s — %s" % (f.get("type"), f.get("detail"))
        cips = f.get("client_ips") or []
        if cips:
            det += " | clients: %s" % ", ".join(cips)
        evs.append(_mkevent(host, "dns", f.get("type"),
                            (f.get("severity") or "info").lower(),
                            f.get("event_time"), f.get("time_source") or "event",
                            det, {"domain": f.get("domain")},
                            "dns#%s:%s" % (f.get("type"), f.get("domain"))))
    return evs, {"feeder": "dns_parser(NextDNS, off-host)", "file": os.path.basename(path),
                 "host": host, "contributed": True, "reason": None,
                 "events": len(evs), "queries": res.get("rows_parsed")}


def _adapt_fim(mod, path, host):
    res, err = _load_json(path)
    if err:
        return [], _unavail("fim", os.path.basename(path), err)
    if not isinstance(res, dict) or not res.get("ok", True):
        return [], {"feeder": "fim", "file": os.path.basename(path), "host": host,
                    "contributed": False,
                    "reason": (res or {}).get("error") or "not an ok compare", "events": 0}
    evs = []
    for m in res.get("modified", []):
        evs.append(_mkevent(host, "fim", "fim_modified", "high",
                            m.get("event_time"), m.get("time_source") or "mtime",
                            "modified %s (%s -> %s)" % (m.get("path"),
                             m.get("old_hash"), m.get("new_hash")),
                            {"path": m.get("path")}, "fim#mod:%s" % m.get("path")))
    for a in res.get("added", []):
        sev = "high" if _in_autostart(a.get("path")) else "medium"
        evs.append(_mkevent(host, "fim", "fim_added", sev,
                            a.get("event_time"), a.get("time_source") or "mtime",
                            "added %s" % a.get("path"),
                            {"path": a.get("path")}, "fim#add:%s" % a.get("path")))
    for d in res.get("deleted", []):
        # deleted -> no reliable change time -> untimed on purpose.
        evs.append(_mkevent(host, "fim", "fim_deleted", "high",
                            d.get("event_time"), d.get("time_source"),
                            "deleted/unreadable %s" % d.get("path"),
                            {"path": d.get("path")}, "fim#del:%s" % d.get("path")))
    return evs, {"feeder": "fim", "file": os.path.basename(path), "host": host,
                 "contributed": True, "reason": None, "events": len(evs)}


# --------------------------------------------------------------------------- #
# trust anchor
# --------------------------------------------------------------------------- #

def _sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def make_anchor(out_dir, src="/opt/liao"):
    """Hash every file under src and copy baselines aside. Run once after a
    known-good deploy, then MOVE out_dir off the droplet."""
    src = os.path.expanduser(src)
    out_dir = os.path.expanduser(out_dir)
    if not os.path.isdir(src):
        return {"ok": False, "error": "src not a directory: %s" % src}
    files = {}
    for root, _dirs, names in os.walk(src):
        for n in names:
            full = os.path.join(root, n)
            rel = os.path.relpath(full, src)
            dg = _sha256_file(full)
            if dg is not None:
                files[rel] = dg
    try:
        os.makedirs(out_dir, exist_ok=True)
        bdir = os.path.join(out_dir, "baselines")
        os.makedirs(bdir, exist_ok=True)
        copied = []
        for rel in files:
            if "baseline" in rel.lower() and rel.lower().endswith(".json"):
                shutil.copy2(os.path.join(src, rel),
                             os.path.join(bdir, os.path.basename(rel)))
                copied.append(os.path.basename(rel))
        manifest = {"created": _now(), "src": src, "algo": "sha256",
                    "file_count": len(files), "files": files, "baselines": copied}
        with open(os.path.join(out_dir, "anchor_manifest.json"), "w") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
    except OSError as e:
        return {"ok": False, "error": "write failed: %s" % e}
    return {"ok": True, "out_dir": out_dir, "src": src, "file_count": len(files),
            "baselines_copied": copied,
            "reminder": "MOVE this anchor OFF the droplet now (phone/iCloud). An "
                        "anchor the host can rewrite proves nothing."}


def _hashes_from_sha256sum(text):
    out = {}
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        m = re.match(r"^([A-Fa-f0-9]{64})\s+[\*]?(.+)$", ln)
        if m:
            out[m.group(2).strip()] = m.group(1).lower()
    return out


def verify_anchor(anchor_dir, current=None, hashes_file=None, case_dir=None,
                  src=None):
    """Compare current /opt/liao hashes against the anchor. 'current' may be a
    dict {path: sha256}; else drawn from hashes_file, case_dir (recorded
    droplet_hashes / liao_hashes.txt), or a live walk of src."""
    anchor_dir = os.path.expanduser(anchor_dir)
    man, err = _load_json(os.path.join(anchor_dir, "anchor_manifest.json"))
    if err or not isinstance(man, dict):
        return {"ok": False, "error": "cannot read anchor_manifest.json (%s)" % err}
    anchor = man.get("files", {})

    if current is None:
        if hashes_file:
            current = _hashes_from_sha256sum(_read(hashes_file) or "")
        elif case_dir:
            mpath = os.path.join(case_dir, "manifest.json")
            mani, _ = _load_json(mpath)
            if isinstance(mani, dict) and mani.get("droplet_hashes"):
                current = dict(mani["droplet_hashes"])
            else:
                hf = os.path.join(case_dir, "liao_hashes.txt")
                current = _hashes_from_sha256sum(_read(hf) or "")
        elif src and os.path.isdir(os.path.expanduser(src)):
            src = os.path.expanduser(src)
            current = {}
            for root, _d, names in os.walk(src):
                for n in names:
                    full = os.path.join(root, n)
                    current[os.path.relpath(full, src)] = _sha256_file(full)
    if not current:
        return {"ok": False,
                "error": "no current hashes to compare (pass --hashes / --case / --src)"}

    # Match by basename so a flat `sha256sum /opt/liao/*` lines up with rel paths.
    def base(d):
        return {os.path.basename(k): v for k, v in d.items()}
    a_base, c_base = base(anchor), base(current)
    mismatched, missing, extra = [], [], []
    for name, dg in sorted(a_base.items()):
        if name not in c_base:
            missing.append(name)
        elif c_base[name] != dg:
            mismatched.append(name)
    for name in sorted(c_base):
        if name not in a_base:
            extra.append(name)
    status = "verified" if not (mismatched or missing or extra) else "MISMATCH"
    return {"ok": True, "status": status, "anchor_created": man.get("created"),
            "anchor_files": len(anchor), "current_files": len(current),
            "mismatched": mismatched, "missing": missing, "extra": extra}


def _anchor_events(anchor_res, host, when):
    """Turn a verify_anchor result into HIGH anchor_mismatch timeline events."""
    evs = []
    if not anchor_res or not anchor_res.get("ok"):
        return evs
    for name in anchor_res.get("mismatched", []):
        evs.append(_mkevent(host, "trust_anchor", "anchor_mismatch", "high",
                            when, "collection",
                            "TOOLKIT FILE CHANGED vs anchor: %s" % name,
                            {"path": name}, "anchor#mod:%s" % name))
    for name in anchor_res.get("missing", []):
        evs.append(_mkevent(host, "trust_anchor", "anchor_mismatch", "high",
                            when, "collection",
                            "TOOLKIT FILE MISSING vs anchor: %s" % name,
                            {"path": name}, "anchor#miss:%s" % name))
    for name in anchor_res.get("extra", []):
        evs.append(_mkevent(host, "trust_anchor", "anchor_mismatch", "high",
                            when, "collection",
                            "EXTRA FILE in /opt/liao not in anchor: %s" % name,
                            {"path": name}, "anchor#extra:%s" % name))
    return evs


# --------------------------------------------------------------------------- #
# assemble
# --------------------------------------------------------------------------- #

def _load_manifest(case_dir):
    m, _ = _load_json(os.path.join(case_dir, "manifest.json"))
    return m if isinstance(m, dict) else {}


def _file_host(manifest, default_host, fname):
    f = (manifest.get("files") or {}).get(fname) or {}
    return f.get("host") or default_host


def _file_coll(manifest, default_coll, fname):
    f = (manifest.get("files") or {}).get(fname) or {}
    return f.get("collected_at") or default_coll


def assemble(case_dir, since=None, until=None, enrich=False, anchor_dir=None,
             self_users=None, resolutions=None):
    case_dir = os.path.expanduser(case_dir)
    if not os.path.isdir(case_dir):
        return {"ok": False, "error": "case folder not found: %s" % case_dir}

    manifest = _load_manifest(case_dir)
    default_host = manifest.get("host") or (os.uname().nodename if hasattr(os, "uname") else "unknown-host")
    default_coll = manifest.get("collected_at")
    # Only truly ubiquitous users (root/service) are excluded from user-threading.
    # A named interactive user (e.g. liao) stays mergeable: if that account is the
    # pivot of a compromise, user=liao is exactly the indicator that catches it.
    self_users = set(COMMON_USERS) | set(self_users or [])

    # resolutions (domain -> [ips]) for possible-same-actor links
    resmap = dict(resolutions or {})
    rfile, _ = _load_json(os.path.join(case_dir, "resolutions.json"))
    if isinstance(rfile, dict):
        for d, ips in rfile.items():
            resmap.setdefault(d, [])
            resmap[d] += [ips] if isinstance(ips, str) else list(ips)
    for d, ips in (manifest.get("resolutions") or {}).items():
        resmap.setdefault(d, [])
        resmap[d] += [ips] if isinstance(ips, str) else list(ips)

    events, coverage, blind_spots = [], [], []
    proc_index = {}

    def run(feeder_mod_name, fn, *a):
        """Isolate every adapter: exception -> source_unavailable, assembly goes on."""
        mod = _FEEDERS.get(feeder_mod_name)
        if mod is None:
            return None, _unavail(feeder_mod_name, "-", "feeder module not importable")
        try:
            return fn(mod, *a), None
        except Exception as e:  # noqa: BLE001
            return None, _unavail(feeder_mod_name, a[0] if a else "-",
                                  "exception: %s" % e)

    present = {f for f in os.listdir(case_dir)}

    # proc first (conn joins to it)
    if "ps.txt" in present:
        p = os.path.join(case_dir, "ps.txt")
        host = _file_host(manifest, default_host, "ps.txt")
        out, un = run("proc_inventory", lambda m, pp, hh, cc, idx: _adapt_proc(m, pp, hh, cc, idx),
                      p, host, _file_coll(manifest, default_coll, "ps.txt"), proc_index)
        if un:
            coverage.append(un)
        else:
            evs, cov = out
            events += evs
            coverage.append(cov)
    else:
        coverage.append(_unavail("proc_inventory", "ps.txt", "file absent"))

    if "netstat.txt" in present:
        p = os.path.join(case_dir, "netstat.txt")
        host = _file_host(manifest, default_host, "netstat.txt")
        out, un = run("conn_inventory", lambda m, pp, hh, cc, idx: _adapt_conn(m, pp, hh, cc, idx),
                      p, host, _file_coll(manifest, default_coll, "netstat.txt"), proc_index)
        if un:
            coverage.append(un)
        else:
            evs, cov = out
            events += evs
            coverage.append(cov)
    else:
        coverage.append(_unavail("conn_inventory", "netstat.txt", "file absent"))

    def simple(fname, feeder_mod, adapter, json_blind=False):
        if fname not in present:
            coverage.append(_unavail(feeder_mod, fname, "file absent"))
            return
        p = os.path.join(case_dir, fname)
        host = _file_host(manifest, default_host, fname)
        coll = _file_coll(manifest, default_coll, fname)
        mod = _FEEDERS.get(feeder_mod)
        if mod is None and adapter is not _adapt_fim and adapter is not _adapt_logint_json:
            coverage.append(_unavail(feeder_mod, fname, "feeder module not importable"))
            return
        try:
            if adapter is _adapt_fim:
                evs, cov = _adapt_fim(mod, p, host)
            elif adapter is _adapt_logint_json:
                evs, blinds, cov = _adapt_logint_json(p, host)
                blind_spots.extend(blinds)
            elif adapter is _adapt_logint_raw:
                evs, blinds, cov = _adapt_logint_raw(mod, p, host, coll)
                blind_spots.extend(blinds)
            else:
                evs, cov = adapter(mod, p, host, coll)
        except Exception as e:  # noqa: BLE001
            coverage.append(_unavail(feeder_mod, fname, "exception: %s" % e))
            return
        events.extend(evs)
        coverage.append(cov)

    simple("persist.txt", "persistence_audit", _adapt_persistence)
    simple("accounts.txt", "account_audit", _adapt_accounts)
    # log integrity: prefer precomputed JSON, else raw dump
    if "logint.json" in present:
        simple("logint.json", "log_integrity", _adapt_logint_json)
    elif "logint.txt" in present:
        simple("logint.txt", "log_integrity", _adapt_logint_raw)
    else:
        coverage.append(_unavail("log_integrity", "logint.json", "file absent"))
    simple("auth.log", "log_parser", _adapt_authlog)
    if "access.log" in present:
        simple("access.log", "log_parser", _adapt_weblog)
    simple("dns.json", "dns_parser", _adapt_dns)

    # fim: one or more host-tagged files
    fim_files = sorted(f for f in present if re.match(r"^fim.*\.json$", f))
    if not fim_files:
        coverage.append(_unavail("fim", "fim.json", "file absent"))
    for ff in fim_files:
        host = _file_host(manifest, default_host, ff)
        mod = _FEEDERS.get("fim")
        try:
            evs, cov = _adapt_fim(mod, os.path.join(case_dir, ff), host)
        except Exception as e:  # noqa: BLE001
            coverage.append(_unavail("fim", ff, "exception: %s" % e))
            continue
        events.extend(evs)
        coverage.append(cov)

    # trust anchor (optional): fold HIGH anchor_mismatch events in
    anchor = None
    if anchor_dir:
        anchor = verify_anchor(anchor_dir, case_dir=case_dir)
        if anchor.get("ok"):
            events += _anchor_events(anchor, default_host, default_coll or _now())

    # optional reputation enrichment (off by default; paced inside rep_lookup)
    enrich_info = None
    if enrich:
        enrich_info = _enrich(events)

    # since/until window filter (keeps untimed records)
    if since or until:
        s = _epoch(since) if since else None
        u = _epoch(until) if until else None

        def keep(ev):
            t = _epoch(ev["event_time"])
            if t is None:
                return True
            if s is not None and t < s:
                return False
            if u is not None and t > u:
                return False
            return True
        events = [e for e in events if keep(e)]

    # ---- lanes ----
    timeline, state_lane, untimed = [], [], []
    for ev in events:
        if ev["source"] == "trust_anchor":
            timeline.append(ev)            # anchor_mismatch always on the timeline
        elif ev["event_time"] is None:
            untimed.append(ev)
        elif ev["time_source"] == "collection":
            state_lane.append(ev)
        else:
            timeline.append(ev)

    timeline.sort(key=lambda e: (_epoch(e["event_time"]) or 0,
                                 TIME_CONF.get(e["time_source"], 9),
                                 SEV_ORDER.get(e["severity"], 9)))
    state_lane.sort(key=lambda e: (_epoch(e["event_time"]) or 0))
    untimed.sort(key=lambda e: (SEV_ORDER.get(e["severity"], 9), e["source"]))

    # ---- correlation (union-find over ALL events) ----
    all_ev = timeline + state_lane + untimed
    idx = {e["event_id"]: i for i, e in enumerate(all_ev)}
    uf = _UF(len(all_ev))
    keymap = {}
    for i, ev in enumerate(all_ev):
        for k in _merge_keys(ev, self_users):
            if k in keymap:
                uf.union(keymap[k], i)
            else:
                keymap[k] = i
    comps = {}
    for i, ev in enumerate(all_ev):
        comps.setdefault(uf.find(i), []).append(i)

    threads = []
    for root, members in comps.items():
        if len(members) < 2:
            continue
        evs = [all_ev[i] for i in members]
        evs.sort(key=lambda e: (_epoch(e["event_time"]) or float("inf")))
        # shared indicators: any merge-key held by >=2 members
        counts = {}
        for e in evs:
            for k in _merge_keys(e, self_users):
                counts[k] = counts.get(k, 0) + 1
        shared = [list(k) for k, c in counts.items() if c >= 2]
        max_sev = min(SEV_ORDER.get(e["severity"], 9) for e in evs)
        threads.append({
            "thread_id": hashlib.sha1(("|".join(sorted(e["event_id"] for e in evs))
                                       ).encode()).hexdigest()[:10],
            "events": [e["event_id"] for e in evs],
            "event_count": len(evs),
            "hosts": sorted({e["host"] for e in evs}),
            "sources": sorted({e["source"] for e in evs}),
            "phases": [p for p in PHASES if any(e["phase"] == p for e in evs)],
            "max_severity": SEV_NAMES[max_sev] if max_sev < 4 else "info",
            "shared_indicators": shared,
            "first": evs[0]["event_time"],
            "last": evs[-1]["event_time"],
            "detail_head": evs[0]["detail"][:100],
        })
    threads.sort(key=lambda t: (SEV_ORDER.get(t["max_severity"], 9),
                                -t["event_count"]))

    # ---- possible-same-actor (suspected links, NEVER merged) ----
    possible = []
    # domain <-> resolved IP
    dom_events = [e for e in all_ev if e["actors"].get("domain")]
    ip_events = [e for e in all_ev if e["actors"].get("ip")]
    seen_pl = set()
    for de in dom_events:
        dom = de["actors"]["domain"]
        for ip in resmap.get(dom, []):
            for ie in ip_events:
                if ie["actors"]["ip"] != ip:
                    continue
                if uf.find(idx[de["event_id"]]) == uf.find(idx[ie["event_id"]]):
                    continue  # already the same thread by some exact key
                key = ("dns_ip", dom, ip)
                if key in seen_pl:
                    continue
                seen_pl.add(key)
                possible.append({
                    "kind": "domain_resolves_to_ip",
                    "a": {"domain": dom, "event": de["event_id"]},
                    "b": {"ip": ip, "event": ie["event_id"]},
                    "reason": "resolution says %s -> %s; no shared exact indicator "
                              "— confirm before merging" % (dom, ip)})
    # pid reused across reboots (same host+pid, different KNOWN boot)
    by_pid = {}
    for e in all_ev:
        pid = e["actors"].get("pid")
        if pid is None:
            continue
        by_pid.setdefault((e["host"], pid), []).append(e)
    for (host, pid), group in by_pid.items():
        boots = {e["actors"].get("boot_id") for e in group if e["actors"].get("boot_id")}
        if len(boots) >= 2:
            possible.append({
                "kind": "pid_reused_across_boot",
                "a": {"host": host, "pid": pid},
                "b": {"boots": sorted(boots)},
                "reason": "pid %s seen under %d different boots on %s — same number "
                          "is not the same process across a reboot; confirm"
                          % (pid, len(boots), host)})

    # ---- coverage / missing feeders ----
    contributed = {c["feeder"].split("(")[0] for c in coverage if c.get("contributed")}
    missing_feeders = []
    for fk in EXPECTED_FEEDERS:
        modname = {"proc": "proc_inventory", "persistence": "persistence_audit",
                   "accounts": "account_audit", "logintegrity": "log_integrity",
                   "authlog": "log_parser", "conn": "conn_inventory",
                   "dns": "dns_parser", "fim": "fim"}[fk]
        ok = any(c.get("contributed") and c["feeder"].startswith(
            {"logintegrity": "log_integrity", "authlog": "log_parser",
             "proc": "proc_inventory", "persistence": "persistence_audit",
             "accounts": "account_audit", "conn": "conn_inventory",
             "dns": "dns_parser", "fim": "fim"}[fk]) for c in coverage)
        if not ok:
            missing_feeders.append(modname)

    # clock-sync warning
    clock_warning = None
    td = manifest.get("timedatectl") or ""
    if manifest.get("clock_synced") is False or \
       re.search(r"(?i)system clock synchronized:\s*no", td) or \
       re.search(r"(?i)NTP service:\s*inactive", td):
        clock_warning = ("droplet clock may NOT be synchronized (timedatectl in "
                         "manifest) — event_time ordering could be off")

    # ---- severity roll-up + BLUF ----
    sev_counts = {s: 0 for s in SEV_NAMES}
    for e in all_ev:
        sev_counts[e["severity"]] = sev_counts.get(e["severity"], 0) + 1
    ranked = sorted(all_ev, key=lambda e: (SEV_ORDER.get(e["severity"], 9),
                                           -(_epoch(e["event_time"]) or 0)))
    most_urgent = None
    for e in ranked:
        if e["severity"] in ("high", "medium"):
            most_urgent = e
            break
    highest = min([SEV_ORDER.get(e["severity"], 9) for e in all_ev] + [9])
    highest_sev = SEV_NAMES[highest] if highest < 4 else "none"

    anchor_status = "not checked"
    if anchor and anchor.get("ok"):
        anchor_status = anchor["status"]
    elif anchor and not anchor.get("ok"):
        anchor_status = "ERROR: %s" % anchor.get("error")

    untrusted = bool(anchor and anchor.get("ok") and anchor["status"] != "verified")
    bluf_bits = []
    if untrusted:
        bluf_bits.append("TOOLKIT UNTRUSTED — anchor mismatch; resolve before "
                         "trusting any finding below")
    bluf_bits.append("highest severity: %s" % highest_sev)
    bluf_bits.append("%d actor thread(s)" % len(threads))
    if most_urgent:
        bluf_bits.append("most urgent: [%s] %s/%s %s" % (
            most_urgent["severity"], most_urgent["host"], most_urgent["source"],
            most_urgent["detail"][:70]))
    bluf_bits.append("anchor: %s" % anchor_status)
    if missing_feeders:
        bluf_bits.append("INCOMPLETE COVERAGE: missing %s" % ", ".join(missing_feeders))
    if clock_warning:
        bluf_bits.append("CLOCK UNSYNCED")
    bluf = " | ".join(bluf_bits)

    incomplete = bool(missing_feeders) or any(
        c.get("incomplete") for c in coverage) or clock_warning is not None or \
        any(not c.get("contributed") for c in coverage if c["feeder"].split("(")[0]
            in [m for m in EXPECTED_FEEDERS])

    result = {
        "ok": True, "error": None, "schema": SCHEMA_VERSION, "version": VERSION,
        "case_dir": case_dir, "hosts": sorted({e["host"] for e in all_ev}) or [default_host],
        "collected_at": default_coll, "assembled_at": _now(),
        "bluf": bluf, "highest_severity": highest_sev, "thread_count": len(threads),
        "most_urgent": (most_urgent["event_id"] if most_urgent else None),
        "severity_counts": sev_counts,
        "coverage": coverage, "missing_feeders": missing_feeders,
        "clock_warning": clock_warning,
        "blind_spots": blind_spots,
        "timeline": timeline, "state_lane": state_lane, "untimed": untimed,
        "threads": threads, "possible_links": possible,
        "anchor": anchor, "anchor_status": anchor_status, "toolkit_untrusted": untrusted,
        "enrichment": enrich_info,
        "incomplete_coverage": incomplete,
        "telemetry_note": ("Most telemetry comes from the droplet itself, which a "
                           "compromised host can lie about. NextDNS is the only "
                           "off-host source. Not an all-clear."),
    }
    return _scrub(result)


def _enrich(events):
    """Reputation enrichment for HIGH/MEDIUM ip/domain actors (opt-in).
    Hits external APIs via rep_lookup, which paces for VT's 4/min free tier.
    Results are advisory; time_source of the lookup is 'inherited'."""
    mod = _FEEDERS.get("rep_lookup")
    if mod is None:
        return {"ran": False, "reason": "rep_lookup not importable"}
    indicators = []
    seen = set()
    for e in events:
        if e["severity"] not in ("high", "medium"):
            continue
        for ind in (e["actors"].get("ip"), e["actors"].get("domain")):
            if ind and ind not in seen:
                seen.add(ind)
                indicators.append(ind)
    if not indicators:
        return {"ran": True, "checked": 0, "results": {}}
    out = {}
    for i, ind in enumerate(indicators):
        try:
            rep = mod.lookup(ind)
            out[ind] = {"level": rep.get("level"), "verdict": rep.get("verdict"),
                        "time_source": "inherited"}
        except Exception as e:  # noqa: BLE001
            out[ind] = {"level": "ERROR", "verdict": str(e)}
        if i < len(indicators) - 1:
            time.sleep(getattr(mod, "_VT_MIN_INTERVAL", 16.0))
    # attach verdicts back onto matching events
    for e in events:
        for ind in (e["actors"].get("ip"), e["actors"].get("domain")):
            if ind in out and out[ind].get("level"):
                e["detail"] += " | rep(%s): %s" % (ind, out[ind]["level"])
    return {"ran": True, "checked": len(indicators), "results": out}


# --------------------------------------------------------------------------- #
# collect (droplet only) / init-case
# --------------------------------------------------------------------------- #

def _run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.SubprocessError, OSError) as e:
        return 1, "", str(e)


def init_case_text(case_id="<id>"):
    """Print the manual commands to build a case folder by hand."""
    return r"""# Build a Liao case folder by hand (owned scope only).
# Droplet:  /opt/liao/cases/{cid}/    Phone: ~/Documents/liao_cases/{cid}/
CID={cid}; CASE=/opt/liao/cases/$CID; mkdir -p "$CASE"; cd "$CASE"

# process table (proc_inventory)
ps -eo pid,ppid,user,lstart,stat,pcpu,pmem,args > ps.txt
# active connections (conn_inventory)  — ss form the parser expects
ss -tunap > netstat.txt
# auth log excerpt (log_parser --auth)
cp /var/log/auth.log auth.log            # or: journalctl -u ssh --no-pager > auth.log
# persistence surface (persistence_audit)  — read-only collector
sudo sh -c "$(python3 /opt/liao/persistence_audit.py --collect)" > persist.txt
# accounts & privilege (account_audit)     — read-only collector
sudo sh -c "$(python3 /opt/liao/account_audit.py --collect)" > accounts.txt
# log integrity (log_integrity)            — raw dump is big; store its JSON
sudo sh -c "$(python3 /opt/liao/log_integrity.py --collect)" \
    | python3 /opt/liao/log_integrity.py --stdin --json > logint.json
# DNS (dns_parser)   — NextDNS export or fetch; store the ANALYSIS json (no URL!)
python3 /opt/liao/dns_parser.py --url --json > dns.json
# fim compare (fim)  — against the OFF-HOST baseline
python3 /opt/liao/fim.py --check > fim.json
# toolkit hashes for off-host anchor verification
sha256sum /opt/liao/* > liao_hashes.txt
# clock + collection metadata
timedatectl > timedatectl.txt
# write manifest.json yourself: host, collected_at, clock_synced, files{{...}},
#   and (for anchor) droplet_hashes or keep liao_hashes.txt above.

# then assemble (phone or droplet):
python3 /opt/liao/ioc_timeline.py --assemble "$CASE" [--anchor ~/anchor] [--enrich]
""".format(cid=case_id)


def collect(case_id, case_root="/opt/liao/cases", opt_liao="/opt/liao",
            anchor_dir=None, enrich=False):
    """Droplet mode: run every collector+feeder, write the case folder, isolate
    failures per feeder, then assemble. Returns the assemble result (or error)."""
    case_dir = os.path.join(os.path.expanduser(case_root), case_id)
    try:
        os.makedirs(case_dir, exist_ok=True)
    except OSError as e:
        return {"ok": False, "error": "cannot make case dir: %s" % e}

    host = os.uname().nodename if hasattr(os, "uname") else "unknown-host"
    files_meta, errors = {}, {}
    now = _now()

    def write(fname, text):
        with open(os.path.join(case_dir, fname), "w") as fh:
            fh.write(text)
        files_meta[fname] = {"host": host, "collected_at": now}

    rc, out, err = _run(["ps", "-eo", "pid,ppid,user,lstart,stat,pcpu,pmem,args"])
    if rc == 0 and out.strip():
        write("ps.txt", out)
    else:
        errors["ps.txt"] = err or "ps failed"

    rc, out, err = _run(["ss", "-tunap"])
    if rc == 0 and out.strip():
        write("netstat.txt", out)
    else:
        errors["netstat.txt"] = err or "ss failed"

    src = _read("/var/log/auth.log")
    if src is not None:
        write("auth.log", src)
    else:
        errors["auth.log"] = "unreadable /var/log/auth.log"

    for fname, feeder in (("persist.txt", "persistence_audit"),
                          ("accounts.txt", "account_audit")):
        mod = _FEEDERS.get(feeder)
        collector = getattr(mod, "COLLECT_CMD", None) if mod else None
        if not collector:
            errors[fname] = "%s has no COLLECT_CMD" % feeder
            continue
        rc, out, err = _run(["sudo", "sh", "-c", collector], timeout=120)
        if rc == 0 and out.strip():
            write(fname, out)
        else:
            errors[fname] = err or "collector rc=%s" % rc

    # log_integrity: run collector, pipe through its own --json
    mod = _FEEDERS.get("log_integrity")
    collector = getattr(mod, "COLLECT_CMD", None) if mod else None
    if collector:
        rc, dump, err = _run(["sudo", "sh", "-c", collector], timeout=180)
        if rc == 0 and dump.strip():
            try:
                res = mod.audit(dump, collected_at=now)
                pub = mod._public(res) if hasattr(mod, "_public") else res
                write("logint.json", json.dumps(pub, default=str))
            except Exception as e:  # noqa: BLE001
                errors["logint.json"] = "audit failed: %s" % e
        else:
            errors["logint.json"] = err or "collector rc=%s" % rc
    else:
        errors["logint.json"] = "log_integrity has no COLLECT_CMD"

    # toolkit hashes for the off-host anchor
    rc, out, err = _run(["sha256sum"] + sorted(glob.glob(os.path.join(opt_liao, "*"))))
    droplet_hashes = _hashes_from_sha256sum(out) if rc == 0 else {}

    rc, td, _ = _run(["timedatectl"])
    clock_synced = None
    if rc == 0 and td:
        write("timedatectl.txt", td)
        m = re.search(r"(?i)system clock synchronized:\s*(\w+)", td)
        if m:
            clock_synced = (m.group(1).lower() == "yes")

    manifest = {"host": host, "collected_at": now, "clock_synced": clock_synced,
                "timedatectl": td if rc == 0 else None,
                "files": files_meta, "droplet_hashes": droplet_hashes,
                "collector_errors": errors}
    with open(os.path.join(case_dir, "manifest.json"), "w") as fh:
        json.dump(_scrub(manifest), fh, indent=2, sort_keys=True)

    # NOTE: dns.json and fim.json are NOT collected here automatically — dns
    # needs the NextDNS credential (keychain) and fim needs the off-host
    # baseline; run those two steps from --init-case. They are reported missing.
    res = assemble(case_dir, enrich=enrich, anchor_dir=anchor_dir)
    res["collector_errors"] = errors
    return res


# --------------------------------------------------------------------------- #
# formatting
# --------------------------------------------------------------------------- #

def _sev_tag(s):
    return s.upper()


def _hms(sec):
    if sec is None:
        return "?"
    sec = int(sec)
    h, r = divmod(sec, 3600)
    m, s = divmod(r, 60)
    return (("%dh" % h) if h else "") + (("%dm" % m) if m else "") + ("%ds" % s)


def format_human(res, timeline_max=60):
    if not res.get("ok"):
        return "!!! IOC TIMELINE FAILED: %s" % res.get("error")
    L = []
    L.append("=" * 72)
    L.append("LIAO IOC TIMELINE  v%s   hosts=%s   collected=%s"
             % (VERSION, ", ".join(res["hosts"]), res.get("collected_at")))
    L.append("BLUF: " + res["bluf"])
    L.append("=" * 72)
    if res["toolkit_untrusted"]:
        L += ["!" * 72,
              "!! TOOLKIT UNTRUSTED: the trust anchor does not match /opt/liao.",
              "!! Every droplet-sourced finding below is suspect until you resolve",
              "!! the anchor mismatch from a known-good copy. See ANCHOR section.",
              "!" * 72]

    # coverage
    L.append("")
    L.append("FEEDER COVERAGE")
    for c in res["coverage"]:
        mark = "ok " if c.get("contributed") else "-- "
        extra = []
        if c.get("events") is not None:
            extra.append("%d ev" % c["events"])
        if c.get("blind_spots"):
            extra.append("%d gap" % c["blind_spots"])
        if c.get("incomplete"):
            extra.append("INCOMPLETE")
        if not c.get("contributed"):
            extra.append("MISSING: %s" % (c.get("reason") or "?"))
        L.append("  [%s] %-26s %-14s %s" % (mark, c["feeder"],
                 (c.get("host") or "-"), "  ".join(extra)))
    if res["missing_feeders"]:
        L.append("  !! MISSING FEEDERS (coverage gaps — NOT an all-clear): %s"
                 % ", ".join(res["missing_feeders"]))
    if res.get("clock_warning"):
        L.append("  !! %s" % res["clock_warning"])

    # blind spots
    L.append("")
    if res["blind_spots"]:
        L.append("BLIND-SPOT WINDOWS (no telemetry — the record itself is dark here)")
        for b in sorted(res["blind_spots"], key=lambda x: x.get("start") or ""):
            L.append("  %s  no telemetry %s -> %s (%s)"
                     % (b.get("host"), b.get("start"), b.get("end"),
                        _hms(b.get("seconds"))))
            if b.get("detail"):
                L.append("      %s" % b["detail"])
    else:
        L.append("BLIND-SPOT WINDOWS: none reported (log_integrity found no gaps, "
                 "or did not run — check coverage above)")

    # timeline
    L.append("")
    tl = res["timeline"]
    L.append("CHRONOLOGICAL TIMELINE  (%d events%s; UTC)"
             % (len(tl), ", newest %d shown" % timeline_max if len(tl) > timeline_max else ""))
    for e in tl[-timeline_max:]:
        span = (" -> %s" % e["end_time"]) if e.get("end_time") else ""
        L.append("  %s%s  [%-6s] %-15s %-14s %-11s %s"
                 % (e["event_time"], span, _sev_tag(e["severity"]), e["phase"],
                    e["host"], e["source"], e["detail"][:90]))

    # state lane
    if res["state_lane"]:
        L.append("")
        L.append("STATE OBSERVED AT COLLECTION  (snapshots — not event-timed)")
        for e in res["state_lane"]:
            L.append("  %s  [%-6s] %-15s %-14s %-11s %s"
                     % (e["event_time"], _sev_tag(e["severity"]), e["phase"],
                        e["host"], e["source"], e["detail"][:90]))

    # threads
    L.append("")
    if res["threads"]:
        L.append("ACTOR THREADS  (events sharing an EXACT indicator; union-find)")
        for t in res["threads"]:
            inds = ", ".join("%s=%s" % (k[0], k[-1]) for k in t["shared_indicators"][:6])
            L.append("  thread %s  [%s]  %d events  hosts=%s  phases=%s"
                     % (t["thread_id"], _sev_tag(t["max_severity"]), t["event_count"],
                        ",".join(t["hosts"]), ">".join(t["phases"])))
            L.append("      shared: %s" % (inds or "(via chained keys)"))
            L.append("      span:   %s -> %s   sources: %s"
                     % (t["first"], t["last"], ", ".join(t["sources"])))
    else:
        L.append("ACTOR THREADS: none (no two events shared an exact indicator)")

    # possible links
    if res["possible_links"]:
        L.append("")
        L.append("POSSIBLE SAME ACTOR — CONFIRM (suspected links, NOT merged)")
        for p in res["possible_links"]:
            L.append("  ? %s: %s" % (p["kind"], p["reason"]))

    # untimed
    if res["untimed"]:
        L.append("")
        L.append("UNTIMED RECORDS  (no reliable event_time — parked, never guessed)")
        for e in res["untimed"]:
            L.append("  [%-6s] %-15s %-11s %s" % (_sev_tag(e["severity"]),
                     e["phase"], e["source"], e["detail"][:90]))

    # anchor detail
    if res.get("anchor") and res["anchor"].get("ok"):
        a = res["anchor"]
        L.append("")
        L.append("TRUST ANCHOR  (%s; anchor from %s)" % (a["status"], a.get("anchor_created")))
        if a["status"] == "verified":
            L.append("  toolkit matches the off-host anchor (%d files)." % a["anchor_files"])
        else:
            for n in a["mismatched"]:
                L.append("  [HIGH ] changed: %s" % n)
            for n in a["missing"]:
                L.append("  [HIGH ] missing: %s" % n)
            for n in a["extra"]:
                L.append("  [HIGH ] extra:   %s" % n)

    L.append("")
    L.append("_%s_" % res["telemetry_note"])
    return "\n".join(L)


def format_md(res):
    """Markdown export for the Obsidian vault."""
    if not res.get("ok"):
        return "# IOC Timeline — FAILED\n\n%s\n" % res.get("error")
    md = ["# IOC Timeline — %s" % ", ".join(res["hosts"]), "",
          "> **BLUF:** %s" % res["bluf"], "",
          "- collected: `%s`" % res.get("collected_at"),
          "- assembled: `%s`" % res.get("assembled_at"),
          "- highest severity: **%s**  |  threads: **%d**  |  anchor: **%s**"
          % (res["highest_severity"], res["thread_count"], res["anchor_status"]), ""]
    if res["toolkit_untrusted"]:
        md += ["> [!danger] TOOLKIT UNTRUSTED — anchor mismatch; resolve before "
               "trusting droplet-sourced findings.", ""]
    md += ["## Feeder coverage", "",
           "| feeder | host | events | status |", "|---|---|---|---|"]
    for c in res["coverage"]:
        md.append("| %s | %s | %s | %s |" % (
            c["feeder"], c.get("host") or "-", c.get("events", "-"),
            "ok" if c.get("contributed") else ("MISSING: %s" % (c.get("reason") or "?"))))
    if res["blind_spots"]:
        md += ["", "## Blind-spot windows", ""]
        for b in res["blind_spots"]:
            md.append("- `%s -> %s` (%s) on %s — %s" % (
                b.get("start"), b.get("end"), _hms(b.get("seconds")),
                b.get("host"), b.get("detail")))
    md += ["", "## Timeline", "",
           "| time | sev | phase | host | source | detail |",
           "|---|---|---|---|---|---|"]
    for e in res["timeline"]:
        md.append("| %s | %s | %s | %s | %s | %s |" % (
            e["event_time"], e["severity"], e["phase"], e["host"], e["source"],
            e["detail"].replace("|", "\\|")[:120]))
    if res["threads"]:
        md += ["", "## Actor threads", ""]
        for t in res["threads"]:
            md.append("- **%s** `%s` — %d events, hosts %s, phases %s"
                      % (t["max_severity"], t["thread_id"], t["event_count"],
                         ",".join(t["hosts"]), ">".join(t["phases"])))
    if res["possible_links"]:
        md += ["", "## Possible same actor — confirm", ""]
        for p in res["possible_links"]:
            md.append("- *%s* — %s" % (p["kind"], p["reason"]))
    md += ["", "---", "_%s_" % res["telemetry_note"], ""]
    return "\n".join(md)


# --------------------------------------------------------------------------- #
# console + CLI
# --------------------------------------------------------------------------- #

def _console():
    while True:
        print("\n=== Liao :: IOC Timeline ===")
        print("1) Assemble a case folder")
        print("2) Verify trust anchor")
        print("3) Make trust anchor (run on droplet after a known-good deploy)")
        print("4) Print manual case-collection commands (--init-case)")
        print("0) Back")
        c = input("> ").strip()
        if c == "0":
            return
        if c == "1":
            d = input("case folder: ").strip()
            an = input("anchor dir (blank = skip): ").strip() or None
            print("\n" + format_human(assemble(d, anchor_dir=an)))
        elif c == "2":
            an = input("anchor dir: ").strip()
            src = input("live --src (blank) or --hashes file / --case dir: ").strip()
            kw = {}
            if src and os.path.isdir(src) and os.path.exists(os.path.join(src, "manifest.json")):
                kw["case_dir"] = src
            elif src and os.path.isfile(src):
                kw["hashes_file"] = src
            elif src:
                kw["src"] = src
            print(json.dumps(verify_anchor(an, **kw), indent=2))
        elif c == "3":
            out = input("anchor out dir: ").strip()
            src = input("src [/opt/liao]: ").strip() or "/opt/liao"
            r = make_anchor(out, src)
            print(json.dumps(r, indent=2))
        elif c == "4":
            print(init_case_text(input("case id: ").strip() or "<id>"))
        else:
            print("?")


_HELP = """ioc_timeline.py v%s — Liao incident-timeline assembler (read-only).

  assemble a case:   python3 ioc_timeline.py --assemble CASE_DIR [--anchor ANCHOR]
                         [--since ISO] [--until ISO] [--enrich] [--json|--md]
  collect+assemble:  python3 ioc_timeline.py --collect CASE_ID  (droplet only)
  print manual cmds: python3 ioc_timeline.py --init-case [CASE_ID]
  make anchor:       python3 ioc_timeline.py --make-anchor OUT [--src /opt/liao]
  verify anchor:     python3 ioc_timeline.py --verify-anchor ANCHOR
                         [--hashes FILE | --case CASE_DIR | --src DIR]
  options:           --self-users a,b   --json   --md

exit codes: 0 clean · 1 flagged · 2 error · 3 incomplete coverage
""" % VERSION

VALUE_FLAGS = {"--assemble", "--collect", "--make-anchor", "--verify-anchor",
               "--anchor", "--since", "--until", "--src", "--hashes", "--case",
               "--self-users", "--init-case", "--case-root"}


def _exit_for(res):
    if not res.get("ok"):
        return 2
    # "flagged" = a HIGH/MEDIUM event or an anchor mismatch. A thread of only
    # low/info events (e.g. the admin's own login clustering) is not a flag.
    flagged = (res.get("toolkit_untrusted")
               or res["severity_counts"].get("high")
               or res["severity_counts"].get("medium"))
    if flagged:
        return 1
    if res.get("incomplete_coverage"):
        return 3
    return 0


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

    def val(name, default=None):
        if name in args:
            i = args.index(name)
            if i + 1 < len(args) and not args[i + 1].startswith("--"):
                return args[i + 1]
        return default

    as_json = "--json" in args
    as_md = "--md" in args
    self_users = [u for u in (val("--self-users", "") or "").split(",") if u]

    if "--init-case" in args:
        print(init_case_text(val("--init-case", "<id>")))
        return 0

    if "--make-anchor" in args:
        r = make_anchor(val("--make-anchor"), val("--src", "/opt/liao"))
        print(json.dumps(_scrub(r), indent=2))
        return 0 if r.get("ok") else 2

    if "--verify-anchor" in args:
        kw = {}
        if val("--hashes"):
            kw["hashes_file"] = val("--hashes")
        if val("--case"):
            kw["case_dir"] = val("--case")
        if val("--src"):
            kw["src"] = val("--src")
        r = verify_anchor(val("--verify-anchor"), **kw)
        if as_json:
            print(json.dumps(_scrub(r), indent=2))
        else:
            if not r.get("ok"):
                print("!! verify failed: %s" % r.get("error"))
            else:
                print("ANCHOR %s  (anchor %s files, current %s files)"
                      % (r["status"], r["anchor_files"], r["current_files"]))
                for k in ("mismatched", "missing", "extra"):
                    for n in r[k]:
                        print("  [HIGH] %-9s %s" % (k, n))
        return 0 if (r.get("ok") and r.get("status") == "verified") else \
            (1 if r.get("ok") else 2)

    if "--collect" in args:
        res = collect(val("--collect"), case_root=val("--case-root", "/opt/liao/cases"),
                      anchor_dir=val("--anchor"), enrich="--enrich" in args)
    elif "--assemble" in args:
        res = assemble(val("--assemble"), since=val("--since"), until=val("--until"),
                       enrich="--enrich" in args, anchor_dir=val("--anchor"),
                       self_users=self_users)
    else:
        _console()
        return 0

    if as_json:
        print(json.dumps(_scrub(res), indent=2, default=str))
    elif as_md:
        print(format_md(res))
    else:
        print(format_human(res))
    return _exit_for(res)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
