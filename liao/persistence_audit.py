#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
persistence_audit.py  —  Liao read-only persistence-surface auditor.

Scope: OWNED ASSETS ONLY. This tool parses a section-marked text dump that YOU
collected from YOUR OWN host. It takes NO network action and NEVER executes,
decodes, or expands any command text it reads. Flags are review candidates,
not verdicts.

What it does:
  * Parses cron (user + system), systemd enabled-units / timers / unit-files,
    SSH authorized_keys, login hooks, and /etc/ld.so.preload.
  * Normalizes everything into timestamped records (timeline contract).
  * Flags persistence-relevant review candidates with severity.
  * Snapshots a known-good baseline (JSON) and diffs later dumps against it.

Stdlib only (runs in Pythonista). stat dump accepted in BOTH formats:
  old (space):  <epoch> <owner> <octal> <path>
  new (pipe) :  <epoch>|<owner>|<octal>|<filetype>|<path>     (menu opt 5 prints the collector)

Exit codes (batch mode):  0 clean · 1 something flagged · 2 error · 3 incomplete input
"""

import sys
import os
import re
import json
import hashlib
from datetime import datetime, timezone

VERSION = "1.0.1"
BASELINE_DEFAULT = "~/Documents/liao_persistence_baseline.json"

EXPECTED_SECTIONS = [
    "crontab_user", "cron_system", "systemd_enabled", "systemd_timers",
    "systemd_units", "ssh_keys", "login_hooks", "ld_preload",
]

STD_EXEC_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/")
SYSTEMD_PREFIX_CHARS = set("@+!-:")

# fetch-piped-to-shell  OR  base64-decode-piped-to-shell  (TEXT MATCH ONLY).
DL_EXEC_RE = re.compile(
    r"(?:\b(?:curl|wget|fetch)\b[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|dash|zsh|ksh|python[0-9.]*)\b)"
    r"|(?:\bbase64\b[^|]*(?:-d|--decode)[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|dash|zsh|python[0-9.]*)\b)"
    r"|(?:\b(?:echo|printf)\b[^|]*\|\s*base64\b[^|]*(?:-d|--decode)[^|]*\|\s*(?:sh|bash|dash))",
    re.IGNORECASE,
)
# exec path under a volatile/world dir or a hidden dot-directory.
TEMP_HIDDEN_RE = re.compile(r"(?:/tmp/|/var/tmp/|/dev/shm/)|/\.[^/\s]+/")

DATE_RE = re.compile(r"[A-Z][a-z]{2}\s+\d{4}-\d\d-\d\d\s+\d\d:\d\d:\d\d\s+UTC")

COLLECT_CMD = r"""#!/bin/sh
# liao persistence-surface collector v1 (READ-ONLY). Run as root on the target.
# Emits a section-marked dump on stdout. Redirect to a file and COPY IT OFF-HOST.
#   sudo sh collect_persistence.sh > dump_$(hostname)_$(date -u +%Y%m%dT%H%M%SZ).txt
emit_stat() { for f in "$@"; do [ -e "$f" ] && stat -c "%Y|%U|%a|%F|%n" "$f"; done; }

echo "===SECTION crontab_user==="
for u in $(cut -d: -f1 /etc/passwd); do
  echo "--- user:$u"
  crontab -l -u "$u" 2>/dev/null || echo "no crontab for $u"
done

echo "===SECTION cron_system==="
emit_stat /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*
for f in /etc/crontab /etc/cron.d/*; do
  [ -f "$f" ] && { echo "--- file:$f"; cat "$f"; }
done

echo "===SECTION systemd_enabled==="
systemctl list-unit-files --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1"  enabled enabled"}'

echo "===SECTION systemd_timers==="
systemctl list-timers --all --no-legend --no-pager 2>/dev/null

echo "===SECTION systemd_units==="
emit_stat /etc/systemd/system/*.service /etc/systemd/system/*.timer
for f in /etc/systemd/system/*.service; do
  [ -e "$f" ] || continue
  echo "--- file:$f"
  grep -E '^(User|ExecStart|ExecStartPre)=' "$f" 2>/dev/null
done

echo "===SECTION ssh_keys==="
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$f" ] && stat -c "%Y|%U|%a|%F|%n" "$f"
done
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$f" ] || continue
  echo "--- file:$f"
  ssh-keygen -lf "$f" 2>/dev/null
done

echo "===SECTION login_hooks==="
emit_stat /etc/profile /etc/profile.d/* /etc/bash.bashrc /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile

echo "===SECTION ld_preload==="
[ -f /etc/ld.so.preload ] && cat /etc/ld.so.preload

echo "===END==="
"""

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _mtime_iso(epoch):
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).replace(microsecond=0).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _entry_id(section, key, content):
    h = hashlib.sha1()
    h.update(("%s\x00%s\x00%s" % (section, key or "", content or "")).encode("utf-8", "replace"))
    return h.hexdigest()[:16]


def is_world_writable(perms):
    p = (perms or "").strip()
    if not p.isdigit():
        return False
    return bool(int(p[-1]) & 0o2)


def _is_interpreter(base):
    if base in ("bash", "sh", "dash", "zsh", "ksh"):
        return True
    return bool(re.match(r"^(python|perl|ruby|node|php)[0-9.]*$", base))


def _strip_systemd_prefix(tok):
    i = 0
    while i < len(tok) and tok[i] in SYSTEMD_PREFIX_CHARS:
        i += 1
    return tok[i:]


def resolve_exec_binary(execline):
    """Return the real target of an ExecStart= line: the binary, or for an
    interpreter (python3/bash/...), the script it runs. Text only; never run."""
    toks = (execline or "").split()
    if not toks:
        return None
    binary = _strip_systemd_prefix(toks[0])
    base = os.path.basename(binary)
    if _is_interpreter(base):
        for a in toks[1:]:
            if a.startswith("-"):
                continue
            return a  # script path (may be a %i template or relative)
        return binary
    return binary


def _make_record(section, kind, path=None, owner=None, perms=None, ftype=None,
                 user=None, unit=None, content="", event_time=None, time_source=None,
                 fp=None, opts=None, exec_list=None):
    key = unit or path
    if not key and kind == "cron_entry":
        key = "crontab:" + (user or "")
    rec = {
        "section": section, "kind": kind, "path": path, "owner": owner,
        "perms": perms, "ftype": ftype, "user": user, "unit": unit,
        "content": content, "event_time": event_time, "time_source": time_source,
        "entry_id": _entry_id(section, key, content), "flags": [],
    }
    if fp is not None:
        rec["fp"] = fp
    if opts is not None:
        rec["opts"] = opts
    if exec_list is not None:
        rec["exec"] = exec_list
    return rec


def parse_stat_line(ln):
    """Accept BOTH stat formats. Return dict or None."""
    if "|" in ln:
        parts = ln.split("|")
        if len(parts) >= 5 and parts[0].strip().isdigit():
            path = "|".join(parts[4:]).strip()
            if path.startswith("/"):   # path token guards against content lines
                return {"epoch": parts[0].strip(), "owner": parts[1].strip(),
                        "perms": parts[2].strip(), "ftype": parts[3].strip(),
                        "path": path}
        return None
    toks = ln.split(None, 3)
    if len(toks) == 4 and toks[0].isdigit() and toks[3].strip().startswith("/"):
        return {"epoch": toks[0], "owner": toks[1], "perms": toks[2],
                "ftype": None, "path": toks[3].strip()}
    return None


# --------------------------------------------------------------------------- #
# section splitting
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


def _split_filebacked(lines, section):
    """Return (files_by_path, file_order, contents_by_path, notes)."""
    files, file_order, contents, notes = {}, [], {}, []
    cur_path = None
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("--- file:"):
            cur_path = s[len("--- file:"):].strip()
            contents.setdefault(cur_path, [])
            continue
        if s.startswith("--- user:"):
            cur_path = None
            continue
        st = parse_stat_line(ln)
        if st:
            # A stat line ends any open file block (sections may interleave
            # stat / --- file: / stat / --- file:, as ssh_keys does).
            cur_path = None
            if st["path"] not in files:
                file_order.append(st["path"])
            files[st["path"]] = st
        elif cur_path is not None:
            contents[cur_path].append(ln)
        else:
            notes.append("unparsed stat line in %s: %r" % (section, ln.strip()[:90]))
    return files, file_order, contents, notes


def _is_cron_entry_line(s):
    if not s or s.startswith("#"):
        return False
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", s):   # env assignment
        return False
    return bool(re.match(r"^(@\w+|[\d*])", s))      # @reboot / schedule


# --------------------------------------------------------------------------- #
# per-section record builders
# --------------------------------------------------------------------------- #

def _build_crontab_user(lines, coll):
    recs = []
    cur_user = None
    for ln in lines:
        s = ln.strip()
        if s.startswith("--- user:"):
            cur_user = s[len("--- user:"):].strip()
            continue
        if not s or s.lower().startswith("no crontab for"):
            continue
        if _is_cron_entry_line(s):
            recs.append(_make_record("crontab_user", "cron_entry", user=cur_user,
                                     content=s, event_time=coll, time_source="collection"))
    return recs, []


def _build_cron_system(lines, coll):
    files, order, contents, notes = _split_filebacked(lines, "cron_system")
    recs = []
    for p in order:
        m = files[p]
        recs.append(_make_record("cron_system", "file", path=p, owner=m["owner"],
                                  perms=m["perms"], ftype=m["ftype"],
                                  event_time=_mtime_iso(m["epoch"]), time_source="mtime"))
    for p, clines in contents.items():
        meta = files.get(p)
        inh = _mtime_iso(meta["epoch"]) if meta else None
        for cl in clines:
            s = cl.strip()
            if _is_cron_entry_line(s):
                recs.append(_make_record("cron_system", "cron_entry", path=p,
                                         owner=meta["owner"] if meta else None,
                                         perms=meta["perms"] if meta else None,
                                         content=s,
                                         event_time=inh,
                                         time_source="inherited" if inh else None))
    return recs, notes


def _build_enabled(lines, coll):
    recs = []
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        unit = s.split()[0]
        recs.append(_make_record("systemd_enabled", "enabled_unit", unit=unit,
                                  content="enabled", event_time=coll, time_source="collection"))
    return recs, []


def _build_timers(lines, coll):
    recs, notes = [], []
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        toks = s.split()
        if len(toks) < 2 or not (toks[-2].endswith(".timer") and toks[-1].endswith(".service")):
            continue  # header / footer / noise
        timer, svc = toks[-2], toks[-1]
        dates = DATE_RE.findall(ln)
        nxt = dates[0] if dates else None
        last = dates[1] if len(dates) > 1 else None
        content = "timer=%s service=%s" % (timer, svc)
        rec = _make_record("systemd_timers", "timer", unit=timer,
                           content=content, event_time=coll, time_source="collection")
        rec["next"], rec["last"] = nxt, last   # schedule data; NOT part of entry_id
        recs.append(rec)
    return recs, notes


def _build_units(lines, coll):
    files, order, contents, notes = _split_filebacked(lines, "systemd_units")
    recs = []
    for p in order:
        m = files[p]
        user, execs = None, []
        for cl in contents.get(p, []):
            cs = cl.strip()
            if cs.startswith("User="):
                user = cs.split("=", 1)[1].strip()
            elif cs.startswith("ExecStart=") or cs.startswith("ExecStartPre="):
                execs.append(cs.split("=", 1)[1].strip())
        content = "; ".join((["User=%s" % user] if user else []) + ["ExecStart=%s" % e for e in execs])
        recs.append(_make_record("systemd_units", "unit", path=p, owner=m["owner"],
                                  perms=m["perms"], ftype=m["ftype"], user=user,
                                  unit=os.path.basename(p), content=content,
                                  event_time=_mtime_iso(m["epoch"]), time_source="mtime",
                                  exec_list=execs))
    return recs, notes


def _build_ssh(lines, coll):
    files, order, contents, notes = _split_filebacked(lines, "ssh_keys")
    recs = []
    for p, clines in contents.items():
        meta = files.get(p)
        last = None
        pending_opts = None
        for cl in clines:
            cs = cl.strip()
            if not cs:
                continue
            if cs.lower().startswith("opts:"):
                opt = cs[5:].strip()
                if last is not None:
                    last["opts"] = opt
                else:
                    pending_opts = opt
                continue
            m = re.match(r"^\d+\s+SHA256:(\S+)\s+(.*?)\s+\((\w+)\)\s*$", cs)
            if not m:
                notes.append("unparsed key line in ssh_keys: %r" % cs[:90])
                continue
            fp, comment = m.group(1), m.group(2).strip()
            rec = _make_record("ssh_keys", "ssh_key", path=p,
                               owner=meta["owner"] if meta else None,
                               perms=meta["perms"] if meta else None,
                               ftype=meta["ftype"] if meta else None,
                               content="SHA256:%s %s" % (fp, comment),
                               event_time=_mtime_iso(meta["epoch"]) if meta else None,
                               time_source="mtime" if meta else None, fp=fp,
                               opts=pending_opts)
            pending_opts = None
            last = rec
            recs.append(rec)
    # stat-only authorized_keys files with no parsed keys -> still record the file
    for p in order:
        if p not in contents or not any(r["path"] == p for r in recs):
            m = files[p]
            recs.append(_make_record("ssh_keys", "file", path=p, owner=m["owner"],
                                      perms=m["perms"], ftype=m["ftype"],
                                      event_time=_mtime_iso(m["epoch"]), time_source="mtime"))
    return recs, notes


def _build_hooks(lines, coll):
    files, order, contents, notes = _split_filebacked(lines, "login_hooks")
    recs = []
    for p in order:
        m = files[p]
        recs.append(_make_record("login_hooks", "hook", path=p, owner=m["owner"],
                                  perms=m["perms"], ftype=m["ftype"],
                                  event_time=_mtime_iso(m["epoch"]), time_source="mtime"))
    return recs, notes


def _build_preload(lines, coll):
    recs, notes = [], []
    body = [ln for ln in lines if ln.strip()]
    if body:
        for ln in body:
            recs.append(_make_record("ld_preload", "preload", path="/etc/ld.so.preload",
                                     content=ln.strip(), event_time=coll, time_source="collection"))
    return recs, notes


_BUILDERS = {
    "crontab_user": _build_crontab_user,
    "cron_system": _build_cron_system,
    "systemd_enabled": _build_enabled,
    "systemd_timers": _build_timers,
    "systemd_units": _build_units,
    "ssh_keys": _build_ssh,
    "login_hooks": _build_hooks,
    "ld_preload": _build_preload,
}


# --------------------------------------------------------------------------- #
# flagging
# --------------------------------------------------------------------------- #

def _add_flag(rec, name, severity, note):
    rec["flags"].append({"name": name, "severity": severity, "note": note})


def flag_records(records):
    """Attach flags to records; return (flagged_records, info_list, symlink_notes)."""
    info, symlinks = [], []
    fp_users = {}
    for r in records:
        if r["kind"] == "ssh_key" and r.get("fp"):
            fp_users.setdefault(r["fp"], set()).add(r.get("owner") or "?")

    for r in records:
        path = r.get("path") or ""
        perms = r.get("perms")
        owner = r.get("owner")
        ftype = r.get("ftype")
        kind = r["kind"]

        probable_symlink = False
        if ftype and "symbolic link" in ftype.lower():
            probable_symlink = True
            r["symlink"] = "confirmed"
            symlinks.append((path, "confirmed"))
        elif not ftype and perms == "777":
            probable_symlink = True
            r["symlink"] = "probable"
            symlinks.append((path, "probable (777, type unknown)"))

        if perms and is_world_writable(perms) and not probable_symlink:
            _add_flag(r, "world_writable", "HIGH", "perms %s grant write to 'other'" % perms)

        if kind in ("file", "unit", "hook", "ssh_key", "preload") and owner and owner != "root" \
                and path.startswith("/etc"):
            if path.startswith("/etc/systemd/system") or path.startswith("/etc/cron") or path == "/etc/crontab":
                sev = "HIGH"
            else:
                sev = "MEDIUM"
            _add_flag(r, "non_root_owner_system_path", sev,
                      "owned by %s; editable to change what root runs" % owner)

        texts = []
        if kind == "cron_entry":
            texts.append(r.get("content", ""))
        if kind == "unit":
            texts.extend(r.get("exec", []) or [])
        for t in texts:
            if TEMP_HIDDEN_RE.search(t):
                _add_flag(r, "exec_from_temp_or_hidden", "HIGH",
                          "exec/script path under tmp, shm, or a hidden dot-dir")
            if DL_EXEC_RE.search(t):
                _add_flag(r, "download_and_execute_pattern", "HIGH",
                          "fetch|shell or base64-decode|shell shape (text match only)")

        if kind == "preload":
            _add_flag(r, "ld_preload_present", "HIGH", "/etc/ld.so.preload has content")

        if kind == "ssh_key" and path.startswith("/root/"):
            others = sorted(u for u in fp_users.get(r.get("fp"), set()) if u != (r.get("owner") or "?"))
            note = "authorized_keys under /root"
            if others:
                note += "; same fingerprint also present for: " + ", ".join(others)
            _add_flag(r, "root_authorized_key", "MEDIUM", note)

        if kind == "ssh_key" and r.get("opts"):
            _add_flag(r, "key_options_present", "LOW", "forced options/command on key: %s" % r["opts"])

        if kind == "unit":
            for e in (r.get("exec", []) or []):
                b = resolve_exec_binary(e)
                if b and b.startswith("/") and not b.startswith(STD_EXEC_PREFIXES):
                    info.append({"entry_id": r["entry_id"], "unit": r.get("unit") or path,
                                 "target": b, "event_time": r.get("event_time"),
                                 "detail": "nonstandard_exec_path: %s outside standard dirs" % b})

    flagged = [r for r in records if r["flags"]]
    return flagged, info, symlinks


# --------------------------------------------------------------------------- #
# top-level audit
# --------------------------------------------------------------------------- #

def audit(text, baseline_data=None, collected_at=None):
    if text is None or not text.strip():
        return {"ok": False, "error": "EMPTY INPUT: no dump text was provided.",
                "records": [], "flagged": [], "info": []}

    sections, order, complete, saw_marker, preamble = split_sections(text)
    if not saw_marker:
        return {"ok": False,
                "error": "NO SECTION MARKERS: input has no '===SECTION ...===' lines; "
                         "this is not a persistence dump.",
                "records": [], "flagged": [], "info": []}

    coll = collected_at or _now_iso()
    records, notes = [], []
    if preamble:
        notes.append("%d line(s) appeared before the first section marker (ignored)." % len(preamble))

    for name in order:
        builder = _BUILDERS.get(name)
        if not builder:
            notes.append("UNKNOWN section '%s' present — not parsed." % name)
            continue
        try:
            recs, n = builder(sections.get(name, []), coll)
        except Exception as e:  # never let one malformed section sink the audit
            notes.append("ERROR parsing section '%s': %s" % (name, e))
            continue
        records.extend(recs)
        notes.extend(n)

    missing = [s for s in EXPECTED_SECTIONS if s not in sections]
    extra = [s for s in order if s not in EXPECTED_SECTIONS]
    ld_clean = ("ld_preload" in sections and not any(r["kind"] == "preload" for r in records))

    flagged, info, symlinks = flag_records(records)

    if baseline_data:
        base_ids = set(baseline_data.get("entry_ids", []))
        info = [i for i in info if i["entry_id"] not in base_ids]  # suppress already-reviewed

    sev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in flagged:
        for f in r["flags"]:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1

    return {
        "ok": True, "error": None, "complete": complete, "saw_markers": True,
        "sections_found": order, "sections_missing": missing, "sections_extra": extra,
        "collection_time": coll, "record_count": len(records), "records": records,
        "flagged": flagged, "info": info, "symlinks": symlinks, "notes": notes,
        "ld_preload_clean": ld_clean, "severity_counts": sev,
    }


def build_baseline(text, path=None, collected_at=None):
    res = audit(text, collected_at=collected_at)
    if not res["ok"]:
        return {"ok": False, "path": None, "count": 0, "error": res["error"]}
    data = {
        "version": VERSION, "created": _now_iso(),
        "collection_time": res["collection_time"], "complete": res["complete"],
        "entry_ids": sorted(r["entry_id"] for r in res["records"]),
        "records": {
            r["entry_id"]: {
                "section": r["section"], "kind": r["kind"], "path": r["path"],
                "unit": r["unit"], "owner": r["owner"], "perms": r["perms"],
                "event_time": r["event_time"], "time_source": r["time_source"],
                "content": r["content"],
            } for r in res["records"]
        },
    }
    target = os.path.expanduser(path or BASELINE_DEFAULT)
    d = os.path.dirname(target)
    try:
        if d:
            os.makedirs(d, exist_ok=True)
        with open(target, "w") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
    except Exception as e:
        return {"ok": False, "path": target, "count": 0, "error": "write failed: %s" % e}
    return {"ok": True, "path": target, "count": len(data["records"]),
            "incomplete": not res["complete"], "error": None}


def compare(text, baseline_path=None, collected_at=None):
    target = os.path.expanduser(baseline_path or BASELINE_DEFAULT)
    try:
        with open(target) as fh:
            base = json.load(fh)
    except Exception as e:
        return {"ok": False, "error": "cannot read baseline %s: %s" % (target, e)}

    res = audit(text, baseline_data=base, collected_at=collected_at)
    if not res["ok"]:
        return {"ok": False, "error": res["error"]}

    base_recs = base.get("records", {})
    cur = {r["entry_id"]: r for r in res["records"]}

    added = [cur[i] for i in cur if i not in base_recs]
    removed = [dict(base_recs[i], entry_id=i) for i in base_recs if i not in cur]
    modified = []
    for i in cur:
        if i not in base_recs:
            continue
        b, c = base_recs[i], cur[i]
        changed = (b.get("owner") != c.get("owner")) or (b.get("perms") != c.get("perms"))
        if c.get("time_source") in ("mtime", "inherited") and b.get("event_time") != c.get("event_time"):
            changed = True
        if changed:
            modified.append({
                "entry_id": i, "path": c.get("path") or c.get("unit"),
                "was": {"owner": b.get("owner"), "perms": b.get("perms"), "event_time": b.get("event_time")},
                "now": {"owner": c.get("owner"), "perms": c.get("perms"), "event_time": c.get("event_time")},
                "event_time": c.get("event_time"),
            })
    return {"ok": True, "error": None, "baseline": target, "complete": res["complete"],
            "added": added, "removed": removed, "modified": modified,
            "flagged": res["flagged"], "info": res["info"]}


# --------------------------------------------------------------------------- #
# human formatting
# --------------------------------------------------------------------------- #

_BANNER = "!" * 68


def _flag_block(flagged):
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    rows = []
    for r in flagged:
        tgt = r.get("unit") or r.get("path") or ("crontab:" + (r.get("user") or ""))
        for f in r["flags"]:
            rows.append((order.get(f["severity"], 9), f["severity"], f["name"], tgt, r, f))
    rows.sort(key=lambda x: (x[0], x[2], str(x[3])))
    out = []
    for _, sevv, name, tgt, r, f in rows:
        meta = []
        if r.get("owner"):
            meta.append("owner=%s" % r["owner"])
        if r.get("perms"):
            meta.append("perms=%s" % r["perms"])
        if r.get("event_time"):
            meta.append("@%s" % r["event_time"])
        out.append("  [%-6s] %-27s %s" % (sevv, name, tgt))
        out.append("           %s" % ("  ".join(meta) if meta else "(no file metadata)"))
        out.append("           -> %s" % f["note"])
    return "\n".join(out)


def format_human(res):
    if not res.get("ok"):
        return "%s\n!! AUDIT FAILED: %s\n%s" % (_BANNER, res.get("error"), _BANNER)

    L = []
    sev = res["severity_counts"]
    nflag = len(res["flagged"])
    ninfo = len(res["info"])
    verdict = ("%d flagged (%d HIGH / %d MED / %d LOW) + %d INFO"
               % (nflag, sev["HIGH"], sev["MEDIUM"], sev["LOW"], ninfo)) if nflag or ninfo \
        else "nothing flagged"
    L.append("LIAO PERSISTENCE AUDIT  v%s   collected=%s" % (VERSION, res["collection_time"]))
    L.append("RESULT: %s   |   dump %s" % (verdict, "COMPLETE" if res["complete"] else "INCOMPLETE"))
    L.append("")

    if not res["complete"]:
        L.append(_BANNER)
        L.append("!! INCOMPLETE INPUT: no '===END===' terminator — paste was truncated.")
        L.append("!! Findings below cover only what parsed; DO NOT treat as a full picture.")
        L.append(_BANNER)
    if res["sections_missing"]:
        L.append(_BANNER)
        L.append("!! MISSING SECTIONS: " + ", ".join(res["sections_missing"]))
        L.append("!! Those persistence surfaces were NOT examined.")
        L.append(_BANNER)
    if res["sections_extra"]:
        L.append("?? Unexpected sections (not parsed): " + ", ".join(res["sections_extra"]))

    L.append("Parsed %d records across %d sections: %s"
             % (res["record_count"], len(res["sections_found"]), ", ".join(res["sections_found"])))
    L.append("")

    if res["flagged"]:
        L.append("FLAGGED  (review candidates, NOT verdicts)")
        L.append(_flag_block(res["flagged"]))
        L.append("")
    if res["info"]:
        L.append("INFO  (nonstandard exec paths — not counted as flagged)")
        for i in sorted(res["info"], key=lambda x: str(x.get("unit"))):
            L.append("  %-28s %s" % (i.get("unit"), i.get("target")))
        L.append("")

    notes = []
    if res.get("symlinks"):
        uniq = sorted(set(p for p, _ in res["symlinks"]))
        notes.append("probable/confirmed symlinks (NOT flagged world-writable): %d" % len(uniq))
        for p in uniq:
            notes.append("   - %s" % p)
    if res.get("ld_preload_clean"):
        notes.append("ld_preload: section present and empty -> no /etc/ld.so.preload (clean)")
    for n in res["notes"]:
        notes.append(n)
    if notes:
        L.append("NOTES")
        for n in notes:
            L.append("  " + n)
        L.append("")

    if not res["flagged"] and not res["info"]:
        L.append("No drift / nothing flagged from this vantage.")
    L.append("Vantage limit: reflects ONLY the sections in this dump, at collection time. "
             "Flags are leads to verify, not confirmed compromise.")
    return "\n".join(L)


def format_baseline(res):
    if not res["ok"]:
        return "%s\n!! BASELINE FAILED: %s\n%s" % (_BANNER, res["error"], _BANNER)
    L = ["BASELINE WRITTEN: %s" % res["path"],
         "  %d records snapshotted." % res["count"]]
    if res.get("incomplete"):
        L.append("  !! WARNING: source dump was INCOMPLETE (no ===END===) — baseline is partial.")
    L.append(_BANNER)
    L.append("!! COPY THIS BASELINE OFF-HOST NOW. A baseline that lives only on the")
    L.append("!! audited host can be edited by whatever you are hunting. Store a copy")
    L.append("!! somewhere the target cannot reach, and diff against that copy.")
    L.append(_BANNER)
    return "\n".join(L)


def format_compare(res):
    if not res["ok"]:
        return "%s\n!! COMPARE FAILED: %s\n%s" % (_BANNER, res["error"], _BANNER)
    L = ["COMPARE vs baseline: %s" % res["baseline"],
         "  dump %s" % ("COMPLETE" if res["complete"] else "INCOMPLETE"),
         "  added=%d  removed=%d  modified=%d"
         % (len(res["added"]), len(res["removed"]), len(res["modified"])), ""]
    if res["added"]:
        L.append("ADDED since baseline")
        for r in res["added"]:
            L.append("  + %-9s %-22s %s  @%s"
                     % (r.get("kind"), (r.get("unit") or r.get("path") or ""),
                        r.get("content", "")[:46], r.get("event_time")))
        L.append("")
    if res["removed"]:
        L.append("REMOVED since baseline")
        for r in res["removed"]:
            L.append("  - %-9s %-22s %s"
                     % (r.get("kind"), (r.get("unit") or r.get("path") or ""), r.get("content", "")[:46]))
        L.append("")
    if res["modified"]:
        L.append("MODIFIED since baseline (owner / perms / mtime)")
        for m in res["modified"]:
            L.append("  ~ %s" % m["path"])
            L.append("      was: owner=%s perms=%s @%s"
                     % (m["was"]["owner"], m["was"]["perms"], m["was"]["event_time"]))
            L.append("      now: owner=%s perms=%s @%s"
                     % (m["now"]["owner"], m["now"]["perms"], m["now"]["event_time"]))
        L.append("")
    if not (res["added"] or res["removed"] or res["modified"]):
        L.append("No drift / nothing changed from this vantage vs the baseline.")
    return "\n".join(L)


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
        with open(os.path.expanduser(path), "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return None


def _console():
    while True:
        print("\n" + "=" * 52)
        print("LIAO PERSISTENCE AUDIT  (read-only, owned scope)")
        print(" 1) Audit    — paste a dump")
        print(" 2) Audit    — from a file path")
        print(" 3) Baseline — build from a pasted dump")
        print(" 4) Compare  — pasted dump vs baseline")
        print(" 5) Collector — print the collection command")
        print(" 0) Back")
        try:
            c = input("> ").strip()
        except EOFError:
            return
        if c == "0":
            return
        elif c == "1":
            print(format_human(audit(_read_paste())))
        elif c == "2":
            p = input("path: ").strip()
            t = _read_file(p)
            print("!! cannot read: %s" % p) if t is None else print(format_human(audit(t)))
        elif c == "3":
            t = _read_paste()
            p = input("baseline path [blank=default %s]: " % BASELINE_DEFAULT).strip() or None
            print(format_baseline(build_baseline(t, p)))
        elif c == "4":
            t = _read_paste()
            p = input("baseline path [blank=default %s]: " % BASELINE_DEFAULT).strip() or None
            print(format_compare(compare(t, p)))
        elif c == "5":
            print(COLLECT_CMD)
        else:
            print("?")


_HELP = """persistence_audit.py v%s — Liao read-only persistence-surface auditor

  interactive menu:   python3 persistence_audit.py
  audit a file:       python3 persistence_audit.py DUMP.txt [--json]
  audit via stdin:    collect ... | python3 persistence_audit.py --stdin [--json]
  build a baseline:   python3 persistence_audit.py --build-baseline BASE.json (DUMP.txt | --stdin)
  compare to baseline:python3 persistence_audit.py --compare BASE.json (DUMP.txt | --stdin)
  print collector:    python3 persistence_audit.py --collect
  options:            --json  --collected-at <ISO8601>  --version  -h/--help

exit codes: 0 clean · 1 flagged · 2 error · 3 incomplete input
""" % VERSION

VALUE_FLAGS = {"--compare", "--build-baseline", "--collected-at"}


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
    buildp = val("--build-baseline")
    comparep = val("--compare")
    collected = val("--collected-at")

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
        r = build_baseline(text, buildp, collected)
        print(json.dumps(r, indent=2) if as_json else format_baseline(r))
        return 0 if r["ok"] else 2

    if "--compare" in args:
        if text is None:
            text = sys.stdin.read()
        r = compare(text, comparep, collected)
        print(json.dumps(r, indent=2, default=str) if as_json else format_compare(r))
        return 0 if r["ok"] else 2

    if text is None:
        _console()
        return 0

    r = audit(text, collected_at=collected)
    print(json.dumps(r, indent=2, default=str) if as_json else format_human(r))
    if not r["ok"]:
        return 2
    if not r["complete"]:
        return 3
    return 1 if r["flagged"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
