#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
account_audit.py  —  Liao read-only account & privilege auditor.

Scope: OWNED ASSETS ONLY. Parses a section-marked text dump that YOU collected
from YOUR OWN host. It takes NO network action and NEVER executes, decodes, or
expands anything it reads. It never reads /etc/shadow or /etc/gshadow contents
and never prints a password hash: any hash-shaped string found in input is
redacted before parsing and reported loudly. Flags are review candidates, not
verdicts.

What it does:
  * Parses accounts, groups, passwd -S status, sudoers (+ sudoers.d), effective
    sshd settings, last-login data and stat metadata of the account files.
  * Normalizes everything into timestamped records (timeline contract).
  * Flags any new or unexpected path to root as a review candidate.
  * Snapshots a known-good baseline (JSON) and diffs later dumps against it;
    reviewed flags can be acknowledged (suppressed) via the baseline.

Stdlib only (runs in Pythonista). stat lines accepted in BOTH formats:
  old (space):  <epoch> <owner> <octal> <path>
  new (pipe) :  <epoch>|<owner>|<octal>|<filetype>|<path>   (menu opt 5 prints the collector)

Exit codes (batch):  0 clean · 1 flagged/drift · 2 error · 3 incomplete input/vantage
"""

import sys
import os
import re
import json
import hashlib
from datetime import datetime, timezone

VERSION = "1.0.0"
BASELINE_DEFAULT = "~/Documents/liao_account_baseline.json"

EXPECTED_SECTIONS = [
    "meta", "passwd", "group", "account_status", "sudoers",
    "sshd_effective", "lastlog", "account_files",
]

# Site policy. Override with env LIAO_ADMINS / LIAO_SERVICE_NAMES (comma lists),
# or admins at runtime with --admins a,b
ADMIN_USERS_DEFAULT = tuple(os.environ.get("LIAO_ADMINS", "root").split(","))
SERVICE_NAMES = tuple(x for x in os.environ.get("LIAO_SERVICE_NAMES", "do-agent").split(",") if x)
SERVICE_PREFIXES = ("svc-",)
PRIV_GROUPS = ("sudo", "admin", "wheel", "adm", "docker", "lxd")
ROOT_EQUIV_GROUPS = ("docker", "lxd")
STOCK_GROUP_MEMBERS = {("adm", "syslog")}          # stock Ubuntu: syslog reads logs
NON_LOGIN_SHELLS = {"nologin", "false", "true", "sync", "halt", "shutdown"}
NOBODY_UID = 65534
SENSITIVE_SHADOW = ("/etc/shadow", "/etc/gshadow")
SENSITIVE_DB = ("/etc/passwd", "/etc/group")
KEY_FILES = ("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow", "/etc/sudoers")
AUDITED_INCLUDEDIR = "/etc/sudoers.d"

SUDO_TAGS = {
    "NOPASSWD", "PASSWD", "NOEXEC", "EXEC", "SETENV", "NOSETENV", "LOG_INPUT",
    "NOLOG_INPUT", "LOG_OUTPUT", "NOLOG_OUTPUT", "MAIL", "NOMAIL", "FOLLOW",
    "NOFOLLOW", "INTERCEPT", "NOINTERCEPT",
}
# Binaries that hand out a shell / arbitrary write when run via sudo (text match only).
SHELL_ESCAPE_BINS = {
    "bash", "sh", "dash", "zsh", "ksh", "fish", "csh", "tcsh", "su", "sudo", "env",
    "vi", "vim", "nvim", "view", "nano", "ed", "less", "more", "man", "find", "awk",
    "gawk", "mawk", "perl", "ruby", "lua", "node", "php", "tee", "cp", "mv", "dd",
    "chmod", "chown", "tar", "zip", "rsync", "git", "systemctl", "journalctl",
    "docker", "apt", "apt-get", "dpkg", "pip", "pip3", "crontab", "install", "ln",
    "sed", "socat", "nc", "ncat", "script", "ssh", "scp", "busybox", "nmap",
}

# Password-hash shapes ($1$ $2a$ $2b$ $2y$ $5$ $6$ $7$ $y$ $gy$ ...). Redacted on sight.
HASH_RE = re.compile(r"\$(?:1|2[abxy]?|5|6|7|y|gy|sha1|md5)\$[^\s:]+")
LASTLOG_DATE_RE = re.compile(
    r"[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+[+-]\d{4}\s+\d{4}")
LAST_DATE_RE = re.compile(
    r"[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+\d{4}")
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

COLLECT_CMD = r"""#!/bin/sh
# liao account/privilege collector v1 (READ-ONLY). Run as root on the target.
# Never reads /etc/shadow or /etc/gshadow contents; stat metadata only.
#   sudo sh collect_accounts.sh > acct_$(hostname)_$(date -u +%Y%m%dT%H%M%SZ).txt
# sudo needed for: account_status, sudoers, sshd_effective (lastlog2 may too).
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; LC_ALL=C; export LC_ALL
emit_stat() { for f in "$@"; do [ -e "$f" ] && stat -c "%Y|%U|%a|%F|%n" "$f"; done; }
# Mask field 2 of passwd/group: keep x * ! !! or empty; anything else -> <HASH_MASKED>
mask2() { awk -F: 'BEGIN{OFS=":"}{if($2!="x"&&$2!="*"&&$2!="!"&&$2!="!!"&&$2!="")$2="<HASH_MASKED>";print}'; }

echo "===SECTION meta==="
echo "host:$(hostname)"
echo "collected_utc:$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "collector_uid:$(id -u)"

echo "===SECTION passwd==="
getent passwd | mask2

echo "===SECTION group==="
getent group | mask2

echo "===SECTION account_status==="
out=$(passwd -S -a 2>&1); echo "--- rc:$?"; echo "$out" | awk '{print $1, $2, $3}'

echo "===SECTION sudoers==="
emit_stat /etc/sudoers /etc/sudoers.d/*
for f in /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  echo "--- file:$f"
  sed -e '/^[[:space:]]*$/d' -e '/^[[:space:]]*#include/b' -e '/^[[:space:]]*#/d' "$f" 2>&1
done

echo "===SECTION sshd_effective==="
out=$(sshd -T 2>&1); rc=$?; echo "--- rc:$rc"
if [ "$rc" -ne 0 ]; then echo "$out" | head -n 3 | sed 's/^/--- error:/'
else echo "$out" | grep -iE '^(permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|permitemptypasswords|allowusers|allowgroups|denyusers|authorizedkeysfile) '; fi

echo "===SECTION lastlog==="
if command -v lastlog >/dev/null 2>&1; then echo "--- source:lastlog"; lastlog 2>&1
elif command -v lastlog2 >/dev/null 2>&1; then echo "--- source:lastlog2"; lastlog2 2>&1
else echo "--- source:last"; last -F -w 2>&1; fi

echo "===SECTION account_files==="
emit_stat /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers /etc/sudoers.d /etc/sudoers.d/*

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


def _iso_from_meta(s):
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            d = datetime.strptime(s.strip(), fmt)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d.astimezone(timezone.utc).isoformat()
        except ValueError:
            continue
    return None


def _key_id(key):
    return hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:16]


def _perm_int(p):
    p = (p or "").strip()
    if not p or any(c not in "01234567" for c in p):
        return None
    return int(p, 8)


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
    """Accept BOTH stat formats. Return dict or None."""
    if "|" in ln:
        parts = ln.split("|")
        if len(parts) >= 5 and parts[0].strip().isdigit():
            path = "|".join(parts[4:]).strip()
            if path.startswith("/"):
                return {"epoch": parts[0].strip(), "owner": parts[1].strip(),
                        "perms": parts[2].strip(), "ftype": parts[3].strip(), "path": path}
        return None
    toks = ln.split(None, 3)
    if len(toks) == 4 and toks[0].isdigit() and toks[3].strip().startswith("/"):
        return {"epoch": toks[0], "owner": toks[1], "perms": toks[2],
                "ftype": None, "path": toks[3].strip()}
    return None


def _shell_base(shell):
    return os.path.basename((shell or "").strip())


def _login_capable(shell):
    """Empty shell field means /bin/sh -> login capable."""
    return _shell_base(shell) not in NON_LOGIN_SHELLS


def _is_service(name):
    return name in SERVICE_NAMES or any(name.startswith(p) for p in SERVICE_PREFIXES)


def _is_system(acct):
    return acct["uid"] < 1000 or acct["uid"] == NOBODY_UID


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


def _ctl(lines):
    """Pull collector control lines (--- rc / --- error / --- source) out of a section."""
    rc, errs, src, body = None, [], None, []
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("--- rc:"):
            rc = s[7:].strip()
        elif s.startswith("--- error:"):
            errs.append(s[10:].strip())
        elif s.startswith("--- source:"):
            src = s[11:].strip()
        else:
            body.append(ln)
    return rc, errs, src, body


def _split_filebacked(lines):
    """Return (stats_by_path, stat_order, contents_by_path, notes)."""
    files, order, contents, notes = {}, [], {}, []
    cur = None
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("--- file:"):
            cur = s[len("--- file:"):].strip()
            contents.setdefault(cur, [])
            continue
        st = parse_stat_line(ln) if cur is None else None
        if st:
            if st["path"] not in files:
                order.append(st["path"])
            files[st["path"]] = st
        elif cur is not None:
            contents[cur].append(ln.rstrip("\n"))
        else:
            notes.append("unparsed line in sudoers: %r" % s[:90])
    return files, order, contents, notes


# --------------------------------------------------------------------------- #
# section parsers -> model
# --------------------------------------------------------------------------- #

def _parse_meta(lines):
    m = {}
    for ln in lines:
        s = ln.strip()
        if ":" in s:
            k, v = s.split(":", 1)
            m[k.strip()] = v.strip()
    return m


def _parse_passwd(lines, notes):
    accts = []
    for ln in lines:
        s = ln.rstrip("\n")
        if not s.strip():
            continue
        p = s.split(":")
        if len(p) != 7 or not p[2].isdigit() or not p[3].isdigit():
            notes.append("unparsed passwd line: %r" % s[:90])
            continue
        accts.append({"name": p[0], "pw": p[1], "uid": int(p[2]), "gid": int(p[3]),
                      "gecos": p[4], "home": p[5], "shell": p[6]})
    return accts


def _parse_group(lines, notes):
    groups = []
    for ln in lines:
        s = ln.rstrip("\n")
        if not s.strip():
            continue
        p = s.split(":")
        if len(p) != 4 or not p[2].isdigit():
            notes.append("unparsed group line: %r" % s[:90])
            continue
        groups.append({"name": p[0], "pw": p[1], "gid": int(p[2]),
                       "members": [m.strip() for m in p[3].split(",") if m.strip()]})
    return groups


def _parse_status(lines, notes):
    out = {}
    for ln in lines:
        t = ln.split()
        if len(t) < 2:
            notes.append("unparsed account_status line: %r" % ln.strip()[:90])
            continue
        code = {"PS": "P", "LK": "L"}.get(t[1], t[1])
        out[t[0]] = {"status": code, "changed": t[2] if len(t) > 2 else None}
    return out


def _parse_sshd(lines):
    out = {}
    for ln in lines:
        t = ln.strip().split(None, 1)
        if not t:
            continue
        out[t[0].lower()] = t[1].strip() if len(t) > 1 else ""
    return out


def _parse_lastlog(lines, src, notes):
    """Return {user: {"never": bool, "port", "from", "time"}}."""
    out = {}
    if src in (None, "lastlog", "lastlog2"):
        for ln in lines:
            s = ln.strip()
            if not s or s.startswith("Username"):
                continue
            name = s.split()[0]
            if "**Never logged in**" in s:
                out[name] = {"never": True, "port": None, "from": None, "time": None}
                continue
            m = LASTLOG_DATE_RE.search(s)
            if not m:
                notes.append("unparsed lastlog line: %r" % s[:90])
                continue
            pre = s[:m.start()].split()
            try:
                t = datetime.strptime(" ".join(m.group(0).split()), "%a %b %d %H:%M:%S %z %Y")
                iso = t.astimezone(timezone.utc).isoformat()
            except ValueError:
                iso = None
            out[name] = {"never": False, "port": pre[1] if len(pre) > 1 else None,
                         "from": pre[2] if len(pre) > 2 else None, "time": iso}
    else:  # `last -F -w`: newest first; local time of the host (assumed UTC)
        for ln in lines:
            s = ln.strip()
            if not s or s.startswith(("reboot", "wtmp", "btmp", "shutdown")):
                continue
            m = LAST_DATE_RE.search(s)
            if not m:
                continue
            name = s.split()[0]
            if name in out:
                continue
            pre = s[:m.start()].split()
            try:
                t = datetime.strptime(" ".join(m.group(0).split()), "%a %b %d %H:%M:%S %Y")
                iso = t.replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                iso = None
            out[name] = {"never": False, "port": pre[1] if len(pre) > 1 else None,
                         "from": pre[2] if len(pre) > 2 else None, "time": iso}
        notes.append("lastlog source is `last` (wtmp window only; times assumed UTC). "
                     "Accounts absent from wtmp are 'unknown', not 'never'.")
    return out


# ---- sudoers ---------------------------------------------------------------- #

def _join_continuations(lines):
    out, buf = [], ""
    for ln in lines:
        s = ln.rstrip()
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        out.append((buf + s).strip())
        buf = ""
    if buf.strip():
        out.append(buf.strip())
    return [x for x in out if x]


def _split_commas(s):
    return [x for x in re.split(r"(?<!\\),", s)]


def _parse_alias(s):
    """'Cmnd_Alias A = x, y : B = z' -> (type, {A: [x,y], B: [z]})."""
    typ, rest = s.split(None, 1)
    out = {}
    for part in rest.split(":"):
        if "=" not in part:
            continue
        name, vals = part.split("=", 1)
        out[name.strip()] = [v.strip() for v in _split_commas(vals) if v.strip()]
    return typ, out


def _parse_sudo_rule(s):
    if "=" not in s:
        return None
    left, right = s.split("=", 1)
    lt = left.strip().rsplit(None, 1)
    if len(lt) != 2:
        return None
    users = [u.strip() for u in _split_commas(lt[0]) if u.strip()]
    hosts = lt[1]
    rest = right.strip()
    runas = None
    tags, cmds = set(), []
    for item in _split_commas(rest):
        it = item.strip()
        m = re.match(r"^\(([^)]*)\)\s*", it)
        if m:
            runas = m.group(1).strip()
            it = it[m.end():]
        while True:
            m = re.match(r"^([A-Z_]+)\s*:\s*", it)
            if m and m.group(1) in SUDO_TAGS:
                tags.add(m.group(1))
                it = it[m.end():]
            else:
                break
        if it.strip():
            cmds.append(it.strip())
    return {"users": users, "hosts": hosts, "runas": runas, "tags": sorted(tags), "cmds": cmds}


def _parse_sudoers(lines, notes):
    stats, order, contents, n = _split_filebacked(lines)
    notes.extend(n)
    items = []
    aliases = {"User_Alias": {}, "Runas_Alias": {}, "Host_Alias": {}, "Cmnd_Alias": {}}
    for path, clines in contents.items():
        for s in _join_continuations(clines):
            norm = " ".join(s.split())
            it = {"path": path, "text": norm}
            if norm.startswith("Defaults"):
                it["type"] = "defaults"
            elif re.match(r"^(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias|Cmd_Alias)\s", norm):
                typ, al = _parse_alias(norm)
                typ = "Cmnd_Alias" if typ == "Cmd_Alias" else typ
                aliases[typ].update(al)
                it["type"] = "alias"
            elif re.match(r"^[#@]include(dir)?\s", norm):
                it["type"] = "include"
                it["target"] = norm.split(None, 1)[1].strip()
                it["is_dir"] = norm[1:].startswith("includedir")
            else:
                r = _parse_sudo_rule(norm)
                if r is None:
                    it["type"] = "unparsed"
                    notes.append("unparsed sudoers line in %s: %r" % (path, norm[:90]))
                else:
                    it["type"] = "rule"
                    it.update(r)
            items.append(it)
    return stats, contents, items, aliases


# --------------------------------------------------------------------------- #
# record + flag helpers
# --------------------------------------------------------------------------- #

def _rec(section, kind, key, content="", user=None, uid=None, group=None, path=None,
         event_time=None, time_source=None, data=None):
    return {"section": section, "kind": kind, "key": key, "entry_id": _key_id(key),
            "user": user, "uid": uid, "group": group, "path": path, "content": content,
            "event_time": event_time, "time_source": time_source,
            "data": data or {}, "flags": []}


def _flag(rec, code, severity, detail):
    rec["flags"].append({"code": code, "severity": severity, "detail": detail})


def _ack_key(code, key, detail):
    return "%s|%s|%s" % (code, key, detail)


def _ts(files, path, coll):
    st = files.get(path)
    if st:
        t = _mtime_iso(st["epoch"])
        if t:
            return t, "mtime"
    return coll, "collection"


def _expand_users(tokens, aliases, model, depth=0):
    """sudoers user-list -> (set(usernames), everyone, unresolved, groups_named)."""
    users, unresolved, groups_named = set(), [], []
    everyone = False
    if depth > 8:
        return users, everyone, ["alias recursion"], groups_named
    for t in tokens:
        if t.startswith("!"):
            continue
        if t == "ALL":
            everyone = True
        elif t in aliases.get("User_Alias", {}):
            u, e, un, g = _expand_users(aliases["User_Alias"][t], aliases, model, depth + 1)
            users |= u
            everyone = everyone or e
            unresolved += un
            groups_named += g
        elif t.startswith("%#"):
            gid = t[2:]
            names = [g["name"] for g in model["groups"] if str(g["gid"]) == gid]
            groups_named += names or [t]
            for gname in names:
                users |= model["eff"].get(gname, set())
        elif t.startswith("%"):
            gname = t[2:] if t.startswith("%:") else t[1:]
            groups_named.append(gname)
            if gname not in model["eff"]:
                unresolved.append(t)
            users |= model["eff"].get(gname, set())
        elif t.startswith("#"):
            names = [a["name"] for a in model["accounts"] if str(a["uid"]) == t[1:]]
            users |= set(names)
            if not names:
                unresolved.append(t)
        elif t.startswith("+"):
            unresolved.append(t)
        else:
            users.add(t)
    return users, everyone, unresolved, groups_named


def _runas_root_capable(runas, aliases):
    if runas is None:
        return True
    user_part = runas.split(":", 1)[0].strip()
    if user_part == "":
        return False  # (:group) -> runs as invoking user
    toks = [t.strip() for t in user_part.split(",") if t.strip()]
    for t in toks:
        if t in ("ALL", "root", "#0"):
            return True
        if t in aliases.get("Runas_Alias", {}):
            if _runas_root_capable(",".join(aliases["Runas_Alias"][t]), aliases):
                return True
    return False


def _cmd_info(cmds, aliases):
    """-> (is_all, escape_bins)."""
    is_all, esc = False, []
    flat = []
    for c in cmds:
        if c in aliases.get("Cmnd_Alias", {}):
            flat.extend(aliases["Cmnd_Alias"][c])
        else:
            flat.append(c)
    for c in flat:
        if c.startswith("!"):
            continue
        if c == "ALL":
            is_all = True
            continue
        base = os.path.basename(c.split()[0]) if c.split() else ""
        if base in SHELL_ESCAPE_BINS or re.match(r"^python[0-9.]*$", base):
            esc.append(base)
    return is_all, sorted(set(esc))


def _downgrade(sev):
    return {"high": "medium", "medium": "low", "low": "low"}.get(sev, sev)


# --------------------------------------------------------------------------- #
# top-level audit
# --------------------------------------------------------------------------- #

def _fail(msg):
    return {"ok": False, "error": msg, "records": [], "flagged": [], "info": [],
            "acknowledged": []}


def audit(text, baseline_data=None, collected_at=None, admins=None):
    if text is None or not text.strip():
        return _fail("EMPTY INPUT: no dump text was provided.")

    text, n_redacted = HASH_RE.subn("<HASH_REDACTED>", text)
    sections, order, complete, saw_marker, preamble = split_sections(text)
    if not saw_marker:
        return _fail("NO SECTION MARKERS: input has no '===SECTION ...===' lines; "
                     "this is not an account dump.")

    notes, problems = [], []
    if preamble:
        notes.append("%d line(s) before the first section marker (ignored)." % len(preamble))
    if n_redacted:
        problems.append("HASH MATERIAL IN INPUT: %d password-hash-shaped string(s) were "
                        "redacted before parsing. The collector never emits these — find out "
                        "how this dump was made." % n_redacted)

    meta = _parse_meta(sections.get("meta", []))
    if collected_at:
        coll, coll_src = collected_at, "override"
    elif _iso_from_meta(meta.get("collected_utc")):
        coll, coll_src = _iso_from_meta(meta.get("collected_utc")), "meta"
    else:
        coll, coll_src = _now_iso(), "now (dump has no collected_utc)"
    host = meta.get("host")
    cuid = meta.get("collector_uid")
    if cuid is not None and cuid != "0":
        problems.append("COLLECTOR NOT ROOT (uid %s): account_status, sudoers and "
                        "sshd_effective are unreliable or empty." % cuid)

    admin_set = set(admins or ADMIN_USERS_DEFAULT)

    # ---- parse ----
    accounts = _parse_passwd(sections.get("passwd", []), notes)
    groups = _parse_group(sections.get("group", []), notes)

    st_rc, st_err, _, st_body = _ctl(sections.get("account_status", []))
    status = _parse_status(st_body, notes)
    if "account_status" in sections:
        if st_rc not in (None, "0") or not status:
            problems.append("ACCOUNT_STATUS FAILED (rc=%s%s): password/lock state NOT examined."
                            % (st_rc, "; " + "; ".join(st_err) if st_err else ""))

    sudo_stats, sudo_contents, sudo_items, aliases = _parse_sudoers(sections.get("sudoers", []), notes)
    if "sudoers" in sections and "/etc/sudoers" not in sudo_contents:
        problems.append("SUDOERS INCOMPLETE: no /etc/sudoers contents in dump — sudo rules NOT examined.")

    sshd_rc, sshd_err, _, sshd_body = _ctl(sections.get("sshd_effective", []))
    sshd = _parse_sshd(sshd_body)
    if "sshd_effective" in sections and (sshd_rc not in (None, "0") or not sshd):
        problems.append("SSHD_EFFECTIVE FAILED (rc=%s%s): sshd settings NOT examined."
                        % (sshd_rc, "; " + "; ".join(sshd_err) if sshd_err else ""))

    ll_rc, ll_err, ll_src, ll_body = _ctl(sections.get("lastlog", []))
    lastlog = _parse_lastlog(ll_body, ll_src, notes)
    if "lastlog" in sections and not lastlog:
        problems.append("LASTLOG EMPTY: last-login data NOT examined.")

    files = {}
    for path, st in sudo_stats.items():
        files[path] = st
    af_unparsed = 0
    for ln in sections.get("account_files", []):
        if not ln.strip():
            continue
        st = parse_stat_line(ln)
        if st:
            files[st["path"]] = st
        else:
            af_unparsed += 1
    if af_unparsed:
        notes.append("%d unparsed line(s) in account_files." % af_unparsed)
    if "account_files" in sections:
        miss = [p for p in KEY_FILES if p not in files]
        if miss:
            problems.append("ACCOUNT_FILES MISSING STAT: %s — permissions NOT examined for these."
                            % ", ".join(miss))

    if "passwd" in sections and not accounts:
        problems.append("PASSWD EMPTY: no accounts parsed.")
    if "group" in sections and not groups:
        problems.append("GROUP EMPTY: no groups parsed.")

    missing = [s for s in EXPECTED_SECTIONS if s not in sections]
    extra = [s for s in order if s not in EXPECTED_SECTIONS]

    # ---- model ----
    eff = {}
    for g in groups:
        mem = set(g["members"]) | {a["name"] for a in accounts if a["gid"] == g["gid"]}
        eff.setdefault(g["name"], set()).update(mem)
    model = {"accounts": accounts, "groups": groups, "eff": eff}
    user_groups = {}
    for gname, mem in eff.items():
        for u in mem:
            user_groups.setdefault(u, set()).add(gname)

    t_passwd = _ts(files, "/etc/passwd", coll)
    t_group = _ts(files, "/etc/group", coll)
    t_shadow = _ts(files, "/etc/shadow", coll)

    records = []
    acct_rec = {}

    # ---- accounts ----
    seen_names = {}
    uid_map, gid_map = {}, {}
    for a in accounts:
        uid_map.setdefault(a["uid"], []).append(a["name"])
    for g in groups:
        gid_map.setdefault(g["gid"], []).append(g["name"])

    for a in accounts:
        n = a["name"]
        seen_names[n] = seen_names.get(n, 0) + 1
        key = "user:%s" % n if seen_names[n] == 1 else "user:%s#%d" % (n, seen_names[n])
        pw_marker = a["pw"] if a["pw"] in ("x", "*", "!", "!!", "") else "<HASH_MASKED>"
        data = {"uid": a["uid"], "gid": a["gid"], "gecos": a["gecos"], "home": a["home"],
                "shell": a["shell"], "pw_field": pw_marker}
        r = _rec("passwd", "account", key, content="%s:%s:%d:%d:%s:%s" % (
            n, pw_marker, a["uid"], a["gid"], a["home"], a["shell"]),
            user=n, uid=a["uid"], event_time=t_passwd[0], time_source=t_passwd[1], data=data)
        records.append(r)
        if seen_names[n] == 1:
            acct_rec[n] = r
        else:
            _flag(r, "duplicate_uid_or_gid", "high", "account name '%s' appears more than once" % n)

        svc, sysacct = _is_service(n), _is_system(a)
        if a["uid"] == 0 and n != "root":
            _flag(r, "uid0_non_root", "high", "account '%s' has UID 0 (full root)" % n)
        if len(uid_map.get(a["uid"], [])) > 1:
            _flag(r, "duplicate_uid_or_gid", "high", "UID %d shared by: %s"
                  % (a["uid"], ", ".join(sorted(uid_map[a["uid"]]))))
        if (svc or sysacct) and n != "root" and _login_capable(a["shell"]):
            _flag(r, "service_account_login_shell", "medium",
                  "%s account has login shell %r (expected nologin/false)"
                  % ("service" if svc else "system", a["shell"] or "(empty = /bin/sh)"))
        if pw_marker == "<HASH_MASKED>" or "<HASH_REDACTED>" in a["pw"]:
            _flag(r, "password_hash_in_passwd", "high",
                  "password hash stored in world-readable /etc/passwd (value masked)")
        elif a["pw"] == "":
            _flag(r, "empty_passwd_field", "high",
                  "empty password field in /etc/passwd: no password required")
        for gname in PRIV_GROUPS:
            if n in eff.get(gname, set()) and n not in admin_set \
                    and (gname, n) not in STOCK_GROUP_MEMBERS:
                how = "explicit" if any(n in g["members"] for g in groups if g["name"] == gname) \
                    else "primary group"
                extra_d = " (root-equivalent)" if gname in ROOT_EQUIV_GROUPS else ""
                _flag(r, "broad_sudo_grant", "medium",
                      "%s%s is in privileged group '%s'%s via %s membership"
                      % ("service account " if svc else ("system account " if sysacct else "user "),
                         n, gname, extra_d, how))

    # shared home among non-stock accounts (info): shared ~/.ssh/authorized_keys path
    homes = {}
    for a in accounts:
        if a["uid"] >= 1000 and a["uid"] != NOBODY_UID or _is_service(a["name"]):
            homes.setdefault(a["home"], []).append(a["name"])
    for h, names in homes.items():
        if len(names) > 1 and h not in ("/", "/nonexistent", "/var/empty"):
            for nme in names:
                if nme in acct_rec:
                    _flag(acct_rec[nme], "shared_home_dir", "info",
                          "home %s shared by %s — they share one ~/.ssh/authorized_keys path"
                          % (h, ", ".join(sorted(names))))

    # ---- groups ----
    for g in groups:
        key = "group:%s" % g["name"]
        r = _rec("group", "group", key, content="%s:%d:%s" % (g["name"], g["gid"], ",".join(g["members"])),
                 group=g["name"], event_time=t_group[0], time_source=t_group[1],
                 data={"gid": g["gid"], "members": sorted(g["members"]),
                       "effective": sorted(eff.get(g["name"], set()))})
        if len(gid_map.get(g["gid"], [])) > 1:
            _flag(r, "duplicate_uid_or_gid", "high", "GID %d shared by groups: %s"
                  % (g["gid"], ", ".join(sorted(gid_map[g["gid"]]))))
        if g["pw"] not in ("x", "*", "!", "!!", ""):
            _flag(r, "password_hash_in_passwd", "high", "group password hash in /etc/group (masked)")
        records.append(r)

    # ---- account status ----
    acct_by_name = {a["name"]: a for a in accounts}
    for n, s in status.items():
        a = acct_by_name.get(n)
        r = _rec("account_status", "status", "status:%s" % n,
                 content="%s %s %s" % (n, s["status"], s["changed"] or ""),
                 user=n, uid=a["uid"] if a else None,
                 event_time=t_shadow[0], time_source=t_shadow[1],
                 data={"status": s["status"], "pw_changed": s["changed"]})
        if s["status"] == "NP":
            _flag(r, "empty_password", "high", "passwd -S reports NO PASSWORD (NP) for '%s'" % n)
        elif s["status"] == "P" and n != "root" and (_is_service(n) or (a and _is_system(a))):
            _flag(r, "usable_password_on_service_account", "medium",
                  "%s account '%s' has a usable password (P)"
                  % ("service" if _is_service(n) else "system", n))
        records.append(r)
    if status:
        for a in accounts:
            if a["name"] not in status:
                notes.append("no passwd -S status for '%s'." % a["name"])

    # ---- sudoers ----
    for it in sudo_items:
        t_ev, t_src = _ts(files, it["path"], coll)
        t_src = "inherited" if t_src == "mtime" else t_src
        kind = "sudo_rule" if it["type"] == "rule" else "sudo_directive"
        r = _rec("sudoers", kind, "sudo:%s:%s" % (it["path"], it["text"]), content=it["text"],
                 path=it["path"], event_time=t_ev, time_source=t_src,
                 data={k: v for k, v in it.items() if k not in ("path", "text")})
        records.append(r)
        base = os.path.basename(it["path"])
        if it["path"].startswith(AUDITED_INCLUDEDIR + "/") and ("." in base or base.endswith("~")):
            notes.append("sudo ignores %s (name has '.' or ends '~'); its rules are recorded anyway."
                         % it["path"])

        if it["type"] == "defaults" and "!authenticate" in it["text"]:
            scope = it["text"].split(None, 1)[0]
            _flag(r, "nopasswd_sudo", "high",
                  "'%s !authenticate' disables password prompts for %s"
                  % (scope, "EVERY sudo user" if scope == "Defaults" else scope.split(":", 1)[-1]))
        if it["type"] == "include":
            tgt = it["target"]
            ok = (it["is_dir"] and tgt.rstrip("/") == AUDITED_INCLUDEDIR) or \
                 (not it["is_dir"] and (tgt.startswith(AUDITED_INCLUDEDIR + "/") or tgt == "/etc/sudoers"))
            if not ok:
                _flag(r, "sudo_include_unaudited", "medium",
                      "sudoers pulls rules from %s, which this collector does not read" % tgt)
        if it["type"] != "rule":
            continue

        users, everyone, unresolved, gnamed = _expand_users(it["users"], aliases, model)
        root_cap = _runas_root_capable(it["runas"], aliases)
        is_all, esc = _cmd_info(it["cmds"], aliases)
        principal = ",".join(it["users"])
        runas_txt = "(%s)" % it["runas"] if it["runas"] is not None else "(root)"
        root_only = set(it["users"]) == {"root"}
        if unresolved:
            notes.append("sudo rule in %s names unresolved principal(s) %s: %r"
                         % (it["path"], ", ".join(unresolved), it["text"][:70]))

        if "NOPASSWD" in it["tags"]:
            if root_only:
                _flag(r, "nopasswd_sudo", "info",
                      "NOPASSWD for root itself (cloud-init default) — no new path to root")
            else:
                sev = "high" if (is_all or esc) else "medium"
                d = "NOPASSWD %s for %s as %s" % (
                    "ALL commands" if is_all else "scoped: " + ", ".join(it["cmds"])[:80],
                    principal, runas_txt)
                if esc and not is_all:
                    d += "; shell-escape-capable: %s" % ", ".join(esc)
                if not root_cap:
                    sev = _downgrade(sev)
                    d += "; runas excludes root"
                if everyone:
                    sev = "high"
                    d += "; applies to ALL users"
                _flag(r, "nopasswd_sudo", sev, d)

        if everyone:
            _flag(r, "broad_sudo_grant", "high", "sudo rule grants to ALL users: %r" % it["text"][:80])
        else:
            outsiders = sorted(u for u in users if u not in admin_set)
            if outsiders:
                svcs = [u for u in outsiders if _is_service(u)]
                _flag(r, "broad_sudo_grant", "medium",
                      "sudo via %s reaches non-admin %s%s"
                      % (principal, ", ".join(outsiders),
                         (" (service: %s)" % ", ".join(svcs)) if svcs else ""))

    # ---- sshd ----
    for k, v in sshd.items():
        r = _rec("sshd_effective", "sshd_setting", "sshd:%s" % k, content="%s %s" % (k, v),
                 event_time=coll, time_source="collection", data={"value": v})
        lv = v.lower()
        if k == "permitrootlogin":
            if lv == "yes":
                _flag(r, "sshd_root_login", "high", "PermitRootLogin yes (password or key)")
            elif lv in ("prohibit-password", "without-password"):
                _flag(r, "sshd_root_login", "medium", "PermitRootLogin %s (root by key)" % v)
            elif lv == "forced-commands-only":
                _flag(r, "sshd_root_login", "low", "PermitRootLogin forced-commands-only")
        elif k == "passwordauthentication" and lv == "yes":
            _flag(r, "sshd_password_auth", "medium", "PasswordAuthentication yes")
        elif k == "permitemptypasswords" and lv == "yes":
            _flag(r, "permit_empty_passwords", "high", "PermitEmptyPasswords yes")
        elif k == "kbdinteractiveauthentication" and lv == "yes":
            _flag(r, "sshd_password_auth", "low",
                  "KbdInteractiveAuthentication yes (password via PAM)")
        records.append(r)

    # ---- lastlog ----
    for n, L in lastlog.items():
        r = _rec("lastlog", "last_login", "lastlog:%s" % n,
                 content=("never" if L["never"] else "%s from %s at %s" % (L["port"], L["from"], L["time"])),
                 user=n, uid=acct_by_name[n]["uid"] if n in acct_by_name else None,
                 event_time=None if L["never"] else L["time"],
                 time_source=None if L["never"] or not L["time"] else "event",
                 data=dict(L))
        if n == "root" and not L["never"]:
            _flag(r, "root_login_recorded", "info",
                  "root last logged in interactively from %s at %s" % (L["from"], L["time"]))
        records.append(r)
    if ll_src != "last":
        for a in accounts:
            L = lastlog.get(a["name"])
            if L and L["never"] and _login_capable(a["shell"]) and a["name"] in acct_rec:
                _flag(acct_rec[a["name"]], "never_logged_in_with_shell", "low",
                      "login shell %r but never logged in" % (a["shell"] or "(empty = /bin/sh)"))

    # ---- files ----
    for path in sorted(files):
        st = files[path]
        pi = _perm_int(st["perms"])
        r = _rec("account_files", "file", "file:%s" % path,
                 content="%s %s %s" % (st["owner"], st["perms"], st.get("ftype") or ""),
                 path=path, event_time=_mtime_iso(st["epoch"]), time_source="mtime",
                 data={"owner": st["owner"], "perms": st["perms"], "ftype": st.get("ftype"),
                       "epoch": st["epoch"]})
        bad = []
        if pi is not None:
            if path in SENSITIVE_SHADOW:
                if pi & 0o004:
                    bad.append("readable by other")
                if pi & 0o022:
                    bad.append("writable by group/other")
                if st["owner"] != "root":
                    bad.append("owner %s" % st["owner"])
            elif path in SENSITIVE_DB:
                if pi & 0o022:
                    bad.append("writable by group/other")
                if st["owner"] != "root":
                    bad.append("owner %s (writable by non-root)" % st["owner"])
            elif path == AUDITED_INCLUDEDIR:
                if pi & 0o022:
                    bad.append("directory writable by group/other")
                if st["owner"] != "root":
                    bad.append("directory owner %s" % st["owner"])
            elif path == "/etc/sudoers" or path.startswith(AUDITED_INCLUDEDIR + "/"):
                if (pi & 0o7777) not in (0o440, 0o640) or st["owner"] != "root":
                    bad.append("expected root-owned 0440/0640, got %s %s" % (st["owner"], st["perms"]))
        if bad:
            _flag(r, "sensitive_file_perms", "high", "%s: %s" % (path, "; ".join(bad)))
        records.append(r)

    # ---- collect findings, apply acknowledgements ----
    acks = set((baseline_data or {}).get("acknowledged", []))
    flagged, info, acked = [], [], []
    for r in records:
        for f in r["flags"]:
            item = dict(f)
            item.update({"key": r["key"], "kind": r["kind"], "user": r["user"], "uid": r["uid"],
                         "group": r["group"], "path": r["path"],
                         "event_time": r["event_time"], "time_source": r["time_source"],
                         "ack_key": _ack_key(f["code"], r["key"], f["detail"])})
            if f["severity"] == "info":
                info.append(item)
            elif item["ack_key"] in acks:
                acked.append(item)
            else:
                flagged.append(item)
    flagged.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["code"], x["key"]))

    sev = {"high": 0, "medium": 0, "low": 0}
    for f in flagged:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1

    vantage_ok = complete and not missing and not problems
    return {
        "ok": True, "error": None, "version": VERSION, "host": host,
        "complete": complete, "vantage_ok": vantage_ok,
        "sections_found": order, "sections_missing": missing, "sections_extra": extra,
        "problems": problems, "notes": notes,
        "collection_time": coll, "collection_time_source": coll_src,
        "admins": sorted(admin_set), "record_count": len(records), "records": records,
        "flagged": flagged, "info": info, "acknowledged": acked, "severity_counts": sev,
        "hashes_redacted": n_redacted,
    }


# --------------------------------------------------------------------------- #
# baseline / compare
# --------------------------------------------------------------------------- #

def build_baseline(text, path=None, collected_at=None, admins=None, ack=False):
    res = audit(text, collected_at=collected_at, admins=admins)
    if not res["ok"]:
        return {"ok": False, "path": None, "count": 0, "error": res["error"]}
    data = {
        "version": VERSION, "created": _now_iso(), "host": res["host"],
        "collection_time": res["collection_time"], "complete": res["complete"],
        "vantage_ok": res["vantage_ok"], "admins": res["admins"],
        "acknowledged": sorted(f["ack_key"] for f in res["flagged"]) if ack else [],
        "records": {
            r["key"]: {"kind": r["kind"], "content": r["content"], "data": r["data"],
                       "user": r["user"], "uid": r["uid"], "group": r["group"], "path": r["path"],
                       "event_time": r["event_time"], "time_source": r["time_source"]}
            for r in res["records"]
        },
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
    return {"ok": True, "path": target, "count": len(data["records"]),
            "acknowledged": len(data["acknowledged"]), "incomplete": not res["vantage_ok"],
            "problems": res["problems"] + (["no ===END=== terminator"] if not res["complete"] else [])
                        + (["missing sections: " + ", ".join(res["sections_missing"])]
                           if res["sections_missing"] else []),
            "error": None}


def _diff_fields(b, c, fields):
    return {f: {"was": b.get(f), "now": c.get(f)} for f in fields if b.get(f) != c.get(f)}


def compare(text, baseline_path=None, collected_at=None, admins=None):
    target = _resolve_path(baseline_path, BASELINE_DEFAULT)
    try:
        with open(target) as fh:
            base = json.load(fh)
    except Exception as e:
        return {"ok": False, "error": "cannot read baseline %s: %s" % (target, e)}

    res = audit(text, baseline_data=base, collected_at=collected_at,
                admins=admins or base.get("admins"))
    if not res["ok"]:
        return {"ok": False, "error": res["error"]}

    B = base.get("records", {})
    C = {r["key"]: r for r in res["records"]}

    def kind_keys(src, kind):
        return {k for k, v in src.items() if v["kind"] == kind}

    def ent(k, r, **extra):
        e = {"key": k, "user": r.get("user"), "uid": r.get("uid"), "group": r.get("group"),
             "path": r.get("path"), "content": r.get("content"),
             "event_time": r.get("event_time"), "time_source": r.get("time_source")}
        e.update(extra)
        return e

    out = {"accounts": {"added": [], "removed": [], "modified": []},
           "groups": {"added": [], "removed": [], "membership": [], "modified": []},
           "sudo": {"added": [], "removed": []},
           "sshd": {"added": [], "removed": [], "changed": []},
           "files": {"added": [], "removed": [], "modified": []},
           "logins": []}

    # accounts (+ status folded in)
    for k in sorted(kind_keys(C, "account") - kind_keys(B, "account")):
        out["accounts"]["added"].append(ent(k, C[k]))
    for k in sorted(kind_keys(B, "account") - kind_keys(C, "account")):
        out["accounts"]["removed"].append(ent(k, B[k], event_time=C.get("file:/etc/passwd", {}).get("event_time"),
                                              time_source="mtime"))
    for k in sorted(kind_keys(B, "account") & kind_keys(C, "account")):
        ch = _diff_fields(B[k]["data"], C[k]["data"], ("uid", "gid", "gecos", "home", "shell", "pw_field"))
        if ch:
            out["accounts"]["modified"].append(ent(k, C[k], changes=ch))
    for k in sorted(kind_keys(B, "status") | kind_keys(C, "status")):
        b, c = B.get(k), C.get(k)
        if b and c and b["data"].get("status") != c["data"].get("status"):
            out["accounts"]["modified"].append(ent(k, c, changes={"status": {
                "was": b["data"].get("status"), "now": c["data"].get("status")}}))

    # groups
    for k in sorted(kind_keys(C, "group") - kind_keys(B, "group")):
        out["groups"]["added"].append(ent(k, C[k]))
    for k in sorted(kind_keys(B, "group") - kind_keys(C, "group")):
        out["groups"]["removed"].append(ent(k, B[k], event_time=C.get("file:/etc/group", {}).get("event_time"),
                                            time_source="mtime"))
    for k in sorted(kind_keys(B, "group") & kind_keys(C, "group")):
        bm, cm = set(B[k]["data"].get("members", [])), set(C[k]["data"].get("members", []))
        if bm != cm:
            out["groups"]["membership"].append(ent(k, C[k], added_members=sorted(cm - bm),
                                                   removed_members=sorted(bm - cm)))
        ch = _diff_fields(B[k]["data"], C[k]["data"], ("gid",))
        if ch:
            out["groups"]["modified"].append(ent(k, C[k], changes=ch))

    # sudo (rules + directives; key includes normalized text)
    for kind in ("sudo_rule", "sudo_directive"):
        for k in sorted(kind_keys(C, kind) - kind_keys(B, kind)):
            out["sudo"]["added"].append(ent(k, C[k], kind=kind))
        for k in sorted(kind_keys(B, kind) - kind_keys(C, kind)):
            pth = B[k].get("path")
            fe = C.get("file:%s" % pth) or C.get("file:%s" % AUDITED_INCLUDEDIR) or {}
            out["sudo"]["removed"].append(ent(k, B[k], kind=kind, event_time=fe.get("event_time"),
                                              time_source="mtime" if fe else None))

    # sshd
    for k in sorted(kind_keys(C, "sshd_setting") - kind_keys(B, "sshd_setting")):
        out["sshd"]["added"].append(ent(k, C[k]))
    for k in sorted(kind_keys(B, "sshd_setting") - kind_keys(C, "sshd_setting")):
        out["sshd"]["removed"].append(ent(k, B[k], event_time=res["collection_time"],
                                          time_source="collection"))
    for k in sorted(kind_keys(B, "sshd_setting") & kind_keys(C, "sshd_setting")):
        if B[k]["data"].get("value") != C[k]["data"].get("value"):
            out["sshd"]["changed"].append(ent(k, C[k], was=B[k]["data"].get("value"),
                                              now=C[k]["data"].get("value")))

    # file metadata
    for k in sorted(kind_keys(C, "file") - kind_keys(B, "file")):
        out["files"]["added"].append(ent(k, C[k]))
    for k in sorted(kind_keys(B, "file") - kind_keys(C, "file")):
        out["files"]["removed"].append(ent(k, B[k], event_time=res["collection_time"],
                                           time_source="collection"))
    for k in sorted(kind_keys(B, "file") & kind_keys(C, "file")):
        ch = _diff_fields(B[k]["data"], C[k]["data"], ("owner", "perms", "ftype", "epoch"))
        if ch:
            if "epoch" in ch:
                ch["mtime"] = {"was": _mtime_iso(ch["epoch"]["was"]), "now": _mtime_iso(ch["epoch"]["now"])}
                del ch["epoch"]
            out["files"]["modified"].append(ent(k, C[k], changes=ch))

    # logins (context, not drift)
    for k in sorted(kind_keys(C, "last_login")):
        b = B.get(k)
        if not b or b.get("event_time") != C[k]["event_time"]:
            if C[k]["event_time"]:
                out["logins"].append(ent(k, C[k]))

    drift = sum(len(v) for sec, d in out.items() if sec != "logins" for v in d.values())
    r = {"ok": True, "error": None, "baseline": target, "baseline_created": base.get("created"),
         "baseline_collection_time": base.get("collection_time"), "host": res["host"],
         "baseline_host": base.get("host"), "collection_time": res["collection_time"],
         "complete": res["complete"], "vantage_ok": res["vantage_ok"],
         "problems": res["problems"], "sections_missing": res["sections_missing"],
         "drift_count": drift, "flagged": res["flagged"], "info": res["info"],
         "acknowledged": res["acknowledged"], "severity_counts": res["severity_counts"]}
    r.update(out)
    if base.get("host") and res["host"] and base.get("host") != res["host"]:
        r["problems"] = r["problems"] + ["HOST MISMATCH: baseline is %s, dump is %s"
                                         % (base.get("host"), res["host"])]
        r["vantage_ok"] = False
    return r


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


def _finding_lines(items, label_sev=True):
    out = []
    for f in items:
        tgt = f.get("user") or f.get("group") or f.get("path") or f["key"]
        meta = []
        if f.get("uid") is not None:
            meta.append("uid=%s" % f["uid"])
        if f.get("path") and f.get("path") != tgt:
            meta.append(f["path"])
        meta.append("@%s (%s)" % (f.get("event_time"), f.get("time_source")))
        out.append("  [%-6s] %-34s %s" % (f["severity"].upper(), f["code"], tgt))
        out.append("           %s" % "  ".join(meta))
        out.append("           -> %s" % f["detail"])
    return out


def format_human(res):
    if not res.get("ok"):
        return "%s\n!! AUDIT FAILED: %s\n%s" % (_BANNER, res.get("error"), _BANNER)
    L = []
    sev = res["severity_counts"]
    nflag = len(res["flagged"])
    verdict = ("%d flagged (%d HIGH / %d MED / %d LOW)" % (nflag, sev["high"], sev["medium"], sev["low"])
               if nflag else "nothing flagged")
    L.append("LIAO ACCOUNT AUDIT  v%s   host=%s   collected=%s (%s)"
             % (VERSION, res["host"], res["collection_time"], res["collection_time_source"]))
    L.append("RESULT: %s   |   dump %s   |   vantage %s"
             % (verdict, "COMPLETE" if res["complete"] else "INCOMPLETE",
                "OK" if res["vantage_ok"] else "DEGRADED"))
    L.append("admins (not flagged for sudo): %s" % ", ".join(res["admins"]))
    L.append("")
    L += _loud_block(res)
    if res["sections_extra"]:
        L.append("?? Unexpected sections (not parsed): " + ", ".join(res["sections_extra"]))
    L.append("Parsed %d records across %d sections: %s"
             % (res["record_count"], len(res["sections_found"]), ", ".join(res["sections_found"])))
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
            L.append("  ~ %s  %s" % (f["code"], f.get("user") or f.get("group") or f.get("path") or f["key"]))
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
    L.append("Vantage limit: reflects ONLY this dump, at collection time. Flags are leads to "
             "verify, not confirmed compromise.")
    return "\n".join(L)


def format_baseline(res):
    if not res["ok"]:
        return "%s\n!! BASELINE FAILED: %s\n%s" % (_BANNER, res["error"], _BANNER)
    L = ["BASELINE WRITTEN: %s" % res["path"],
         "  %d records snapshotted; %d flag(s) acknowledged." % (res["count"], res["acknowledged"])]
    if res.get("incomplete"):
        L.append(_BANNER)
        L.append("!! WARNING: source dump vantage was DEGRADED — baseline is partial:")
        for p in res.get("problems", []):
            L.append("!!   " + p)
        L.append(_BANNER)
    L += [_BANNER,
          "!! COPY THIS BASELINE OFF-HOST NOW. A baseline that lives only on the",
          "!! audited host can be edited by whatever you are hunting. Store a copy",
          "!! somewhere the target cannot reach, and diff against that copy.",
          _BANNER]
    return "\n".join(L)


def _ch_txt(ch):
    return "; ".join("%s %s -> %s" % (k, v["was"], v["now"]) for k, v in ch.items())


def format_compare(res):
    if not res["ok"]:
        return "%s\n!! COMPARE FAILED: %s\n%s" % (_BANNER, res["error"], _BANNER)
    L = ["COMPARE vs baseline: %s" % res["baseline"],
         "  baseline collected %s   |   dump collected %s" % (res["baseline_collection_time"], res["collection_time"]),
         "  dump %s   |   vantage %s   |   drift items: %d"
         % ("COMPLETE" if res["complete"] else "INCOMPLETE",
            "OK" if res["vantage_ok"] else "DEGRADED", res["drift_count"]), ""]
    L += _loud_block(res)

    def at(e):
        return "@%s (%s)" % (e.get("event_time"), e.get("time_source"))

    a = res["accounts"]
    if any(a.values()):
        L.append("ACCOUNTS")
        for e in a["added"]:
            L.append("  + %-18s %s  %s" % (e["user"], e["content"], at(e)))
        for e in a["removed"]:
            L.append("  - %-18s %s  %s" % (e["user"], e["content"], at(e)))
        for e in a["modified"]:
            L.append("  ~ %-18s %s  %s" % (e["user"], _ch_txt(e["changes"]), at(e)))
        L.append("")
    g = res["groups"]
    if any(g.values()):
        L.append("GROUPS")
        for e in g["added"]:
            L.append("  + %-18s %s  %s" % (e["group"], e["content"], at(e)))
        for e in g["removed"]:
            L.append("  - %-18s %s  %s" % (e["group"], e["content"], at(e)))
        for e in g["membership"]:
            parts = (["+" + m for m in e["added_members"]] + ["-" + m for m in e["removed_members"]])
            L.append("  ~ %-18s members %s  %s" % (e["group"], " ".join(parts), at(e)))
        for e in g["modified"]:
            L.append("  ~ %-18s %s  %s" % (e["group"], _ch_txt(e["changes"]), at(e)))
        L.append("")
    s = res["sudo"]
    if any(s.values()):
        L.append("SUDO")
        for e in s["added"]:
            L.append("  + %s: %s  %s" % (e["path"], e["content"], at(e)))
        for e in s["removed"]:
            L.append("  - %s: %s  %s" % (e["path"], e["content"], at(e)))
        L.append("")
    d = res["sshd"]
    if any(d.values()):
        L.append("SSHD")
        for e in d["added"]:
            L.append("  + %s  %s" % (e["content"], at(e)))
        for e in d["removed"]:
            L.append("  - %s  %s" % (e["content"], at(e)))
        for e in d["changed"]:
            L.append("  ~ %s: %s -> %s  %s" % (e["key"][5:], e["was"], e["now"], at(e)))
        L.append("")
    f = res["files"]
    if any(f.values()):
        L.append("FILE METADATA")
        for e in f["added"]:
            L.append("  + %s  %s  %s" % (e["path"], e["content"], at(e)))
        for e in f["removed"]:
            L.append("  - %s  %s" % (e["path"], at(e)))
        for e in f["modified"]:
            L.append("  ~ %s  %s" % (e["path"], _ch_txt(e["changes"])))
        L.append("")
    if res["logins"]:
        L.append("LOGINS since baseline (context, not drift)")
        for e in res["logins"]:
            L.append("  %-18s %s" % (e["user"], e["content"]))
        L.append("")
    if res["flagged"]:
        sev = res["severity_counts"]
        L.append("CURRENT FLAGS not acknowledged in baseline: %d (%d HIGH / %d MED / %d LOW)"
                 % (len(res["flagged"]), sev["high"], sev["medium"], sev["low"]))
        L += _finding_lines(res["flagged"])
        L.append("")
    if res["acknowledged"]:
        L.append("Acknowledged flags still present (suppressed): %d" % len(res["acknowledged"]))
        L.append("")
    if not res["drift_count"] and not res["flagged"]:
        if res["vantage_ok"]:
            L.append("No drift and nothing flagged from this vantage vs the baseline.")
        else:
            L.append("No drift in what parsed — vantage DEGRADED, NOT an all-clear.")
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# collector install chunks (mobile terminals truncate long pastes)
# --------------------------------------------------------------------------- #

def collector_chunks(dest="~/collect_accounts.sh"):
    lines = COLLECT_CMD.rstrip("\n").split("\n")
    cuts = [i for i, ln in enumerate(lines) if ln.startswith('echo "===SECTION account_status')
            or ln.startswith('echo "===SECTION sshd_effective')]
    bounds = [0] + [c - 1 for c in cuts] + [len(lines)]  # cut before the blank line
    parts = [lines[bounds[i]:bounds[i + 1]] for i in range(len(bounds) - 1)]
    out = []
    for i, p in enumerate(parts):
        op = ">" if i == 0 else ">>"
        out.append("# chunk %d/%d  (wait for the $ prompt before the next)" % (i + 1, len(parts)))
        out.append("cat %s %s <<'EOF'" % (op, dest))
        out.extend(p)
        out.append("EOF")
        out.append("")
    sha = hashlib.sha256(COLLECT_CMD.encode()).hexdigest()[:16]
    out.append("# verify: expect %d lines, hash %s, SYNTAX_OK" % (len(lines), sha))
    out.append("wc -l %s; sha256sum %s | cut -c1-16; sh -n %s && echo SYNTAX_OK" % (dest, dest, dest))
    out.append("# run (TYPE this, don't paste it — a paste can land at the sudo prompt):")
    out.append("sudo sh %s > ~/acct.txt; wc -l ~/acct.txt; tail -1 ~/acct.txt" % dest)
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
        print("LIAO ACCOUNT AUDIT  (read-only, owned scope)")
        print(" 1) Audit    — paste a dump")
        print(" 2) Audit    — from a file path")
        print(" 3) Baseline — build from a pasted dump")
        print(" 4) Compare  — pasted dump vs baseline")
        print(" 5) Collector — print the collection script")
        print(" 6) Collector — print paste-safe install chunks")
        print(" 7) Baseline + acknowledge all current flags (pasted dump)")
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
        elif c in ("3", "7"):
            t = _read_paste()
            p = input("baseline path [blank=default %s]: " % BASELINE_DEFAULT).strip() or None
            print(format_baseline(build_baseline(t, p, ack=(c == "7"))))
        elif c == "4":
            t = _read_paste()
            p = input("baseline path [blank=default %s]: " % BASELINE_DEFAULT).strip() or None
            print(format_compare(compare(t, p)))
        elif c == "5":
            print(COLLECT_CMD)
        elif c == "6":
            print(collector_chunks())
        else:
            print("?")


_HELP = """account_audit.py v%s — Liao read-only account & privilege auditor

  interactive menu:    python3 account_audit.py
  audit a file:        python3 account_audit.py DUMP.txt [--json] [--baseline BASE.json]
  audit via stdin:     sudo sh collect_accounts.sh | python3 account_audit.py --stdin [--json]
  build a baseline:    python3 account_audit.py --build-baseline BASE.json [--ack] (DUMP.txt | --stdin)
  compare to baseline: python3 account_audit.py --compare BASE.json (DUMP.txt | --stdin)
  print collector:     python3 account_audit.py --collect | --collect-chunks
  options:             --json  --admins a,b  --collected-at <ISO8601>  --version  -h/--help
  --ack                acknowledge (suppress) every current flag in the new baseline
  --baseline B         apply B's acknowledgements to a plain audit

exit codes: 0 clean · 1 flagged/drift · 2 error · 3 incomplete input/vantage
""" % VERSION

VALUE_FLAGS = {"--compare", "--build-baseline", "--collected-at", "--admins", "--baseline"}


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
    admins = [x.strip() for x in val("--admins").split(",") if x.strip()] if val("--admins") else None

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
        r = build_baseline(text, val("--build-baseline"), collected, admins, ack="--ack" in args)
        print(json.dumps(r, indent=2) if as_json else format_baseline(r))
        if not r["ok"]:
            return 2
        return 3 if r.get("incomplete") else 0

    if "--compare" in args:
        if text is None:
            text = sys.stdin.read()
        r = compare(text, val("--compare"), collected, admins)
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
    r = audit(text, baseline_data=base, collected_at=collected, admins=admins)
    print(json.dumps(r, indent=2, default=str) if as_json else format_human(r))
    return _exit_for(r)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
