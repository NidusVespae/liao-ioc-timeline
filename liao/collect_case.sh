#!/bin/sh
# /opt/liao/collect_case.sh  v1  -  Liao case collector (run only on hosts you own).
# Runs as root via liao-collect.service. Read-only on the host; writes only a new
# case folder under /var/lib/liao/cases. Never prints or stores secrets.
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LC_ALL=C; export LC_ALL
TZ=UTC; export TZ
umask 077
set -u

OPT=/opt/liao
BASE=/var/lib/liao/baselines
ROOT=/var/lib/liao/cases
CONF=/etc/liao/liao.conf

# Optional site config (sourced as root, so it must be root-owned and not
# group/world-writable). See etc/liao.conf.example.
if [ -f "$CONF" ]; then
  case "$(stat -c '%U %a' "$CONF")" in
    "root "[0-7][0-5][0-5]|"root "[0-7][0-5][0-4]) . "$CONF" ;;
    *) echo "collect_case: ignoring $CONF (must be root-owned, not group/world-writable)" >&2 ;;
  esac
fi
OWNER=${LIAO_OWNER:-svc-liao}
KEEP=${LIAO_KEEP_CASES:-30}
LIAO_FIM_EXCLUDE=${LIAO_FIM_EXCLUDE:-}
export LIAO_FIM_EXCLUDE
PY="python3 -E -s -B"

[ "$(id -u)" = 0 ] || { echo "collect_case: must run as root" >&2; exit 2; }
[ -d "$ROOT" ] && [ ! -L "$ROOT" ] || { echo "collect_case: $ROOT missing" >&2; exit 2; }

CID=$(date -u +%Y%m%dT%H%M%SZ)
COLL=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CASE=$ROOT/$CID
mkdir "$CASE" || { echo "collect_case: cannot create $CASE" >&2; exit 2; }
RCS=$CASE/collector_rc.txt
: > "$RCS"

# cap FILE cmd...   -> stdout to $CASE/FILE, record rc + first stderr lines
cap() {
  f=$1; shift
  "$@" > "$CASE/$f" 2> "$CASE/.stderr"
  rc=$?
  e=$(head -n 3 "$CASE/.stderr" | tr '\n' ' ' | cut -c1-300)
  echo "$f rc=$rc${e:+ stderr: $e}" >> "$RCS"
  rm -f "$CASE/.stderr"
  return 0
}

# 1. process table + sockets
cap ps.txt ps -eo pid,ppid,user,lstart,stat,pcpu,pmem,args
cap netstat.txt ss -tunap

# 2. auth log (previous rotation + current)
if [ -r /var/log/auth.log ]; then
  if [ -r /var/log/auth.log.1 ]; then
    cap auth.log cat /var/log/auth.log.1 /var/log/auth.log
  else
    cap auth.log cat /var/log/auth.log
  fi
else
  echo "auth.log rc=missing /var/log/auth.log unreadable" >> "$RCS"
fi

# 3. persistence + accounts (deployed read-only collectors, exact paths)
cap persist.txt "$OPT/collect_persistence.sh"
cap accounts.txt "$OPT/collect_accounts.sh"

# 4. log integrity: raw dump stays in PrivateTmp; case keeps the JSON results
LDUMP=$(mktemp) || LDUMP=
if [ -n "$LDUMP" ]; then
  "$OPT/collect_logintegrity.sh" > "$LDUMP" 2> "$CASE/.stderr"
  echo "logint_dump rc=$? bytes=$(wc -c < "$LDUMP")" >> "$RCS"
  rm -f "$CASE/.stderr"
  cap logint.json $PY "$OPT/log_integrity.py" --stdin --json < "$LDUMP"
  cap logint_compare.json $PY "$OPT/log_integrity.py" --compare "$BASE/logintegrity_baseline.json" --json "$LDUMP"
  rm -f "$LDUMP"
else
  echo "logint_dump rc=mktemp-failed" >> "$RCS"
fi

# 5. baseline compares (not yet consumed by ioc_timeline; kept for review)
cap persist_compare.json $PY "$OPT/persistence_audit.py" --compare "$BASE/persistence_baseline.json" --collected-at "$COLL" --json "$CASE/persist.txt"
cap accounts_compare.json $PY "$OPT/account_audit.py" --compare "$BASE/account_baseline.json" --json "$CASE/accounts.txt"

# 6. file integrity vs the root-only baseline
#    Paths under LIAO_FIM_EXCLUDE (space-separated prefixes, e.g. a git repo that
#    changes daily) are filtered out; the suppressed count is recorded in fim.json.
cap fim.json python3 -I -B -c '
import sys, json
sys.path.insert(0, "/opt/liao")
import fim
import os
X = tuple(p for p in os.environ.get("LIAO_FIM_EXCLUDE", "").split() if p)
r = fim.compare_against_baseline(baseline_path="/var/lib/liao/baselines/fim_baseline.json")
n = 0
for k in ("modified", "deleted", "added"):
    keep = [e for e in r.get(k, []) if not str(e.get("path", "")).startswith(X)]
    n += len(r.get(k, [])) - len(keep)
    r[k] = keep
r["suppressed_prefixes"] = list(X)
r["suppressed_count"] = n
json.dump(r, sys.stdout, indent=2)
'

# 7. hashes of the anchor allowlist (verify_anchor reads liao_hashes.txt)
if [ -r "$OPT/ANCHOR_FILES" ]; then
  grep -v -e '^#' -e '^[[:space:]]*$' "$OPT/ANCHOR_FILES" | xargs -r sha256sum > "$CASE/liao_hashes.txt" 2> "$CASE/.stderr"
  rc=$?
  e=$(head -n 3 "$CASE/.stderr" | tr '\n' ' ' | cut -c1-300)
  echo "liao_hashes.txt rc=$rc${e:+ stderr: $e}" >> "$RCS"
  rm -f "$CASE/.stderr"
else
  echo "liao_hashes.txt rc=missing /opt/liao/ANCHOR_FILES" >> "$RCS"
fi

# 8. clock
cap timedatectl.txt timedatectl

# 9. manifest (written last; its presence marks the case complete)
HOST=$(hostname) CID=$CID COLL=$COLL CASE=$CASE python3 -I -B -c '
import json, os, re
case, coll, host = os.environ["CASE"], os.environ["COLL"], os.environ["HOST"]
def rd(n):
    try:
        with open(os.path.join(case, n), errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""
td = rd("timedatectl.txt")
m = re.search(r"(?i)system clock synchronized:\s*(\w+)", td)
files = {}
for n in ("ps.txt", "netstat.txt", "auth.log", "persist.txt", "accounts.txt",
          "logint.json", "fim.json", "timedatectl.txt", "liao_hashes.txt"):
    p = os.path.join(case, n)
    if os.path.isfile(p) and os.path.getsize(p) > 0:
        files[n] = {"host": host, "collected_at": coll}
errs = {}
for ln in rd("collector_rc.txt").splitlines():
    name, _, rest = ln.partition(" ")
    if not rest.startswith("rc=0"):
        errs[name] = rest[:300]
man = {"host": host, "case_id": os.environ["CID"], "collected_at": coll,
       "collector": "collect_case.sh v1",
       "clock_synced": (m.group(1).lower() == "yes") if m else None,
       "timedatectl": td or None, "files": files, "collector_errors": errs}
with open(os.path.join(case, "manifest.json"), "w") as fh:
    json.dump(man, fh, indent=2, sort_keys=True)
' || echo "manifest rc=$?" >> "$RCS"

# 10. hand the case to svc-liao (assemble writes dns.json + timeline into it)
chown -R "$OWNER":root "$CASE"

# 11. retention: keep the newest $KEEP real case directories (never follows links)
find "$ROOT" -mindepth 1 -maxdepth 1 -type d -name '20[0-9][0-9][01][0-9][0-3][0-9]T[0-2][0-9][0-5][0-9][0-5][0-9]Z' \
  | sort -r | tail -n +$((KEEP + 1)) | while read -r old; do rm -rf -- "$old"; done

echo "collect_case: case $CID written; non-zero rc lines: $(grep -vc ' rc=0' "$RCS")"
exit 0
