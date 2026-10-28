#!/bin/sh
# /opt/liao/assemble_case.sh  v1  -  Liao timeline assembly (run only on hosts you own).
# Runs as svc-liao via liao-assemble.service (EnvironmentFile=/etc/liao/secrets.env).
# Assembles the NEWEST complete case once: dns.json, timeline.md, timeline.json.
# Optional arg: a case id (YYYYMMDDTHHMMSSZ) to (re)assemble that case.
PATH=/usr/bin:/bin; export PATH
LC_ALL=C; export LC_ALL
TZ=UTC; export TZ
umask 077
set -u

OPT=/opt/liao
ROOT=/var/lib/liao/cases
PY="python3 -E -s -B"
# users too ubiquitous to thread on (root + service users are excluded by default);
# set LIAO_SELF_USERS in /etc/liao/liao.conf (comma list)
SELF=${LIAO_SELF_USERS:-svc-liao}

[ "$(id -un)" = svc-liao ] || { echo "assemble_case: must run as svc-liao" >&2; exit 2; }

if [ $# -ge 1 ]; then
  case "$1" in
    20[0-9][0-9][01][0-9][0-3][0-9]T[0-2][0-9][0-5][0-9][0-5][0-9]Z) CASE=$ROOT/$1 ;;
    *) echo "assemble_case: bad case id" >&2; exit 2 ;;
  esac
else
  CASE=$(find "$ROOT" -mindepth 1 -maxdepth 1 -type d \
           -name '20[0-9][0-9][01][0-9][0-3][0-9]T[0-2][0-9][0-5][0-9][0-5][0-9]Z' | sort | tail -n 1)
  [ -n "$CASE" ] || { echo "assemble_case: no cases" >&2; exit 2; }
  if [ -e "$CASE/timeline.json" ]; then
    echo "assemble_case: newest case $(basename "$CASE") already assembled; nothing to do"
    exit 0
  fi
fi
[ -d "$CASE" ] && [ ! -L "$CASE" ] && [ -f "$CASE/manifest.json" ] || {
  echo "assemble_case: $CASE incomplete (no manifest.json)" >&2; exit 2; }

ERR=$CASE/assemble_rc.txt
: > "$ERR"

# DNS (off-host source). URL comes from the environment only; never echoed.
if [ -n "${NEXTDNS_LOGS_URL:-}" ]; then
  $PY "$OPT/dns_parser.py" --url --json > "$CASE/dns.json" 2> "$CASE/.stderr"
  echo "dns.json rc=$? stderr_lines=$(wc -l < "$CASE/.stderr")" >> "$ERR"
  rm -f "$CASE/.stderr"
else
  echo "dns.json rc=skipped NEXTDNS_LOGS_URL not set" >> "$ERR"
fi

# Timeline: markdown for reading, then JSON (written last = the done marker).
$PY "$OPT/ioc_timeline.py" --assemble "$CASE" --self-users "$SELF" --md \
  > "$CASE/timeline.md" 2> "$CASE/.stderr"
echo "timeline.md rc=$?" >> "$ERR"
$PY "$OPT/ioc_timeline.py" --assemble "$CASE" --self-users "$SELF" --json \
  > "$CASE/.timeline.json.tmp" 2>> "$CASE/.stderr"
rc=$?
echo "timeline.json rc=$rc" >> "$ERR"
if [ -s "$CASE/.stderr" ]; then
  echo "stderr: $(head -n 3 "$CASE/.stderr" | tr '\n' ' ' | cut -c1-300)" >> "$ERR"
fi
rm -f "$CASE/.stderr"
mv -f "$CASE/.timeline.json.tmp" "$CASE/timeline.json"

echo "assemble_case: $(basename "$CASE") rc=$rc (0 clean, 1 flagged, 3 coverage gap, 2 error)"
exit $rc
