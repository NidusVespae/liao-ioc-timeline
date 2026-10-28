#!/bin/sh
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
