#!/bin/sh
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
