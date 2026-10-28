#!/bin/sh
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
  awk '$1 !~ /^(ssh-|ecdsa-|sk-)/ {print "opts:", $1}' "$f"
done

echo "===SECTION login_hooks==="
emit_stat /etc/profile /etc/profile.d/* /etc/bash.bashrc /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile

echo "===SECTION ld_preload==="
[ -f /etc/ld.so.preload ] && cat /etc/ld.so.preload

echo "===END==="

