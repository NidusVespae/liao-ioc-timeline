# Install

Tested on Ubuntu 24.04 (systemd 255, Python 3.12). Everything below runs on a host you own.

## 1. Accounts and folders
```sh
sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin svc-liao
sudo groupadd --system liao-secrets && sudo usermod -aG liao-secrets svc-liao
sudo install -d -o root -g root -m 755 /opt/liao /var/lib/liao /var/lib/liao/baselines
sudo install -d -o svc-liao -g root -m 750 /var/lib/liao/cases
sudo install -d -o root -g liao-secrets -m 750 /etc/liao
```

## 2. Code, config, secrets
```sh
sudo install -o root -g root -m 644 liao/*.py liao/ANCHOR_FILES /opt/liao/
sudo install -o root -g root -m 755 liao/*.sh /opt/liao/
sudo install -o root -g root -m 644 etc/liao.conf.example /etc/liao/liao.conf   # then edit
sudo install -o root -g liao-secrets -m 640 /dev/null /etc/liao/secrets.env       # then add keys:
#   NEXTDNS_LOGS_URL='https://…'   ABUSEIPDB_KEY='…'   VIRUSTOTAL_KEY='…'   (single-quoted)
```
On this kind of host `sudo` may create files world-readable regardless of your umask,
so always pass an explicit mode (`install -m`).

## 3. Baselines (only on a host you trust right now)
Collect once, read the plain audits, attribute every finding, then build baselines as
root into `/var/lib/liao/baselines/` (`*_baseline.json`, root 600):
```sh
sudo /opt/liao/collect_persistence.sh > persist.txt
sudo python3 -I -B /opt/liao/persistence_audit.py persist.txt            # review first
sudo python3 -I -B /opt/liao/persistence_audit.py --build-baseline /var/lib/liao/baselines/persistence_baseline.json persist.txt
# same pattern for account_audit (collect_accounts.sh) and log_integrity (collect_logintegrity.sh)
sudo python3 -I -B -c 'import os,sys; os.umask(0o077); sys.path.insert(0,"/opt/liao"); import fim; print(fim.build_baseline(["/opt/liao","/etc/systemd/system"], baseline_path="/var/lib/liao/baselines/fim_baseline.json")["count"])'
```

## 4. Units
```sh
sudo install -o root -g root -m 644 systemd/* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start liao-collect.service      # ~4-5 min; assemble runs after it
sudo python3 -I -B tools/review_case.py /var/lib/liao/cases/$(sudo ls -1 /var/lib/liao/cases | tail -n1)
sudo systemctl enable --now liao-timeline.timer
```
Edit `OnCalendar=` in `liao-timeline.timer` for your timezone.

## 5. Trust anchor (off the host)
```sh
W=$(sudo mktemp -d); grep -v '^#' /opt/liao/ANCHOR_FILES | sudo xargs -I{} cp -p {} "$W/"
sudo python3 -E -s -B /opt/liao/ioc_timeline.py --make-anchor "$W/anchor" --src "$W"
sudo tar -C "$W" -cf ~/liao-anchor.tar anchor && sudo chown "$USER" ~/liao-anchor.tar && sha256sum ~/liao-anchor.tar
sudo rm -rf "$W"
```
Copy the tar to your phone and cloud storage, record its sha256 in `phone/verify_anchor_tar.py`
and `phone/verify_case.py`, verify, then delete it from the server.

## 6. Routine check (from the phone)
Copy a case's `liao_hashes.txt` off the server and run `phone/verify_case.py`
(pick the anchor tar, then the hash file). **MISMATCH = the toolkit is untrusted.**

After any deliberate change to a file listed in `ANCHOR_FILES`: re-baseline, build a new
anchor, verify it, and update the pinned hash.
