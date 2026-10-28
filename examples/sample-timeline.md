<!-- Format example with placeholder values (documentation IPs / example.* domains).
     This is what assemble_case.sh writes to <case>/timeline.md after a routine day
     on which the admin deployed a new service and patched the OS. -->
# IOC Timeline — demo-vps

> **BLUF:** highest severity: high | 4 actor thread(s) | most urgent: [high] demo-vps/fim added /etc/systemd/system/example-app.service | anchor: not checked

- collected: `2026-01-15T12:00:03Z`
- assembled: `2026-01-15T12:04:41.512093+00:00`
- highest severity: **high**  |  threads: **4**  |  anchor: **not checked**

## Feeder coverage

| feeder | host | events | status |
|---|---|---|---|
| proc_inventory | demo-vps | 0 | ok |
| conn_inventory | demo-vps | 6 | ok |
| persistence_audit | demo-vps | 1 | ok |
| account_audit | demo-vps | 3 | ok |
| log_integrity | demo-vps | 41 | ok |
| log_parser(auth) | demo-vps | 212 | ok |
| dns_parser(NextDNS, off-host) | demo-vps | 4 | ok |
| fim | demo-vps | 2 | ok |

## Timeline

| time | sev | phase | host | source | detail |
|---|---|---|---|---|---|
| 2026-01-15T03:12:07+00:00 | low | entry | demo-vps | authlog | Accepted publickey for admin from 192.0.2.10 port 50112 ssh2: ED25519 SHA256:… |
| 2026-01-15T03:14:55+00:00 | medium | privilege | demo-vps | authlog | admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt-get -y upgrade |
| 2026-01-15T03:16:40+00:00 | info | context | demo-vps | log_integrity | reboot 2026-01-15T03:16:31+00:00 -> 2026-01-15T03:16:52+00:00 (21s dark) |
| 2026-01-15T03:22:18+00:00 | medium | privilege | demo-vps | authlog | admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/install -m 644 example-app.service /etc/systemd/system/ |
| 2026-01-15T03:22:18+00:00 | high | persistence | demo-vps | fim | added /etc/systemd/system/example-app.service |
| 2026-01-15T03:22:19+00:00 | medium | persistence | demo-vps | fim | added /etc/systemd/system/multi-user.target.wants/example-app.service |
| 2026-01-15T11:00:02+00:00 | high | c2 | demo-vps | dns | beaconing — 24 queries every ~3600.1s (regularity 0.002) \| clients: 198.51.100.7 |

## Actor threads

- **high** `t-3f9a1c` — 5 events, hosts demo-vps, phases entry>privilege>persistence
- **high** `t-81d0e2` — 1 events, hosts demo-vps, phases c2
- **medium** `t-0b77a4` — 2 events, hosts demo-vps, phases privilege
- **info** `t-5c2e19` — 3 events, hosts demo-vps, phases context

---
_Most telemetry comes from the droplet itself, which a compromised host can lie about. NextDNS is the only off-host source. Not an all-clear._
