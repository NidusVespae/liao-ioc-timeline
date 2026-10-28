#!/usr/bin/env python3
# review_detail.py - read-only drill-down: DNS findings + auth/sudo summary for one case.
import json, os, re, sys
from collections import Counter

case = sys.argv[1]


def load(n):
    with open(os.path.join(case, n)) as fh:
        return json.load(fh)


print("== DNS findings (NextDNS, off-host)")
d = load("dns.json")
for f in d.get("findings", []):
    print("[%s] %-16s %s\n    %s | %s -> %s | clients: %s" % (
        f.get("severity", "?")[0].upper(), f.get("type"), f.get("domain"), f.get("detail"),
        (f.get("first_seen") or "-")[5:16], (f.get("last_seen") or "-")[5:16],
        ", ".join(c[:22] for c in (f.get("client_ips") or [])[:3])))

t = load("timeline.json")
evs = [e for e in (t.get("timeline") or []) + (t.get("state_lane") or []) + (t.get("untimed") or [])
       if e.get("source") == "authlog"]
print("\n== AUTH events: %d" % len(evs))
print("kinds:", dict(Counter(e["kind"] for e in evs)))
acc = Counter((e["actors"].get("user"), e["actors"].get("ip")) for e in evs if e["kind"] == "login_accepted")
print("accepted logins (user@ip):", ", ".join("%s@%s x%d" % (u, i, n) for (u, i), n in acc.most_common()))
span = sorted(e["event_time"] for e in evs if e.get("event_time"))
print("auth window:", span[0][:19] if span else "-", "->", span[-1][:19] if span else "-")
sudo = [e for e in evs if e["kind"] == "sudo"]
who = Counter((e.get("detail") or "").split(" :", 1)[0].strip() for e in sudo if " : " in (e.get("detail") or ""))
print("sudo invokers:", dict(who))
tty = Counter(m.group(1) for e in sudo for m in [re.search(r"TTY=(\S+)", e.get("detail") or "")] if m)
print("sudo TTYs:", dict(tty))
cmds = Counter()
for e in sudo:
    m = re.search(r"COMMAND=(\S+)(?:\s+(\S+))?", e.get("detail") or "")
    if m:
        cmds[(os.path.basename(m.group(1)) + " " + (m.group(2) or "")).strip()] += 1
print("sudo commands (top 25):", ", ".join("%s x%d" % c for c in cmds.most_common(25)))
print("\nfailures / account changes:")
for e in evs:
    if e["kind"] in ("login_failed", "user_add", "group_add") or \
            "incorrect password" in (e.get("detail") or "") or "FAILED" in (e.get("detail") or ""):
        print("  %s %-13s %s@%s %s" % ((e.get("event_time") or "-")[:19], e["kind"],
              e["actors"].get("user"), e["actors"].get("ip"), (e.get("detail") or "")[:90]))
