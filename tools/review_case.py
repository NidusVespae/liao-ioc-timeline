#!/usr/bin/env python3
# review_case.py - compact read-only summary of one Liao case (high/medium only).
import json, os, sys
from collections import Counter

case = sys.argv[1]


def load(n):
    try:
        with open(os.path.join(case, n)) as fh:
            return json.load(fh)
    except Exception as e:
        return {"_err": str(e)}


t = load("timeline.json")
evs = (t.get("timeline") or []) + (t.get("state_lane") or []) + (t.get("untimed") or [])
print("BLUF:", (t.get("bluf") or t.get("_err") or "")[:200])
print("coverage gap:", t.get("incomplete_coverage"), "| missing:", t.get("missing_feeders"),
      "| clock:", t.get("clock_warning"), "| blind spots:", len(t.get("blind_spots") or []))
sev = Counter((e["severity"], e["source"]) for e in evs)
print("counts:", ", ".join("%s/%s=%d" % (s, src, n) for (s, src), n in sorted(sev.items())
                           if s in ("high", "medium")))
groups = Counter()
first = {}
for e in evs:
    if e["severity"] not in ("high", "medium"):
        continue
    key = (e["severity"], e["source"], e["kind"], (e.get("detail") or "")[:90])
    groups[key] += 1
    first.setdefault(key, e.get("event_time"))
print("\nHIGH/MEDIUM (deduped, max 40):")
for (s, src, kind, det), n in sorted(groups.items(), key=lambda x: (x[0][0] != "high", x[0][1]))[:40]:
    print("[%s] %s/%s x%d @%s\n    %s" % (s[0].upper(), src, kind, n, (first[(s, src, kind, det)] or "-")[:19], det))
if len(groups) > 40:
    print("... +%d more groups" % (len(groups) - 40))

print("\nCOMPARES:")
for n in ("persist_compare.json", "accounts_compare.json", "logint_compare.json"):
    d = load(n)
    if "_err" in d:
        print(" ", n, "ERROR", d["_err"][:80])
        continue
    bits = []
    for k, v in d.items():
        if isinstance(v, list) and k not in ("flagged", "info", "acknowledged", "problems"):
            bits.append("%s=%d" % (k, len(v)))
        elif isinstance(v, dict) and all(isinstance(x, list) for x in v.values()) and v:
            bits.append("%s(%s)" % (k, " ".join("%s=%d" % (a, len(b)) for a, b in v.items() if b)))
    if "drift_count" in d:
        bits.insert(0, "drift_count=%s" % d["drift_count"])
    print(" ", n, "|", ", ".join(bits)[:300])
    if n == "persist_compare.json":
        kinds = Counter((x.get("kind"), "+") for x in d.get("added", [])) + \
            Counter((x.get("kind"), "-") for x in d.get("removed", []))
        print("    by kind:", dict(kinds))
        for x in d.get("added", []):
            if x.get("kind") != "timer":
                print("    + %s %s %s" % (x.get("kind"), x.get("unit") or x.get("path"), (x.get("content") or "")[:60]))
        for x in d.get("removed", []):
            if x.get("kind") != "timer":
                print("    - %s %s %s" % (x.get("kind"), x.get("unit") or x.get("path"), (x.get("content") or "")[:60]))
    if n == "logint_compare.json":
        for c in (d.get("changes") or d.get("drift") or [])[:12]:
            if isinstance(c, dict):
                print("    ~ [%s] %s: %s" % (c.get("severity"), c.get("code"), (c.get("detail") or "")[:110]))
