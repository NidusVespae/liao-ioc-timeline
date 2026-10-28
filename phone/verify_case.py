"""verify_case.py - Pythonista (iOS). Independent, off-host check of one case.

Pick 1: your trust-anchor tar (made with ioc_timeline.py --make-anchor, then tarred).
Pick 2: the case's liao_hashes.txt (copied off the server).
Compares the server's recorded hashes with the anchor, then runs three in-memory
tamper tests to prove the comparison would catch a change. Never imports server code.
"""
import hashlib, json, os, re, tarfile
import dialogs

# sha256 of YOUR anchor tar, recorded when you made it (empty = skip, with warning)
ANCHOR_TAR = ""


def sha(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def compare(anchor, current):
    a = {os.path.basename(k): v for k, v in anchor.items()}
    c = {os.path.basename(k): v for k, v in current.items()}
    mis = sorted(n for n in a if n in c and c[n] != a[n])
    miss = sorted(n for n in a if n not in c)
    extra = sorted(n for n in c if n not in a)
    return mis, miss, extra


print("1) pick the ANCHOR tar")
t = dialogs.pick_document(types=["public.item"])
print("2) pick the liao_hashes-<case>.txt file")
h = dialogs.pick_document(types=["public.item"])
if not t or not h:
    raise SystemExit("FAIL: both files are needed")
if ANCHOR_TAR and sha(t) != ANCHOR_TAR:
    raise SystemExit("FAIL: anchor tar hash %s is not your recorded anchor" % sha(t)[:16])
print("anchor tar %s (%s)" % ("OK" if ANCHOR_TAR else "NOT PINNED - set ANCHOR_TAR", sha(t)[:16]))
with tarfile.open(t) as tf:
    mp = [m for m in tf.getnames() if m.endswith("anchor_manifest.json")]
    if not mp:
        raise SystemExit("FAIL: no anchor_manifest.json in that tar")
    anchor = json.loads(tf.extractfile(mp[0]).read())["files"]
cur = {}
for ln in open(h, errors="replace"):
    m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+)$", ln.strip())
    if m:
        cur[m.group(2).strip()] = m.group(1).lower()
print("case hashes: %d lines from %s" % (len(cur), os.path.basename(h)))
if not cur:
    raise SystemExit("FAIL: no hash lines - pick the liao_hashes-<case>.txt file, not a tar")

mis, miss, extra = compare(anchor, cur)
real_ok = not (mis or miss or extra) and len(cur) == len(anchor)
print("\nREAL CHECK: %s  (anchor %d, current %d)" % ("VERIFIED" if real_ok else "MISMATCH", len(anchor), len(cur)))
for k, v in (("mismatched", mis), ("missing", miss), ("extra", extra)):
    for n in v:
        print("  [HIGH] %-10s %s" % (k, n))

print("\nTAMPER TESTS (in memory only, nothing on disk changes):")
tests = []
first = sorted(cur)[0]
x = dict(cur); x[first] = ("0" if x[first][0] != "0" else "1") + x[first][1:]
tests.append(("one byte of %s changed" % os.path.basename(first), compare(anchor, x)[0] == [os.path.basename(first)]))
x = dict(cur); last = sorted(cur)[-1]; del x[last]
tests.append(("%s deleted" % os.path.basename(last), compare(anchor, x)[1] == [os.path.basename(last)]))
x = dict(cur); x["/opt/liao/backdoor.py"] = "ab" * 32
tests.append(("planted /opt/liao/backdoor.py", compare(anchor, x)[2] == ["backdoor.py"]))
for name, caught in tests:
    print("  %-38s %s" % (name, "CAUGHT" if caught else "MISSED"))
print("\nRESULT:", "PASS" if real_ok and all(c for _, c in tests) else "FAIL")
