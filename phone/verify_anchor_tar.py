"""verify_anchor_tar.py - Pythonista (iOS). Check a copy of the trust-anchor tar.

Verifies the tar's sha256, that every baseline copy inside matches the manifest,
and (optional) that the manifest matches hashes you recorded independently while
deploying - so the anchor is checked by something other than the server that made it.
"""
import hashlib, json, os, tarfile
import dialogs

EXP_TAR = ""   # sha256 of the anchor tar, as printed when you made it
EXP = {}       # optional: {"fim.py": "<first 16 of sha256>", ...} recorded at deploy time


def check(path):
    if not path or not os.path.isfile(path):
        print("FAIL: nothing picked")
        return False
    with open(path, "rb") as fh:
        h = hashlib.sha256(fh.read()).hexdigest()
    ok = (h == EXP_TAR) if EXP_TAR else True
    print("tar %s (%d bytes) %s" % (h[:16], os.path.getsize(path),
          ("OK" if ok else "MISMATCH") if EXP_TAR else "NOT PINNED - set EXP_TAR"))
    with tarfile.open(path) as t:
        names = {m.name: m for m in t.getmembers() if m.isfile()}
        mp = [n for n in names if n.endswith("anchor_manifest.json")]
        if not mp:
            print("FAIL: no anchor_manifest.json")
            return False
        files = json.loads(t.extractfile(names[mp[0]]).read()).get("files", {})
        print("manifest: %d files" % len(files))
        if EXP:
            bad = [n for n in EXP if files.get(n, "")[:16] != EXP[n]]
            extra = sorted(set(files) - set(EXP))
            for n in bad:
                print("  MISMATCH %s manifest=%s expected=%s" % (n, files.get(n, "-")[:16], EXP[n]))
            for n in extra:
                print("  UNEXPECTED %s" % n)
            print("manifest vs recorded hashes: %d/%d OK" % (len(EXP) - len(bad), len(EXP)))
            ok = ok and not bad and not extra
        for n in sorted(x for x in names if "/baselines/" in x):
            b = os.path.basename(n)
            d = hashlib.sha256(t.extractfile(names[n]).read()).hexdigest()
            good = d == files.get(b)
            print("  copy %-27s %s %s" % (b, d[:16], "OK" if good else "MISMATCH"))
            ok = ok and good
    print("RESULT:", "PASS" if ok else "FAIL")
    return ok


check(dialogs.pick_document(types=["public.item"]))
