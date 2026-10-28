"""update_tools.py - Pythonista (iOS). Replace your phone copies of toolkit files
with new versions, only if the picked file matches the expected hash.
Old copies are kept as .bak. Edit EXP before running."""
import hashlib, os, shutil
import dialogs

EXP = {  # file name -> first 16 hex of the sha256 you expect
    "persistence_audit.py": "",
    "dns_parser.py": "",
}
DOCS = os.path.expanduser("~/Documents")


def h(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]


def find(name):
    alts = {name, name.replace("_", " ")}
    hits = []
    for dp, dns, fns in os.walk(DOCS):
        dns[:] = [d for d in dns if not d.startswith(".")]
        hits += [os.path.join(dp, n) for n in fns if n in alts]
    return sorted(hits)


for name, want in EXP.items():
    print("== %s (pick it now)" % name)
    if not want:
        print("  SKIP: set the expected hash in EXP first")
        continue
    hits = find(name)
    for p in hits:
        print("  existing: %s %s" % (p[len(DOCS):], h(p)))
    src = dialogs.pick_document(types=["public.item"])
    if not src:
        print("  SKIP: nothing picked")
        continue
    if h(src) != want:
        print("  STOP: picked file is %s, expected %s - nothing changed" % (h(src), want))
        continue
    for t in hits or [os.path.join(DOCS, name)]:
        if os.path.exists(t) and h(t) == want:
            print("  already current: %s" % t[len(DOCS):])
            continue
        if os.path.exists(t):
            shutil.copy2(t, t + ".bak")
        shutil.copyfile(src, t)
        print("  updated: %s -> %s" % (t[len(DOCS):], h(t)))
print("done")
