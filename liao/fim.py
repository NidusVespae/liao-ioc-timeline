#!/usr/bin/env python3
"""
fim.py  —  File Integrity Monitor
=================================
Liao's persistence/rootkit eye. Answers the threat-model question:
"Did anything change a file that should not have changed?"

THE CORE IDEA (and why it beats a rootkit):
A kernel rootkit can hide a running process, intercept system calls, and lie to
live tools about what's happening. What it has a much harder time doing is
un-changing a file it already modified on disk. So if you:

  1. Record a cryptographic hash of every critical file WHILE YOU TRUST THE HOST
     (the "baseline"), and
  2. Store that baseline OFF the host (so the attacker can't quietly edit it),
  3. Then later re-hash and compare,

...a modified, added, or deleted file shows up as a mismatch — even if the live
system swears nothing changed. The baseline is ground truth; the host is the
suspect.

WHAT IT WATCHES (tune to your environment):
- Autostart locations (persistence): startup scripts, cron, launch agents,
  scheduled-task dirs, shell rc files.
- Critical configs and binaries you care about.
- The security toolkit itself — if malware tampered
  with a trading or security script, you want to know loudly.

OFF-HOST STORAGE — IMPORTANT:
The baseline JSON must NOT live only on the machine it's protecting. After
creating a baseline, copy it somewhere the host can't silently rewrite:
iCloud Drive, a private GitHub repo, a USB drive, your Obsidian vault. On a
compromise, you compare the live host against that external copy.

Pythonista / iOS friendly: standard library only (hashlib, os, json).
ok-dict return shapes. Menu-return console. AUTHORIZED USE ONLY — your files.

--- TIMELINE RETROFIT (2026-10-26) ---
Every drift record now carries `event_time` (ISO8601 UTC) + `time_source` so
ioc_timeline.py can place it chronologically:
  - modified/added -> event_time = file mtime, time_source = "mtime"
  - deleted        -> event_time = None,      time_source = None  (unknowable)
"""

import hashlib
import json
import os
from datetime import datetime, timezone


DEFAULT_BASELINE_PATH = os.path.expanduser("~/Documents/liao_fim_baseline.json")
CHUNK = 65536  # 64KB read chunks so large files don't blow up memory


def _now():
    return datetime.now(timezone.utc).isoformat()


def _mtime_iso(mtime):
    """Filesystem mtime (epoch float) -> ISO8601 UTC, or None."""
    if not mtime:
        return None
    return datetime.fromtimestamp(mtime, timezone.utc).isoformat()


def hash_file(path, algo="sha256"):
    """Return hex digest of a file, or None if unreadable."""
    try:
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError):
        return None


def _stat_meta(path):
    """Lightweight metadata to accompany the hash (size + mtime)."""
    try:
        st = os.stat(path)
        return {"size": st.st_size, "mtime": st.st_mtime}
    except OSError:
        return {"size": None, "mtime": None}


def _expand_targets(targets):
    """
    Turn a list of files/dirs into a flat, sorted list of file paths.
    Directories are walked recursively. Missing paths are kept (so a deleted
    watched file is detectable later as 'missing'), tagged separately.
    """
    files = set()
    missing = []
    for t in targets:
        t = os.path.expanduser(t)
        if os.path.isdir(t):
            for root, _dirs, names in os.walk(t):
                for n in names:
                    files.add(os.path.join(root, n))
        elif os.path.isfile(t):
            files.add(t)
        else:
            missing.append(t)
    return sorted(files), missing


def build_baseline(targets, algo="sha256", baseline_path=DEFAULT_BASELINE_PATH):
    """
    Hash every target file and write a baseline snapshot.

    Returns ok-dict:
        {"ok": bool, "created_at", "algo", "count", "unreadable":[...],
         "missing_targets":[...], "baseline_path", "error"}
    """
    files, missing = _expand_targets(targets)
    baseline_abs = os.path.abspath(os.path.expanduser(baseline_path))
    records = {}
    unreadable = []
    for path in files:
        if os.path.abspath(path) == baseline_abs:
            continue  # never baseline the baseline file itself
        digest = hash_file(path, algo)
        if digest is None:
            unreadable.append(path)
            continue
        records[path] = {"hash": digest, **_stat_meta(path)}

    baseline = {
        "created_at": _now(),
        "algo": algo,
        "targets": [os.path.expanduser(t) for t in targets],
        "files": records,
    }

    try:
        os.makedirs(os.path.dirname(baseline_path), exist_ok=True)
        with open(baseline_path, "w") as f:
            json.dump(baseline, f, indent=2)
    except OSError as e:
        return {"ok": False, "error": f"write_failed: {e}",
                "baseline_path": baseline_path, "count": len(records)}

    return {
        "ok": True,
        "created_at": baseline["created_at"],
        "algo": algo,
        "count": len(records),
        "unreadable": unreadable,
        "missing_targets": missing,
        "baseline_path": baseline_path,
        "error": None,
        "reminder": "COPY THIS BASELINE OFF-HOST NOW (iCloud / GitHub / USB / "
                    "Obsidian). A baseline the attacker can edit is worthless.",
    }


def compare_against_baseline(baseline_path=DEFAULT_BASELINE_PATH, algo=None):
    """
    Re-hash the baseline's files and report drift.

    Returns ok-dict:
        {
          "ok": bool,
          "checked_at": iso,
          "baseline_created_at": iso,
          "modified": [ {path, old_hash, new_hash, event_time, time_source, ...}, ... ],
          "deleted":  [ {path, event_time, time_source}, ... ],
          "added":    [ {path, event_time, time_source}, ... ],
          "unchanged": int,
          "verdict": str,              # human one-liner; never a bare 'all clear'
          "error": str | None,
        }
    """
    try:
        with open(os.path.expanduser(baseline_path)) as f:
            baseline = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return {"ok": False, "error": f"baseline_unreadable: {e}",
                "modified": [], "deleted": [], "added": [], "unchanged": 0,
                "verdict": "CANNOT COMPARE — baseline missing or corrupt. If you "
                           "did not expect this, treat it as suspicious: an "
                           "attacker may have deleted it."}

    use_algo = algo or baseline.get("algo", "sha256")
    recorded = baseline.get("files", {})

    modified, deleted = [], []
    unchanged = 0

    for path, rec in recorded.items():
        current = hash_file(path, use_algo)
        if current is None:
            # In baseline, now gone/unreadable. No reliable change time.
            deleted.append({"path": path, "event_time": None,
                            "time_source": None})
            continue
        if current != rec["hash"]:
            meta = _stat_meta(path)
            modified.append({
                "path": path,
                "old_hash": rec["hash"][:16] + "...",
                "new_hash": current[:16] + "...",
                "old_size": rec.get("size"),
                "new_size": meta.get("size"),
                "event_time": _mtime_iso(meta.get("mtime")),
                "time_source": "mtime",
            })
        else:
            unchanged += 1

    # Detect NEW files in any watched directory (a dropped payload / webshell).
    # Exclude the baseline file itself — it must not count as drift, and ideally
    # it shouldn't live inside a watched dir at all (keep it off-host).
    added = []
    baseline_abs = os.path.abspath(os.path.expanduser(baseline_path))
    current_files, _missing = _expand_targets(baseline.get("targets", []))
    for path in current_files:
        if os.path.abspath(path) == baseline_abs:
            continue
        if path not in recorded:
            meta = _stat_meta(path)
            added.append({
                "path": path,
                "event_time": _mtime_iso(meta.get("mtime")),
                "time_source": "mtime",
            })

    drift = bool(modified or deleted or added)
    if drift:
        verdict = (f"DRIFT DETECTED: {len(modified)} modified, "
                   f"{len(deleted)} deleted, {len(added)} added. Investigate "
                   "each — map to persistence/rootkit in the threat model.")
    else:
        verdict = ("No drift from baseline across "
                   f"{unchanged} watched file(s). This is reassuring but NOT a "
                   "full all-clear: it only covers files in the baseline, and a "
                   "rootkit can change things you did not think to watch.")

    return {
        "ok": True,
        "checked_at": _now(),
        "baseline_created_at": baseline.get("created_at"),
        "modified": modified,
        "deleted": deleted,
        "added": added,
        "unchanged": unchanged,
        "verdict": verdict,
        "error": None,
    }


def format_human(report):
    """Render a compare report for reading / pasting to Liao."""
    lines = ["# File Integrity Check"]
    if not report.get("ok"):
        lines.append(f"** {report.get('verdict') or report.get('error')}")
        return "\n".join(lines)

    lines.append(f"Checked: {report['checked_at']}")
    lines.append(f"Baseline from: {report['baseline_created_at']}")
    lines.append("")
    lines.append(f"**{report['verdict']}**")
    lines.append("")

    if report["modified"]:
        lines.append(f"## MODIFIED ({len(report['modified'])})")
        for m in report["modified"]:
            lines.append(f"- {m['path']}")
            lines.append(f"    {m['old_hash']} -> {m['new_hash']}  "
                         f"(size {m['old_size']} -> {m['new_size']})  "
                         f"[{m['event_time']}]")
    if report["deleted"]:
        lines.append(f"## DELETED / UNREADABLE ({len(report['deleted'])})")
        for d in report["deleted"]:
            lines.append(f"- {d['path']}")
    if report["added"]:
        lines.append(f"## ADDED ({len(report['added'])})")
        for a in report["added"]:
            lines.append(f"- {a['path']}  [{a['event_time']}]")
    if not (report["modified"] or report["deleted"] or report["added"]):
        lines.append(f"Unchanged files: {report['unchanged']}")
    return "\n".join(lines)


# --- Sensible default watch targets. EDIT THESE for your actual environment. ---
def suggested_targets():
    """
    Starter set. On iOS most system paths are sandboxed away, so the highest-
    value targets are YOUR OWN scripts and configs that malware would tamper
    with. On a desktop, add the OS autostart locations noted below.
    """
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "Documents"),          # your Pythonista scripts live here
        # Desktop persistence locations (uncomment on Mac/Linux):
        # os.path.join(home, ".bashrc"),
        # os.path.join(home, ".zshrc"),
        # os.path.join(home, ".profile"),
        # os.path.join(home, "Library/LaunchAgents"),   # macOS persistence
        # "/etc/crontab",
        # "/etc/rc.local",
    ]
    return [c for c in candidates if os.path.exists(c)]


def _console():
    baseline_path = DEFAULT_BASELINE_PATH
    targets = suggested_targets()
    while True:
        print("\n=== Liao :: File Integrity Monitor ===")
        print(f"Baseline: {baseline_path}")
        print(f"Targets : {targets or '(none set — add some!)'}")
        print("1) Build baseline from current targets")
        print("2) Compare current state against baseline")
        print("3) Set targets (comma-separated paths)")
        print("4) Raw JSON of a compare")
        print("0) Back")
        choice = input("> ").strip()

        if choice == "1":
            if not targets:
                print("No targets set. Use option 3 first.")
                continue
            rep = build_baseline(targets, baseline_path=baseline_path)
            if rep["ok"]:
                print(f"\nBaselined {rep['count']} file(s).")
                if rep["unreadable"]:
                    print(f"  Unreadable (skipped): {len(rep['unreadable'])}")
                print(f"\n!! {rep['reminder']}")
            else:
                print(f"\nFAILED: {rep['error']}")
        elif choice == "2":
            rep = compare_against_baseline(baseline_path)
            print("\n" + format_human(rep))
        elif choice == "3":
            raw = input("Paths (comma-separated): ").strip()
            if raw:
                targets = [p.strip() for p in raw.split(",") if p.strip()]
        elif choice == "4":
            print(json.dumps(compare_against_baseline(baseline_path), indent=2))
        elif choice == "0":
            return
        else:
            print("?")


def main():
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--baseline":
        print(json.dumps(build_baseline(suggested_targets()), indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "--check":
        print(json.dumps(compare_against_baseline(), indent=2))
    else:
        _console()


if __name__ == "__main__":
    main()
