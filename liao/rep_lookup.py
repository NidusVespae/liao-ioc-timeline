#!/usr/bin/env python3
"""
rep_lookup.py  —  IP / hash / domain reputation lookup
======================================================
Liao's intel eye. Takes an indicator that another tool flagged (an egress IP
from conn_inventory, a decoded URL/hash from multi_decoder) and asks external
threat-intel whether it's actually known-bad — turning a heuristic flag into a
corroborated verdict.

SOURCES (both queried; results cross-referenced):
  - AbuseIPDB : community abuse reports for an IP -> confidence score 0..100
  - VirusTotal: 70+ engines for IP / domain / file-hash -> malicious vote count

CROSS-REFERENCE PRINCIPLE (same as the threat model):
An indicator that BOTH sources independently call bad is a far stronger signal
than either alone. The verdict combines them and says which sources agreed.

KEYS — iOS Keychain (Pythonista), with env-var fallback elsewhere:
Store once in Pythonista's console:
    import keychain
    keychain.set_password("liao_intel", "abuseipdb", "YOUR_ABUSEIPDB_KEY")
    keychain.set_password("liao_intel", "virustotal", "YOUR_VT_KEY")
Then this tool reads them automatically. If a key is absent, that source is
skipped and the tool says so loudly — a skipped source is NOT a clean verdict.

Pythonista / iOS friendly: standard library only (urllib). ok-dict shapes.
Menu-return console. AUTHORIZED USE — these are public reputation APIs; you are
querying indicators, not attacking anything.
"""

import json
import re
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone


SERVICE = "liao_intel"   # keychain service name
_TIMEOUT = 15


def _now():
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Key retrieval: iOS Keychain first, env var fallback.
# --------------------------------------------------------------------------

def _get_key(name, env_var):
    """name = keychain account ('abuseipdb'/'virustotal'); env_var = fallback."""
    try:
        import keychain  # Pythonista-only
        val = keychain.get_password(SERVICE, name)
        if val:
            return val.strip()
    except ImportError:
        pass
    import os
    val = os.environ.get(env_var)
    return val.strip() if val else None


# --------------------------------------------------------------------------
# Indicator typing — decide what kind of thing we were handed.
# --------------------------------------------------------------------------

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HASH = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")


def classify_indicator(ind):
    ind = ind.strip()
    if _IPV4.match(ind):
        return "ip"
    if _HASH.match(ind):
        return "hash"
    # strip scheme/path so a pasted URL still classifies as its domain
    host = ind
    m = re.match(r"^[a-z]+://([^/]+)", ind, re.I)
    if m:
        host = m.group(1)
    host = host.split("/")[0].split(":")[0]
    if _DOMAIN.match(host):
        return "domain"
    return "unknown"


# --------------------------------------------------------------------------
# Source queries. Each returns a normalized dict or an explicit skip/error.
# --------------------------------------------------------------------------

def _http_get_json(url, headers):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def query_abuseipdb(ip, key):
    """AbuseIPDB IP check -> {available, malicious, score, detail}."""
    if not key:
        return {"source": "abuseipdb", "available": False,
                "reason": "no API key in keychain/env"}
    try:
        qs = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        data = _http_get_json(
            "https://api.abuseipdb.com/api/v2/check?" + qs,
            {"Key": key, "Accept": "application/json"},
        )
        d = data.get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        return {
            "source": "abuseipdb",
            "available": True,
            "malicious": score >= 50,           # AbuseIPDB's own "likely" threshold
            "score": score,                     # 0..100
            "detail": {
                "total_reports": d.get("totalReports"),
                "country": d.get("countryCode"),
                "isp": d.get("isp"),
                "domain": d.get("domain"),
                "last_reported": d.get("lastReportedAt"),
            },
        }
    except urllib.error.HTTPError as e:
        return {"source": "abuseipdb", "available": False,
                "reason": f"HTTP {e.code}"}
    except (urllib.error.URLError, ValueError, OSError) as e:
        return {"source": "abuseipdb", "available": False,
                "reason": type(e).__name__}


def query_virustotal(indicator, ind_type, key):
    """VT v3 lookup for ip / domain / hash -> {available, malicious, score, detail}."""
    if not key:
        return {"source": "virustotal", "available": False,
                "reason": "no API key in keychain/env"}

    if ind_type == "ip":
        path = f"ip_addresses/{indicator}"
    elif ind_type == "domain":
        host = indicator
        m = re.match(r"^[a-z]+://([^/]+)", indicator, re.I)
        if m:
            host = m.group(1).split("/")[0].split(":")[0]
        path = f"domains/{host}"
    elif ind_type == "hash":
        path = f"files/{indicator}"
    else:
        return {"source": "virustotal", "available": False,
                "reason": f"unsupported indicator type '{ind_type}'"}

    try:
        data = _http_get_json(
            "https://www.virustotal.com/api/v3/" + path,
            {"x-apikey": key, "Accept": "application/json"},
        )
        stats = (data.get("data", {})
                     .get("attributes", {})
                     .get("last_analysis_stats", {}))
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(v for v in stats.values() if isinstance(v, int)) or 0
        return {
            "source": "virustotal",
            "available": True,
            "malicious": (malicious + suspicious) >= 3,   # >=3 engines agree
            "score": malicious + suspicious,              # raw bad-engine count
            "detail": {
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "total_engines": total,
            },
        }
    except urllib.error.HTTPError as e:
        # VT returns 404 for indicators it has simply never seen.
        if e.code == 404:
            return {"source": "virustotal", "available": True,
                    "malicious": False, "score": 0,
                    "detail": {"note": "not found in VT (unseen indicator)"}}
        return {"source": "virustotal", "available": False,
                "reason": f"HTTP {e.code}"}
    except (urllib.error.URLError, ValueError, OSError) as e:
        return {"source": "virustotal", "available": False,
                "reason": type(e).__name__}


# --------------------------------------------------------------------------
# Cross-referenced verdict.
# --------------------------------------------------------------------------

def _build_verdict(results):
    """Combine source results into one honest verdict line + flags."""
    available = [r for r in results if r.get("available")]
    flagged = [r for r in available if r.get("malicious")]
    skipped = [r for r in results if not r.get("available")]

    if not available:
        level = "UNKNOWN"
        line = ("No intel source returned data (keys missing or APIs "
                "unreachable). This is NOT a clean result — it's a blind spot.")
    elif len(flagged) >= 2:
        level = "MALICIOUS (corroborated)"
        line = ("Multiple independent sources flag this indicator. Treat as bad: "
                "block at your edge, hunt for related connections.")
    elif len(flagged) == 1:
        level = "SUSPICIOUS (single source)"
        line = (f"Flagged by {flagged[0]['source']} only. Corroborate before "
                "acting, but raise scrutiny.")
    else:
        level = "NO DETECTIONS"
        line = ("No source flagged this, across "
                f"{len(available)} source(s) queried. Clean from these feeds — "
                "not proof of safety, only absence of known-bad reports.")

    if skipped:
        line += (" [Skipped: "
                 + ", ".join(f"{s['source']} ({s.get('reason')})"
                             for s in skipped) + "]")
    return level, line


def lookup(indicator):
    """
    Full cross-referenced reputation lookup.

    Returns ok-dict:
        {"ok", "indicator", "type", "checked_at", "level", "verdict",
         "sources": [ <normalized source dict>, ... ], "error"}
    """
    ind = indicator.strip()
    ind_type = classify_indicator(ind)
    if ind_type == "unknown":
        return {"ok": False, "indicator": ind, "type": "unknown",
                "checked_at": _now(), "level": "ERROR",
                "verdict": "Not a recognizable IP, domain, or file hash.",
                "sources": [], "error": "unclassifiable_indicator"}

    ab_key = _get_key("abuseipdb", "ABUSEIPDB_KEY")
    vt_key = _get_key("virustotal", "VIRUSTOTAL_KEY")

    sources = []
    if ind_type == "ip":
        sources.append(query_abuseipdb(ind, ab_key))
    else:
        sources.append({"source": "abuseipdb", "available": False,
                        "reason": f"only supports IPs (got {ind_type})"})
    sources.append(query_virustotal(ind, ind_type, vt_key))

    level, verdict = _build_verdict(sources)
    return {
        "ok": True,
        "indicator": ind,
        "type": ind_type,
        "checked_at": _now(),
        "level": level,
        "verdict": verdict,
        "sources": sources,
        "error": None,
    }


def format_human(report):
    lines = [f"# Reputation: {report['indicator']}  ({report['type']})"]
    lines.append(f"Checked: {report['checked_at']}")
    lines.append("")
    lines.append(f"**{report['level']}**")
    lines.append(report["verdict"])
    lines.append("")
    for s in report["sources"]:
        if not s.get("available"):
            lines.append(f"- {s['source']}: skipped ({s.get('reason')})")
            continue
        verd = "BAD" if s.get("malicious") else "clean"
        lines.append(f"- {s['source']}: {verd} (score {s.get('score')})")
        for k, v in (s.get("detail") or {}).items():
            lines.append(f"    {k}: {v}")
    return "\n".join(lines)


def _split_indicators(raw):
    """Split a pasted blob into individual indicators. Accepts newlines,
    commas, or whitespace as separators; de-dupes while preserving order."""
    parts = re.split(r"[\s,]+", raw.strip())
    seen, out = set(), []
    for p in parts:
        p = p.strip()
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


# VirusTotal free tier = 4 lookups/min. Pace to ~1 call / 16s to stay safe.
_VT_MIN_INTERVAL = 16.0


def lookup_batch(indicators, pace=True, progress=None):
    """
    Look up many indicators, auto-pacing so VirusTotal's 4/min limit isn't hit.

    Only VT-touching lookups (domains, hashes, and IPs — everything hits VT)
    need pacing; we sleep between calls only when more remain.

    progress: optional callback(i, total, indicator) for console feedback.

    Returns ok-dict:
        {"ok", "checked_at", "count",
         "results": [ <lookup report>, ... ],
         "rollup": {"malicious":[...], "suspicious":[...], "clean":[...],
                    "unknown":[...], "error":[...]},
         "summary": str}
    """
    import time
    results = []
    rollup = {"malicious": [], "suspicious": [], "clean": [],
              "unknown": [], "error": []}

    total = len(indicators)
    for i, ind in enumerate(indicators):
        if progress:
            progress(i + 1, total, ind)
        rep = lookup(ind)
        results.append(rep)

        lvl = rep.get("level", "")
        if lvl.startswith("MALICIOUS"):
            rollup["malicious"].append(ind)
        elif lvl.startswith("SUSPICIOUS"):
            rollup["suspicious"].append(ind)
        elif lvl.startswith("NO DETECTIONS"):
            rollup["clean"].append(ind)
        elif lvl == "UNKNOWN":
            rollup["unknown"].append(ind)
        else:
            rollup["error"].append(ind)

        # Pace before the NEXT call (not after the last one).
        if pace and i < total - 1:
            time.sleep(_VT_MIN_INTERVAL)

    parts = []
    if rollup["malicious"]:
        parts.append(f"{len(rollup['malicious'])} MALICIOUS")
    if rollup["suspicious"]:
        parts.append(f"{len(rollup['suspicious'])} suspicious")
    if rollup["clean"]:
        parts.append(f"{len(rollup['clean'])} clean")
    if rollup["unknown"]:
        parts.append(f"{len(rollup['unknown'])} unknown")
    if rollup["error"]:
        parts.append(f"{len(rollup['error'])} error")
    summary = f"{total} checked: " + ", ".join(parts) if parts else \
        f"{total} checked."

    return {
        "ok": True,
        "checked_at": _now(),
        "count": total,
        "results": results,
        "rollup": rollup,
        "summary": summary,
    }


def format_batch(batch):
    """Render a batch: roll-up first (the headline), then per-indicator detail."""
    lines = ["# Reputation Batch", batch["summary"], ""]
    r = batch["rollup"]
    if r["malicious"]:
        lines.append("## MALICIOUS (corroborated) — act on these")
        for d in r["malicious"]:
            lines.append(f"  {d}")
        lines.append("")
    if r["suspicious"]:
        lines.append("## SUSPICIOUS (single source) — corroborate")
        for d in r["suspicious"]:
            lines.append(f"  {d}")
        lines.append("")
    if r["unknown"]:
        lines.append("## UNKNOWN (blind spot — no source returned data)")
        for d in r["unknown"]:
            lines.append(f"  {d}")
        lines.append("")
    lines.append("---")
    lines.append("Per-indicator detail:")
    lines.append("")
    for rep in batch["results"]:
        lines.append(format_human(rep))
        lines.append("")
    return "\n".join(lines)


def _console():
    while True:
        print("\n=== Liao :: Reputation Lookup ===")
        print("Enter one or more IP / domain / file-hash to check.")
        print("(paste a list — newline/comma/space separated — or 0 to go back)")
        raw = input("> ").strip()
        if raw == "0":
            return
        if not raw:
            continue
        indicators = _split_indicators(raw)
        if len(indicators) == 1:
            print("\n" + format_human(lookup(indicators[0])))
            continue

        # Multiple: warn about pacing time and run with progress.
        est = int((len(indicators) - 1) * _VT_MIN_INTERVAL)
        print(f"\n{len(indicators)} indicators. Auto-pacing for VirusTotal's "
              f"4/min limit (~{est}s total). Sit tight...")

        def _progress(i, total, ind):
            print(f"  [{i}/{total}] {ind} ...")

        batch = lookup_batch(indicators, pace=True, progress=_progress)
        print("\n" + format_batch(batch))


def main():
    import sys
    if len(sys.argv) > 1 and sys.argv[1] != "--json":
        rep = lookup(sys.argv[1])
        if "--json" in sys.argv:
            print(json.dumps(rep, indent=2))
        else:
            print(format_human(rep))
    else:
        _console()


if __name__ == "__main__":
    main()
