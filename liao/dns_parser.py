#!/usr/bin/env python3
"""
dns_parser.py  —  NextDNS log threat detection
==============================================
Liao's DNS eye. Reads NextDNS logs — from a local CSV, a pasted blob, or
straight from a NextDNS logs URL — and surfaces the security-relevant patterns.

WHY DNS LOGS MATTER:
Malware has to find its C2 server, and exfiltration often rides over DNS. So a
device's DNS query history is where beaconing, domain-generation-algorithm
(DGA) callouts, and known-bad lookups show up — often before anything else.

WHAT IT FINDS (DNS detection signals from the threat model):
  - DGA-like domains   : high-entropy, random-looking labels (C2 tell)
  - Beaconing          : a domain queried at very regular intervals (C2 tell)
  - NRD hits           : NextDNS flagged a newly-registered domain
  - Suspicious TLDs     : TLDs disproportionately abused by malware
  - Bypass attempts     : queries NextDNS tagged as DNS-bypass methods
  - Blocked standouts   : the most-blocked domains (already stopped, but telling)
  - Rare destinations   : queries resolving to uncommon countries

WHAT IT DOES NOT DO:
Flags candidate DOMAINS, not verdicts. Feed flagged domains to rep_lookup.py
to corroborate, then bring the picture to Liao in the Project.

INPUT — three ways:
  1. Local CSV path      (Settings -> Logs -> Download Logs, imported to device)
  2. A NextDNS logs URL  (the Safari link; CSV or JSON, auto-detected)
  3. Pasted text         (CSV or JSON)

  URL SECURITY: a NextDNS logs URL embeds a token that grants read access to
  your DNS history — treat it as a secret. This tool stores it in the iOS
  Keychain (service 'liao_intel', account 'nextdns_logs_url'), NOT in source,
  so it never syncs to GitHub. Rotate the link in NextDNS if it leaks.

  Confirmed CSV schema (2026-10): timestamp, domain, query_type, dnssec,
  protocol, client_ip, status, reasons, destination_country, root_domain,
  device_id, device_name, ...  JSON entries are normalized to the same fields.
  Missing columns are tolerated.

Pythonista / iOS friendly: standard library only (csv, math, json, urllib).
Local CSV is streamed row-by-row (memory-safe on huge exports); URL/paste is
loaded into memory. ok-dict shapes. Menu-return. AUTHORIZED USE — your logs.

--- TIMELINE RETROFIT (2026-10-26) ---
Every finding carries event_time / first_seen / last_seen (ISO8601 UTC) +
time_source ("event") + client_ips, so ioc_timeline.py can place and correlate
it. event_time = last_seen (most-recent occurrence of that domain).
"""

import csv
import io
import json
import math
import re
from collections import defaultdict, Counter
from datetime import datetime, timezone


# --------------------------------------------------------------------------
# Tunables. DNS logs are noisy; these keep the signal readable.
# --------------------------------------------------------------------------
THRESHOLDS = {
    "dga_entropy": 3.6,          # bits/char above which a label looks random
    "dga_min_label_len": 10,     # only entropy-test labels at least this long
    "dga_min_hits": 3,           # report a DGA-ish domain seen >= this often
    "beacon_min_hits": 12,       # need this many queries to call it beaconing
    "beacon_regularity": 0.15,   # stddev/mean of intervals below this => regular
    "rare_country_max": 50,      # countries with <= this many hits are "rare"
    "top_n": 15,                 # list length for ranked sections
}

_SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".xyz", ".top", ".gq", ".ml", ".cf", ".tk", ".ga",
    ".work", ".click", ".link", ".rest", ".country", ".kim", ".loan",
    ".download", ".stream", ".racing", ".review", ".date", ".faith",
}

_DGA_ALLOW_ROOTS = {
    "gstatic.com", "googleapis.com", "apple.com", "icloud.com", "cloudflare.com",
    "cloudfront.net", "akamaized.net", "akamai.net", "amazonaws.com",
    "appsflyersdk.com", "crashlytics.com", "doubleclick.net", "gvt1.com",
    "fbcdn.net", "1e100.net", "windows.net", "azureedge.net", "anthropic.com",
    # ByteDance / TikTok CDN (hash-style hostnames; 2026-10-27 tuning)
    "tiktokv.us", "tiktokv.com", "tiktokcdn-us.com", "tiktokcdn.com",
    "ibyteimg.com", "byteimg.com",
}

# Keychain (iOS) — keeps the NextDNS logs URL out of synced source.
SERVICE = "liao_intel"
URL_ACCOUNT = "nextdns_logs_url"


def _shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_dga(domain):
    """Heuristic: the most-significant label is long, high-entropy, and not a
    known CDN/hash host. Returns True if it looks algorithm-generated."""
    domain = domain.strip().rstrip(".").lower()
    parts = domain.split(".")
    if len(parts) < 2:
        return False
    root = ".".join(parts[-2:])
    if root in _DGA_ALLOW_ROOTS:
        return False
    label = parts[0]
    if len(label) < THRESHOLDS["dga_min_label_len"]:
        return False
    if re.fullmatch(r"[0-9a-f]{8,}", label) or label.isdigit():
        return False
    ent = _shannon_entropy(label)
    vowels = sum(label.count(v) for v in "aeiou")
    vowel_ratio = vowels / len(label)
    return ent >= THRESHOLDS["dga_entropy"] and vowel_ratio < 0.30


def _tld_of(domain):
    domain = domain.strip().rstrip(".").lower()
    if "." not in domain:
        return None
    return "." + domain.rsplit(".", 1)[1]


def _parse_ts(ts):
    """NextDNS uses ISO8601 with Z. Return epoch seconds or None."""
    if not ts:
        return None
    try:
        ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return None


def _iso(ts):
    """Epoch seconds -> ISO8601 UTC, or None."""
    return datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts is not None else None


# --------------------------------------------------------------------------
# Row adapters — every source is normalized to the same dict shape:
#   {timestamp, domain, query_type, status, reasons, destination_country,
#    client_ip, root_domain, device_name}
# --------------------------------------------------------------------------

def _json_entry_to_row(e):
    """Map one NextDNS JSON log entry to the common row dict."""
    reasons = e.get("reasons")
    if isinstance(reasons, list):
        rstr = " ".join(
            " ".join(str(x) for x in (r.get("id"), r.get("name")) if x)
            if isinstance(r, dict) else str(r)
            for r in reasons
        )
    else:
        rstr = str(reasons or "")
    dev = e.get("device") if isinstance(e.get("device"), dict) else {}
    return {
        "timestamp": e.get("timestamp") or "",
        "domain": e.get("domain") or "",
        "query_type": e.get("type") or e.get("query_type") or "",
        "status": e.get("status") or "",
        "reasons": rstr,
        "destination_country": (e.get("destinationCountry")
                                or e.get("destination_country") or ""),
        "client_ip": e.get("clientIp") or e.get("client_ip") or "",
        "root_domain": e.get("root") or e.get("root_domain") or "",
        "device_name": dev.get("name", "") if dev else (e.get("device_name") or ""),
    }


def _rows_from_json_text(text):
    text = text.strip()
    entries = None
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            entries = obj.get("data") or obj.get("logs") or []
        elif isinstance(obj, list):
            entries = obj
    except ValueError:
        entries = []
        for line in text.splitlines():       # NDJSON fallback
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
    return [_json_entry_to_row(e) for e in (entries or []) if isinstance(e, dict)]


def _rows_from_csv_text(text):
    return list(csv.DictReader(io.StringIO(text)))


def _rows_from_text(text):
    """Auto-detect CSV vs JSON from a text blob -> list of row dicts."""
    s = text.lstrip()
    if s[:1] in ("{", "["):
        return _rows_from_json_text(text)
    return _rows_from_csv_text(text)


# --------------------------------------------------------------------------
# Core analysis — runs over any iterable of normalized row dicts.
# --------------------------------------------------------------------------

def analyze_rows(rows, max_rows=None, source="rows"):
    dga_hits = Counter()
    nrd_domains = Counter()
    bypass_domains = Counter()
    susp_tld = Counter()
    blocked = Counter()
    country = Counter()
    beacon_times = defaultdict(list)     # domain -> [epoch, ...]
    domain_span = {}                     # domain -> [min_ts, max_ts]
    domain_clients = defaultdict(set)    # domain -> {client_ip, ...}
    total = 0
    parsed = 0

    for row in rows:
        total += 1
        if max_rows and total > max_rows:
            total -= 1
            break
        domain = (row.get("domain") or "").strip().rstrip(".").lower()
        if not domain:
            continue
        parsed += 1

        ts = _parse_ts(row.get("timestamp"))
        if ts is not None:
            sp = domain_span.get(domain)
            if sp is None:
                domain_span[domain] = [ts, ts]
            else:
                if ts < sp[0]:
                    sp[0] = ts
                if ts > sp[1]:
                    sp[1] = ts
        cip = (row.get("client_ip") or "").strip()
        if cip and len(domain_clients[domain]) < 8:
            domain_clients[domain].add(cip)

        status = (row.get("status") or "").strip().lower()
        reasons = (row.get("reasons") or "").lower()
        ctry = (row.get("destination_country") or "").strip()

        if status == "blocked":
            blocked[domain] += 1
        if "nrd" in reasons:
            nrd_domains[domain] += 1
        if "bypass" in reasons:
            bypass_domains[domain] += 1
        if ctry:
            country[ctry] += 1

        tld = _tld_of(domain)
        if tld in _SUSPICIOUS_TLDS:
            susp_tld[domain] += 1
        if _looks_dga(domain):
            dga_hits[domain] += 1

        if status != "blocked" and ts is not None \
                and len(beacon_times[domain]) < 500:
            beacon_times[domain].append(ts)

    if parsed == 0:
        return {"ok": False, "error": "no_rows_parsed",
                "summary": "No usable DNS rows found (no 'domain' values). Is "
                           "this a NextDNS CSV/JSON export?",
                "analyzed_at": datetime.now(timezone.utc).isoformat(),
                "rows_total": total, "rows_parsed": 0,
                "findings": [], "suspect_domains": [], "top_blocked": [],
                "rare_countries": [], "source": source}

    # ---- Beaconing analysis ----
    beacons = []
    for domain, times in beacon_times.items():
        if len(times) < THRESHOLDS["beacon_min_hits"]:
            continue
        times.sort()
        intervals = [t2 - t1 for t1, t2 in zip(times, times[1:]) if t2 > t1]
        if len(intervals) < THRESHOLDS["beacon_min_hits"] - 1:
            continue
        mean = sum(intervals) / len(intervals)
        if mean <= 0:
            continue
        var = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        std = math.sqrt(var)
        regularity = std / mean
        if regularity <= THRESHOLDS["beacon_regularity"] and mean >= 30:
            beacons.append({"domain": domain, "hits": len(times),
                            "interval_sec": round(mean, 1),
                            "regularity": round(regularity, 3)})
    beacons.sort(key=lambda b: b["regularity"])

    def _timing(dom):
        sp = domain_span.get(dom)
        t = {"client_ips": sorted(domain_clients.get(dom, []))}
        if sp:
            t.update(event_time=_iso(sp[1]), first_seen=_iso(sp[0]),
                     last_seen=_iso(sp[1]), time_source="event")
        else:
            t.update(event_time=None, first_seen=None, last_seen=None,
                     time_source=None)
        return t

    findings = []
    suspects = set()

    for domain, n in dga_hits.most_common(THRESHOLDS["top_n"]):
        if n >= THRESHOLDS["dga_min_hits"]:
            findings.append({"type": "dga_like", "domain": domain,
                             "detail": f"high-entropy domain, {n} queries",
                             "severity": "high", **_timing(domain)})
            suspects.add(domain)

    for b in beacons[:THRESHOLDS["top_n"]]:
        findings.append({"type": "beaconing", "domain": b["domain"],
                         "detail": f"{b['hits']} queries every ~{b['interval_sec']}s "
                                   f"(regularity {b['regularity']})",
                         "severity": "high", **_timing(b["domain"])})
        suspects.add(b["domain"])

    for domain, n in nrd_domains.most_common(THRESHOLDS["top_n"]):
        findings.append({"type": "newly_registered_domain", "domain": domain,
                         "detail": f"NextDNS flagged NRD, {n} queries",
                         "severity": "medium", **_timing(domain)})
        suspects.add(domain)

    for domain, n in bypass_domains.most_common(THRESHOLDS["top_n"]):
        findings.append({"type": "dns_bypass", "domain": domain,
                         "detail": f"DNS-bypass method, {n} queries",
                         "severity": "medium", **_timing(domain)})
        suspects.add(domain)

    for domain, n in susp_tld.most_common(THRESHOLDS["top_n"]):
        findings.append({"type": "suspicious_tld", "domain": domain,
                         "detail": f"abuse-prone TLD, {n} queries",
                         "severity": "low", **_timing(domain)})
        suspects.add(domain)

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 9))

    rare = [{"country": c, "hits": n} for c, n in country.items()
            if n <= THRESHOLDS["rare_country_max"]]
    rare.sort(key=lambda x: x["hits"])

    if findings:
        summary = (f"{len(findings)} DNS pattern(s) flagged across {parsed} "
                   f"queries. Feed suspect domains to rep_lookup, then bring the "
                   f"picture to Liao.")
    else:
        summary = (f"No threshold-crossing DNS patterns across {parsed} queries. "
                   f"Not an all-clear — low-and-slow C2 can stay under these "
                   f"thresholds. Review blocked standouts and rare countries.")

    return {
        "ok": True,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "rows_total": total,
        "rows_parsed": parsed,
        "findings": findings,
        "suspect_domains": sorted(suspects),
        "top_blocked": [{"domain": d, "hits": n}
                        for d, n in blocked.most_common(THRESHOLDS["top_n"])],
        "rare_countries": rare[:THRESHOLDS["top_n"]],
        "summary": summary,
        "source": source,
        "error": None,
    }


# --------------------------------------------------------------------------
# Entry points: local CSV (streamed), text blob, or URL.
# --------------------------------------------------------------------------

def analyze_csv(path, max_rows=None):
    """Stream a local NextDNS CSV row-by-row (memory-safe on big exports)."""
    try:
        with open(path, newline="", errors="replace") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames or "domain" not in reader.fieldnames:
                # Maybe it's actually JSON saved with a .csv name — fall back.
                f.seek(0)
                head = f.read(2048).lstrip()
                if head[:1] in ("{", "["):
                    f.seek(0)
                    return analyze_rows(_rows_from_text(f.read()),
                                        max_rows=max_rows, source=f"file:{path}")
                return {"ok": False, "error": "not_a_nextdns_csv",
                        "summary": "No 'domain' column found. Is this a NextDNS "
                                   "CSV export?", "findings": [],
                        "suspect_domains": []}
            return analyze_rows(reader, max_rows=max_rows, source=f"file:{path}")
    except OSError as e:
        return {"ok": False, "error": f"read_failed: {e}",
                "summary": f"Could not read {path}.", "findings": [],
                "suspect_domains": []}


def analyze_text(text, max_rows=None):
    """Analyze a pasted CSV or JSON blob."""
    return analyze_rows(_rows_from_text(text), max_rows=max_rows, source="paste")


def analyze_url(url, max_rows=None, timeout=30):
    """
    Fetch a NextDNS logs URL (CSV or JSON) and analyze it.
    The URL token is the credential — plain GET, no header needed. On a 401/403
    the endpoint wants an API key; say so loudly rather than guessing.
    """
    import urllib.request
    import urllib.error
    req = urllib.request.Request(
        url, headers={"User-Agent": "liao-dns/1.0",
                      "Accept": "text/csv, application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        hint = ""
        if e.code in (401, 403):
            hint = (" The URL was rejected (auth). NextDNS may need an API key "
                    "header — if so, say the word and I'll add key support.")
        return {"ok": False, "error": f"http_{e.code}",
                "summary": f"Fetch failed: HTTP {e.code}.{hint} A failed fetch "
                           "is NOT an all-clear.",
                "findings": [], "suspect_domains": [], "source": "url"}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": type(e).__name__,
                "summary": f"Fetch failed: {type(e).__name__}. Check the URL and "
                           "network. A failed fetch is NOT an all-clear.",
                "findings": [], "suspect_domains": [], "source": "url"}

    text = raw.decode("utf-8", errors="replace")
    rep = analyze_rows(_rows_from_text(text), max_rows=max_rows, source="url")
    return rep


# --------------------------------------------------------------------------
# Keychain helpers for the NextDNS logs URL (iOS), env-var fallback elsewhere.
# --------------------------------------------------------------------------

def get_saved_url():
    try:
        import keychain
        v = keychain.get_password(SERVICE, URL_ACCOUNT)
        if v:
            return v.strip()
    except ImportError:
        pass
    import os
    v = os.environ.get("NEXTDNS_LOGS_URL")
    return v.strip() if v else None


def save_url(url):
    try:
        import keychain
        keychain.set_password(SERVICE, URL_ACCOUNT, url.strip())
        return True
    except ImportError:
        return False


def format_human(report):
    lines = ["# DNS Log Analysis (NextDNS)"]
    if not report.get("ok"):
        lines.append(f"** {report.get('summary') or report.get('error')}")
        return "\n".join(lines)
    lines.append(f"Analyzed: {report['analyzed_at']}  |  source: {report.get('source')}")
    lines.append(f"Queries: {report['rows_parsed']} parsed / "
                 f"{report['rows_total']} rows")
    lines.append("")
    lines.append(f"**{report['summary']}**")
    lines.append("")

    if report["findings"]:
        lines.append(f"## FINDINGS ({len(report['findings'])})")
        for f in report["findings"]:
            lines.append(f"- [{f['severity'].upper()}] {f['type']} — {f['domain']}")
            lines.append(f"    {f['detail']}")
            if f.get("last_seen"):
                lines.append(f"    seen {f['first_seen']} -> {f['last_seen']}")
    else:
        lines.append("## FINDINGS (0)")
        lines.append("  Nothing crossed thresholds (see summary caveat).")
    lines.append("")

    if report["suspect_domains"]:
        lines.append("## SUSPECT DOMAINS (run through rep_lookup)")
        for d in report["suspect_domains"]:
            lines.append(f"  {d}")
        lines.append("")

    lines.append("## TOP BLOCKED (already stopped, but telling)")
    for b in report["top_blocked"]:
        lines.append(f"  {b['domain']}  —  {b['hits']} blocked")
    lines.append("")

    if report["rare_countries"]:
        lines.append("## RARE DESTINATION COUNTRIES")
        for r in report["rare_countries"]:
            lines.append(f"  {r['country']}  —  {r['hits']} queries")
    return "\n".join(lines)


def _console():
    while True:
        print("\n=== Liao :: DNS Log Parser (NextDNS) ===")
        saved = get_saved_url()
        print(f"Saved URL: {'yes' if saved else 'no'}")
        print("1) Analyze a local NextDNS CSV by path")
        print("2) Analyze from NextDNS URL (paste once)")
        print("3) Analyze from SAVED NextDNS URL")
        print("4) Save a NextDNS URL to Keychain")
        print("5) Analyze local CSV, cap rows (faster on huge exports)")
        print("6) Raw JSON (from saved URL, else prompt path)")
        print("0) Back")
        choice = input("> ").strip()
        if choice == "1":
            path = input("Path to NextDNS CSV: ").strip()
            print("\nAnalyzing...")
            print(format_human(analyze_csv(path)))
        elif choice == "2":
            url = input("Paste NextDNS logs URL: ").strip()
            print("\nFetching + analyzing...")
            print(format_human(analyze_url(url)))
        elif choice == "3":
            if not saved:
                print("No saved URL. Use option 4 first.")
                continue
            print("\nFetching + analyzing...")
            print(format_human(analyze_url(saved)))
        elif choice == "4":
            url = input("Paste NextDNS logs URL to save: ").strip()
            if save_url(url):
                print("Saved to Keychain (service 'liao_intel').")
            else:
                print("Keychain unavailable here; set env NEXTDNS_LOGS_URL "
                      "instead.")
        elif choice == "5":
            path = input("Path to NextDNS CSV: ").strip()
            cap = input("Max rows [50000]: ").strip()
            cap = int(cap) if cap.isdigit() else 50000
            print(f"\nAnalyzing first {cap} rows...")
            print(format_human(analyze_csv(path, max_rows=cap)))
        elif choice == "6":
            if saved:
                print(json.dumps(analyze_url(saved), indent=2))
            else:
                path = input("Path to NextDNS CSV: ").strip()
                print(json.dumps(analyze_csv(path), indent=2))
        elif choice == "0":
            return
        else:
            print("?")


def main():
    import sys
    argv = sys.argv[1:]
    want_json = "--json" in argv
    rest = [a for a in argv if a != "--json"]
    rep = None
    if rest and (rest[0].startswith("http://") or rest[0].startswith("https://")):
        rep = analyze_url(rest[0])
    elif "--url" in argv:
        saved = get_saved_url()
        rep = analyze_url(saved) if saved else {
            "ok": False, "summary": "No saved URL (Keychain/env).",
            "error": "no_url", "findings": [], "suspect_domains": []}
    elif rest:
        rep = analyze_csv(rest[0])
    if rep is not None:
        print(json.dumps(rep, indent=2) if want_json else format_human(rep))
    else:
        _console()


if __name__ == "__main__":
    main()
