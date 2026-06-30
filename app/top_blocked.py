"""Top blocked domains analyzer for RPZ Monitor.

Strategy: RPZ zone files are huge (1.5GB+). We pre-extract domain names
into a sorted cache file. To check if CDN domains are blocked:
1. Build a set of all CDN domains + their parent domains (~900K entries)
2. Scan the 196MB cache file once, collecting matches (~3-4s)
3. Map matches back to CDN domains for stats

Results cached 60s. mmap pre-warmed at startup.
"""
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta

RPZ_ZONES = [
    "/var/lib/powerdns/rpz-komdigi.zone",
    "/var/lib/powerdns/rpz-local.zone",
]

RPZ_ORIGINS = [".trustpositifkominfo", ".rpz.local", ".rpz-local"]

CACHE_DIR = "/opt/rpz-monitor/data"
CACHE_FILE = os.path.join(CACHE_DIR, "rpz-domains-cache.txt")
CACHE_META = os.path.join(CACHE_DIR, "rpz-domains-cache.meta")

# State
_cache_ready = threading.Event()
_cache_loading = False
_domain_count = 0
_zone_counts: dict = {}

_RE_IP = re.compile(r'^(\d+\.){3}\d+$')

# Result cache: {(range_str, limit): (timestamp, result_dict)}
_result_cache = {}
_RESULT_TTL = 60  # seconds


def _zone_mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0


def _current_meta():
    return {p: _zone_mtime(p) for p in RPZ_ZONES}


def _meta_matches(meta_str):
    current = _current_meta()
    try:
        cached = {}
        for line in meta_str.strip().split("\n"):
            if "=" in line:
                k, v = line.rsplit("=", 1)
                cached[k] = float(v)
        return current == cached
    except Exception:
        return False


def _clean_domain(raw, origin_suffixes):
    """Strip RPZ origin suffix, wildcard prefix, trailing dot."""
    d = raw.lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    for suffix in origin_suffixes:
        if d.endswith(suffix):
            d = d[:-len(suffix)]
            break
    d = d.rstrip(".")
    if not d or d == "@" or d.isdigit():
        return None
    if _RE_IP.match(d):
        return None
    return d


def _build_cache():
    """Stream-parse RPZ zone files, extract domain names, write sorted cache."""
    global _cache_loading, _domain_count, _zone_counts
    _cache_loading = True
    os.makedirs(CACHE_DIR, exist_ok=True)

    record_types = {
        "A", "AAAA", "AFSDB", "APL", "CAA", "CDNSKEY", "CDS", "CERT", "CNAME",
        "CSYNC", "DHCID", "DLV", "DNAME", "DNSKEY", "DS", "EUI48", "EUI64",
        "HINFO", "HIP", "HTTPS", "IPSECKEY", "KEY", "KX", "LOC", "MX", "NAPTR",
        "NS", "NSEC", "NSEC3", "NSEC3PARAM", "OPENPGPKEY", "PTR", "RRSIG", "RP",
        "SIG", "SMIMEA", "SOA", "SRV", "SSHFP", "SVCB", "TA", "TKEY", "TLSA",
        "TSIG", "TXT", "URI",
    }
    skip_types = {"SOA", "NS"}

    domains = set()
    counts = {}

    for zone_path in RPZ_ZONES:
        count = 0
        if not os.path.exists(zone_path):
            counts[zone_path] = 0
            continue
        try:
            with open(zone_path, "r", errors="replace") as f:
                for raw_line in f:
                    line = raw_line.split(";")[0].strip()
                    if not line or line.startswith("$"):
                        continue
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    rr_type = None
                    for p in parts[1:5]:
                        up = p.upper()
                        if up == "IN" or p.isdigit():
                            continue
                        if up in record_types:
                            rr_type = up
                            break
                    if rr_type in (None, *skip_types):
                        continue
                    domain = _clean_domain(parts[0], RPZ_ORIGINS)
                    if domain is None:
                        continue
                    domains.add(domain)
                    count += 1
        except Exception as e:
            print(f"[top_blocked] Error parsing {zone_path}: {e}", flush=True)
        counts[zone_path] = count
        print(f"[top_blocked] Parsed {zone_path}: {count} records -> {len(domains)} unique", flush=True)

    # Write sorted cache file
    try:
        tmp = CACHE_FILE + ".tmp"
        sorted_domains = sorted(domains)
        with open(tmp, "w") as f:
            for d in sorted_domains:
                f.write(d + "\n")
        os.replace(tmp, CACHE_FILE)

        meta_lines = [f"{p}={_zone_mtime(p)}" for p in RPZ_ZONES]
        with open(CACHE_META, "w") as f:
            f.write("\n".join(meta_lines) + "\n")

        _domain_count = len(sorted_domains)
        _zone_counts = counts
        print(f"[top_blocked] Cache built: {_domain_count} domains -> {CACHE_FILE}", flush=True)
    except Exception as e:
        print(f"[top_blocked] Cache write error: {e}", flush=True)

    del domains
    del sorted_domains

    _cache_ready.set()
    _cache_loading = False


def _ensure_cache():
    """Ensure cache file exists and is current."""
    global _cache_loading

    if _cache_ready.is_set():
        if os.path.exists(CACHE_META):
            with open(CACHE_META, "r") as f:
                meta = f.read()
            if _meta_matches(meta):
                return
            _cache_ready.clear()
        else:
            _cache_ready.clear()

    if _cache_loading:
        return

    if os.path.exists(CACHE_FILE) and os.path.exists(CACHE_META):
        with open(CACHE_META, "r") as f:
            meta = f.read()
        if _meta_matches(meta):
            _cache_ready.set()
            return

    t = threading.Thread(target=_build_cache, daemon=True)
    t.start()


def _scan_blocked_domains(cdn_domain_list):
    """Scan RPZ cache file for blocked CDN domains using set intersection.

    Returns set of blocked CDN domain strings.
    """
    # Step 1: Build set of all CDN domains + their parent domains
    check_domains = set()
    for d in cdn_domain_list:
        parts = d.split(".")
        for i in range(len(parts)):
            check_domains.add(".".join(parts[i:]))

    # Step 2: Scan cache file, collect matching RPZ entries
    matched_rpz = set()
    try:
        with open(CACHE_FILE, "r") as f:
            for line in f:
                d = line.rstrip("\n")
                if d in check_domains:
                    matched_rpz.add(d)
    except Exception as e:
        print(f"[top_blocked] Cache scan error: {e}", flush=True)
        return set()

    # Step 3: Map matches back to CDN domains
    blocked = set()
    for cdn_d in cdn_domain_list:
        parts = cdn_d.split(".")
        for i in range(len(parts)):
            if ".".join(parts[i:]) in matched_rpz:
                blocked.add(cdn_d)
                break

    return blocked


def get_top_blocked(db_path, range_str="1d", limit=100):
    """Get top blocked domains from CDN DB cross-referenced with RPZ zones."""
    _ensure_cache()

    # Check result cache
    cache_key = (range_str, int(limit))
    now = time.time()
    if cache_key in _result_cache:
        ts, result = _result_cache[cache_key]
        if now - ts < _RESULT_TTL:
            return result

    range_deltas = {
        "1h": timedelta(hours=1),
        "1d": timedelta(days=1),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    delta = range_deltas.get(range_str, timedelta(days=1))
    cutoff = (datetime.now() - delta).strftime("%Y-%m-%d %H:%M:%S")

    cache_info = {}
    for zone_path in RPZ_ZONES:
        name = os.path.basename(zone_path)
        if zone_path in _zone_counts:
            cache_info[name] = _zone_counts[zone_path]
        elif os.path.exists(zone_path):
            cache_info[name] = "loading..."
        else:
            cache_info[name] = "not found"

    if not _cache_ready.is_set():
        return {
            "top_blocked": [],
            "total_blocked_queries": 0,
            "total_queries": 0,
            "blocked_percentage": 0,
            "cache_info": {**cache_info, "status": "building..."},
        }

    limit = max(1, int(limit))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        total_queries = conn.execute(
            "SELECT COALESCE(SUM(count), 0) FROM cdn_queries WHERE bucket >= ?",
            (cutoff,),
        ).fetchone()[0]

        # Step 1: Get all unique domains with total query count
        domain_rows = conn.execute("""
            SELECT domain, SUM(count) AS queries
            FROM cdn_queries
            WHERE bucket >= ?
            GROUP BY domain
            ORDER BY queries DESC
        """, (cutoff,)).fetchall()

        # Step 2: Scan RPZ cache for blocked domains
        cdn_domain_list = [row["domain"].lower().strip().rstrip(".") for row in domain_rows]
        blocked_set = _scan_blocked_domains(cdn_domain_list)

        # Step 3: Compute total blocked queries
        total_blocked_queries = 0
        blocked_domain_queries = {}
        for row in domain_rows:
            d = row["domain"].lower().strip().rstrip(".")
            if d in blocked_set:
                total_blocked_queries += row["queries"]
                blocked_domain_queries[d] = row["queries"]

        # Step 4: Fetch full details for top blocked domains
        top_blocked = []
        if blocked_set:
            # Sort blocked domains by query count, take top N
            top_blocked_domains = sorted(blocked_domain_queries.items(), key=lambda x: -x[1])[:limit]
            top_domain_set = {d for d, _ in top_blocked_domains}

            placeholders = ",".join("?" * len(top_domain_set))
            detail_rows = conn.execute(f"""
                SELECT domain, app, qtype, SUM(count) AS queries, MAX(last_seen) AS last_seen
                FROM cdn_queries
                WHERE bucket >= ? AND domain IN ({placeholders})
                GROUP BY app, domain, qtype
                ORDER BY queries DESC
                LIMIT ?
            """, [cutoff, *top_domain_set, limit]).fetchall()

            for row in detail_rows:
                top_blocked.append({
                    "domain": row["domain"],
                    "queries": row["queries"],
                    "app": row["app"],
                    "qtype": row["qtype"],
                    "last_seen": row["last_seen"],
                })

    finally:
        conn.close()

    blocked_pct = round((total_blocked_queries / total_queries * 100) if total_queries > 0 else 0, 2)

    cache_info["loaded_domains"] = _domain_count
    cache_info["building"] = _cache_loading

    result = {
        "top_blocked": top_blocked,
        "total_blocked_queries": total_blocked_queries,
        "total_queries": total_queries,
        "blocked_percentage": blocked_pct,
        "cache_info": cache_info,
    }

    _result_cache[cache_key] = (now, result)
    return result


def rebuild_cache():
    """Force rebuild the cache."""
    global _cache_loading
    if _cache_loading:
        return {"status": "already building"}
    _cache_ready.clear()
    _result_cache.clear()
    t = threading.Thread(target=_build_cache, daemon=True)
    t.start()
    return {"status": "rebuild started"}


def invalidate_result_cache():
    """Clear the result cache."""
    _result_cache.clear()


def _warm_cache():
    """Pre-check cache file exists and is current at startup."""
    if os.path.exists(CACHE_FILE) and os.path.exists(CACHE_META):
        with open(CACHE_META, "r") as f:
            meta = f.read()
        if _meta_matches(meta):
            _cache_ready.set()
            global _domain_count
            try:
                with open(CACHE_FILE, "r") as f:
                    _domain_count = sum(1 for _ in f)
            except Exception:
                pass
            print(f"[top_blocked] cache ready: {_domain_count} domains", flush=True)
            return
    _build_cache()


# Auto-warm on import (non-blocking)
try:
    _warmup_thread = threading.Thread(target=_warm_cache, daemon=True)
    _warmup_thread.start()
except Exception:
    pass
