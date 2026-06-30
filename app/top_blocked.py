"""Top blocked domains analyzer for RPZ Monitor.

Strategy: RPZ zone files are huge (1.5GB+). We pre-extract domain names
into a compact cache file (~one domain per line). The cache is rebuilt
only when the zone file mtime changes. The cache file is loaded once
into a set and held in memory.

Background rebuild runs in a thread so the first request doesn't block.
"""
import os
import re
import sqlite3
import threading
from datetime import datetime, timedelta

RPZ_ZONES = [
    "/var/lib/powerdns/rpz-komdigi.zone",
    "/var/lib/powerdns/rpz-local.zone",
]

# Zone origins to strip from domain names
RPZ_ORIGINS = [".trustpositifkominfo", ".rpz.local", ".rpz-local"]

CACHE_DIR = "/opt/rpz-monitor/data"
CACHE_FILE = os.path.join(CACHE_DIR, "rpz-domains-cache.txt")
CACHE_META = os.path.join(CACHE_DIR, "rpz-domains-cache.meta")

# In-memory set of blocked domains (loaded from cache file)
_blocked_set: set = set()
_blocked_set_ready = threading.Event()
_blocked_set_loading = False
_domain_counts: dict = {}  # {zone_path: count}

# Regex to detect IP-like RPZ entries (reversed IPs)
_RE_IP = re.compile(r'^(\d+\.){3}\d+$')


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
    """Strip RPZ origin suffix, wildcard prefix, trailing dot.
    Returns clean domain string or None if should skip."""
    d = raw.lower().rstrip(".")

    # Strip wildcard prefix
    if d.startswith("*."):
        d = d[2:]

    # Strip RPZ origin suffix (e.g. .trustpositifkominfo)
    for suffix in origin_suffixes:
        if d.endswith(suffix):
            d = d[:-len(suffix)]
            break

    d = d.rstrip(".")
    if not d or d == "@" or d.isdigit():
        return None

    # Skip reversed-IP entries (RPZ sometimes blocks by IP)
    if _RE_IP.match(d):
        return None

    return d


def _build_cache():
    """Stream-parse RPZ zone files, extract domain names, write to cache file."""
    global _blocked_set_loading
    _blocked_set_loading = True
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
                    # Strip inline comments
                    line = raw_line.split(";")[0].strip()
                    if not line or line.startswith("$"):
                        continue

                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    # Find record type
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

                    # Clean domain: strip origin suffix, wildcard, trailing dot
                    domain = _clean_domain(parts[0], RPZ_ORIGINS)
                    if domain is None:
                        continue

                    domains.add(domain)
                    count += 1
        except Exception as e:
            print(f"[top_blocked] Error parsing {zone_path}: {e}", flush=True)

        counts[zone_path] = count
        print(f"[top_blocked] Parsed {zone_path}: {count} records -> {len(domains)} unique clean domains", flush=True)

    # Write cache file
    try:
        tmp = CACHE_FILE + ".tmp"
        with open(tmp, "w") as f:
            for d in sorted(domains):
                f.write(d + "\n")
        os.replace(tmp, CACHE_FILE)

        meta_lines = [f"{p}={_zone_mtime(p)}" for p in RPZ_ZONES]
        with open(CACHE_META, "w") as f:
            f.write("\n".join(meta_lines) + "\n")

        print(f"[top_blocked] Cache built: {len(domains)} unique domains -> {CACHE_FILE}", flush=True)
    except Exception as e:
        print(f"[top_blocked] Cache write error: {e}", flush=True)

    global _blocked_set, _domain_counts
    _blocked_set = domains
    _domain_counts = counts
    _blocked_set_ready.set()
    _blocked_set_loading = False


def _ensure_loaded():
    """Ensure the blocked domain set is loaded."""
    global _blocked_set_loading

    if _blocked_set_ready.is_set():
        if os.path.exists(CACHE_META):
            with open(CACHE_META, "r") as f:
                meta = f.read()
            if _meta_matches(meta):
                return
            _blocked_set_ready.clear()
        else:
            _blocked_set_ready.clear()

    if _blocked_set_loading:
        return

    # Try loading from cache file if meta matches
    if os.path.exists(CACHE_FILE) and os.path.exists(CACHE_META):
        with open(CACHE_META, "r") as f:
            meta = f.read()
        if _meta_matches(meta):
            try:
                with open(CACHE_FILE, "r") as f:
                    _blocked_set.clear()
                    for line in f:
                        d = line.strip()
                        if d:
                            _blocked_set.add(d)
                _domain_counts = {}
                for p in RPZ_ZONES:
                    _domain_counts[p] = len(_blocked_set)
                _blocked_set_ready.set()
                print(f"[top_blocked] Loaded {len(_blocked_set)} domains from cache file", flush=True)
                return
            except Exception:
                pass

    # Full rebuild in background thread
    t = threading.Thread(target=_build_cache, daemon=True)
    t.start()


def get_all_blocked_domains():
    """Get combined set of all blocked domains from cache."""
    _ensure_loaded()
    if _blocked_set_ready.is_set():
        return _blocked_set
    _blocked_set_ready.wait(timeout=300)
    return _blocked_set


def get_top_blocked(db_path, range_str="1d", limit=100):
    """Get top blocked domains from CDN DB cross-referenced with RPZ zones."""
    range_deltas = {
        "1h": timedelta(hours=1),
        "1d": timedelta(days=1),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    delta = range_deltas.get(range_str, timedelta(days=1))
    cutoff = (datetime.now() - delta).strftime("%Y-%m-%d %H:%M:%S")

    blocked = get_all_blocked_domains()

    cache_info = {}
    for zone_path in RPZ_ZONES:
        name = os.path.basename(zone_path)
        if zone_path in _domain_counts:
            cache_info[name] = _domain_counts[zone_path]
        elif os.path.exists(zone_path):
            cache_info[name] = "loading..."
        else:
            cache_info[name] = "not found"

    if not blocked:
        return {
            "top_blocked": [],
            "total_blocked_queries": 0,
            "total_queries": 0,
            "blocked_percentage": 0,
            "cache_info": {**cache_info, "error": "No RPZ domains loaded"},
        }

    limit = max(1, int(limit))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        total_queries = conn.execute(
            "SELECT COALESCE(SUM(count), 0) FROM cdn_queries WHERE bucket >= ?",
            (cutoff,),
        ).fetchone()[0]

        rows = conn.execute("""
            SELECT domain, app, qtype, SUM(count) AS queries, MAX(last_seen) AS last_seen
            FROM cdn_queries
            WHERE bucket >= ?
            GROUP BY app, domain, qtype
            ORDER BY queries DESC
        """, (cutoff,)).fetchall()
    finally:
        conn.close()

    top_blocked = []
    total_blocked_queries = 0
    for row in rows:
        domain = row["domain"].lower().strip().rstrip(".")
        is_blocked = False
        if domain in blocked:
            is_blocked = True
        else:
            # Check parent domains
            parts = domain.split(".")
            for i in range(1, len(parts)):
                if ".".join(parts[i:]) in blocked:
                    is_blocked = True
                    break

        if is_blocked:
            total_blocked_queries += row["queries"]
            if len(top_blocked) < limit:
                top_blocked.append({
                    "domain": row["domain"],
                    "queries": row["queries"],
                    "app": row["app"],
                    "qtype": row["qtype"],
                    "last_seen": row["last_seen"],
                })

    blocked_pct = round((total_blocked_queries / total_queries * 100) if total_queries > 0 else 0, 2)

    cache_info["loaded_domains"] = len(blocked)
    cache_info["building"] = _blocked_set_loading

    return {
        "top_blocked": top_blocked,
        "total_blocked_queries": total_blocked_queries,
        "total_queries": total_queries,
        "blocked_percentage": blocked_pct,
        "cache_info": cache_info,
    }


def rebuild_cache():
    """Force rebuild the cache."""
    global _blocked_set_loading
    if _blocked_set_loading:
        return {"status": "already building"}
    _blocked_set_ready.clear()
    t = threading.Thread(target=_build_cache, daemon=True)
    t.start()
    return {"status": "rebuild started"}
