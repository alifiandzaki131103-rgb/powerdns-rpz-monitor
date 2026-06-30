"""Top blocked domains analyzer for RPZ Monitor.

Strategy: RPZ zone files are huge (1.5GB+). We pre-extract domain names
into a sorted cache file. Membership checks use mmap + binary search
so we DON'T load 9M strings into a Python set (saves ~1.3GB RAM).

Background rebuild runs in a thread so the first request doesn't block.
Results are cached for 60s to avoid re-scanning on every page load.
"""
import os
import mmap
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from bisect import bisect_left

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

# mmap'd cache file (lazy init)
_mmap_obj = None
_mmap_lines = []  # list of (start, end) byte offsets for each line
_mmap_mtime = 0

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

    # Free the set immediately
    del domains
    del sorted_domains

    _cache_ready.set()
    _cache_loading = False


def _load_mmap():
    """Load the sorted cache file via mmap for zero-copy binary search."""
    global _mmap_obj, _mmap_lines, _mmap_mtime

    if not os.path.exists(CACHE_FILE):
        return False

    mtime = os.path.getmtime(CACHE_FILE)
    if _mmap_obj is not None and _mmap_mtime == mtime:
        return True

    try:
        fd = os.open(CACHE_FILE, os.O_RDONLY)
        size = os.fstat(fd).st_size
        if size == 0:
            os.close(fd)
            return False

        mm = mmap.mmap(fd, size, access=mmap.ACCESS_READ)
        os.close(fd)

        # Build line index (start offsets)
        lines = []
        pos = 0
        while pos < size:
            end = mm.find(b'\n', pos)
            if end == -1:
                end = size
            if end > pos:  # skip empty lines
                lines.append((pos, end))
            pos = end + 1

        # Replace old mmap
        if _mmap_obj is not None:
            try:
                _mmap_obj.close()
            except Exception:
                pass

        _mmap_obj = mm
        _mmap_lines = lines
        _mmap_mtime = mtime
        return True
    except Exception as e:
        print(f"[top_blocked] mmap error: {e}", flush=True)
        return False


def _is_blocked(domain):
    """Check if domain (or parent) is in the blocked cache via mmap binary search."""
    if not _load_mmap():
        return False

    mm = _mmap_obj
    lines = _mmap_lines

    # Check domain and all parent domains
    parts = domain.lower().strip().rstrip(".").split(".")
    for i in range(len(parts)):
        check = ".".join(parts[i:]).encode("utf-8")
        # Binary search in sorted lines using bytes comparison
        lo, hi = 0, len(lines)
        while lo < hi:
            mid = (lo + hi) // 2
            start, end = lines[mid]
            mid_val = mm[start:end]
            if mid_val < check:
                lo = mid + 1
            else:
                hi = mid
        if lo < len(lines):
            start, end = lines[lo]
            if mm[start:end] == check:
                return True

    return False


def _warm_mmap():
    """Pre-build mmap index in background at startup."""
    if os.path.exists(CACHE_FILE) and os.path.exists(CACHE_META):
        with open(CACHE_META, "r") as f:
            meta = f.read()
        if _meta_matches(meta):
            _cache_ready.set()
            _load_mmap()
            print(f"[top_blocked] mmap warmed: {len(_mmap_lines)} domains indexed", flush=True)
            return
    # If cache doesn't exist or is stale, build it
    _build_cache()
    _load_mmap()
    print(f"[top_blocked] mmap warmed after build: {len(_mmap_lines)} domains", flush=True)


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

    # Force reload mmap if needed
    _load_mmap()

    limit = max(1, int(limit))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        total_queries = conn.execute(
            "SELECT COALESCE(SUM(count), 0) FROM cdn_queries WHERE bucket >= ?",
            (cutoff,),
        ).fetchone()[0]

        # Only fetch top N*5 rows to avoid scanning entire DB
        # Some won't be blocked, so fetch extra buffer
        fetch_limit = min(limit * 5, 5000)
        rows = conn.execute("""
            SELECT domain, app, qtype, SUM(count) AS queries, MAX(last_seen) AS last_seen
            FROM cdn_queries
            WHERE bucket >= ?
            GROUP BY app, domain, qtype
            ORDER BY queries DESC
            LIMIT ?
        """, (cutoff, fetch_limit)).fetchall()
    finally:
        conn.close()

    top_blocked = []
    total_blocked_queries = 0
    for row in rows:
        domain = row["domain"].lower().strip().rstrip(".")
        if _is_blocked(domain):
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

    cache_info["loaded_domains"] = len(_mmap_lines) if _mmap_lines else 0
    cache_info["building"] = _cache_loading

    result = {
        "top_blocked": top_blocked,
        "total_blocked_queries": total_blocked_queries,
        "total_queries": total_queries,
        "blocked_percentage": blocked_pct,
        "cache_info": cache_info,
    }

    # Store in result cache
    _result_cache[cache_key] = (now, result)
    return result


def rebuild_cache():
    """Force rebuild the cache."""
    global _cache_loading
    if _cache_loading:
        return {"status": "already building"}
    _cache_ready.clear()
    _result_cache.clear()  # Also clear result cache on rebuild
    t = threading.Thread(target=_build_cache, daemon=True)
    t.start()
    return {"status": "rebuild started"}


def invalidate_result_cache():
    """Clear the result cache (call after rebuild completes)."""
    _result_cache.clear()


# Auto-warm mmap on import (non-blocking)
try:
    _warmup_thread = threading.Thread(target=_warm_mmap, daemon=True)
    _warmup_thread.start()
except Exception:
    pass
