"""Top blocked domains analyzer for RPZ Monitor."""
import os
import sqlite3
from datetime import datetime, timedelta

RPZ_ZONES = [
    "/var/lib/powerdns/rpz-komdigi.zone",
    "/var/lib/powerdns/rpz-local.zone",
]

# Cache: {filepath: (mtime, set_of_domains)}
_domain_cache = {}

_RECORD_TYPES = {
    "A", "AAAA", "AFSDB", "APL", "CAA", "CDNSKEY", "CDS", "CERT", "CNAME",
    "CSYNC", "DHCID", "DLV", "DNAME", "DNSKEY", "DS", "EUI48", "EUI64", "HINFO",
    "HIP", "HTTPS", "IPSECKEY", "KEY", "KX", "LOC", "MX", "NAPTR", "NS", "NSEC",
    "NSEC3", "NSEC3PARAM", "OPENPGPKEY", "PTR", "RRSIG", "RP", "SIG", "SMIMEA",
    "SOA", "SRV", "SSHFP", "SVCB", "TA", "TKEY", "TLSA", "TSIG", "TXT", "URI",
}


def _strip_comment(line):
    """Strip BIND comments while respecting quoted strings."""
    in_quote = False
    escaped = False
    for idx, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            in_quote = not in_quote
            continue
        if char == ";" and not in_quote:
            return line[:idx]
    return line


def _record_type(parts):
    """Return RR type from token list, or None."""
    for part in parts[1:5]:
        upper = part.upper()
        if upper == "IN" or part.isdigit():
            continue
        if upper in _RECORD_TYPES:
            return upper
    return None


def _load_rpz_domains(zone_path):
    """Load blocked domains from RPZ zone file. Returns set of lowercase domain names.
    Only reads file if mtime changed since last read.
    """
    if not os.path.exists(zone_path):
        return set()

    try:
        mtime = os.path.getmtime(zone_path)
    except OSError:
        return set()

    cached = _domain_cache.get(zone_path)
    if cached and cached[0] == mtime:
        return cached[1]

    domains = set()
    try:
        with open(zone_path, "r", errors="replace") as f:
            for raw_line in f:
                line = _strip_comment(raw_line).strip()
                if not line or line.startswith("$"):
                    continue

                parts = line.split()
                if len(parts) < 2:
                    continue

                rr_type = _record_type(parts)
                if rr_type in (None, "SOA", "NS"):
                    continue

                domain = parts[0].lower().rstrip(".")
                if not domain or domain == "@" or domain.isdigit():
                    continue

                # RPZ policy records are usually CNAME ., but keep other policy RR types too.
                domains.add(domain)
    except Exception:
        domains = set()

    _domain_cache[zone_path] = (mtime, domains)
    return domains


def get_all_blocked_domains():
    """Get combined set of all blocked domains from all RPZ zones."""
    all_domains = set()
    for zone_path in RPZ_ZONES:
        all_domains.update(_load_rpz_domains(zone_path))
    return all_domains


def _matched_zone_count():
    cache_info = {}
    for zone_path in RPZ_ZONES:
        if zone_path in _domain_cache:
            cache_info[os.path.basename(zone_path)] = len(_domain_cache[zone_path][1])
        else:
            cache_info[os.path.basename(zone_path)] = 0
    return cache_info


def _is_blocked(domain, blocked):
    if domain in blocked:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in blocked:
            return True
    return False


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
    if not blocked:
        return {
            "top_blocked": [],
            "total_blocked_queries": 0,
            "total_queries": 0,
            "blocked_percentage": 0,
            "cache_info": {"error": "No RPZ zone files found", **_matched_zone_count()},
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
        if _is_blocked(domain, blocked):
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
    return {
        "top_blocked": top_blocked,
        "total_blocked_queries": total_blocked_queries,
        "total_queries": total_queries,
        "blocked_percentage": blocked_pct,
        "cache_info": _matched_zone_count(),
    }
