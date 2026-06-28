"""CDN analytics for RPZ Monitor."""
import os
import sqlite3
from datetime import datetime, timedelta

DB_PATH = "/opt/rpz-monitor/data/rpz-monitor.db"
LOG_PATH = "/var/log/pdns-query.log"
MAX_BYTES = 20 * 1024 * 1024
RETENTION_DAYS = 30

CDN_PATTERNS = {
    "YouTube/Google": ["youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com", "googleapis.com", "gvt1.com", "google.com", "google.co.id", "googleusercontent.com", "gstatic.com", "gstatic.cn", "googleadservices.com", "googlesyndication.com", "google-analytics.com", "googletagmanager.com", "doubleclick.net", "gvt2.com"],
    "TikTok": ["tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com", "ibyteimg.com", "ttlivecdn.com", "muscdn.com", "kwai-pro.com", "kwaipros.com", "tiktokcdn-us.com", "byteimg.com", "byted-static.com"],
    "Facebook/Meta": ["facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com", "whatsapp.net", "fbsbx.com", "messenger.com", "meta.com", "fb.com", "whatsapp.com"],
    "Netflix": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net", "nflxext.com"],
    "Shopee": ["shopee.co.id", "shopeemobile.com", "susercontent.com", "shopee.com", "shp.ee", "shopecdn.com"],
    "Telegram": ["telegram.org", "t.me", "cdn-telegram.org", "telegram-cdn.org"],
    "Cloudflare": ["cloudflare.com", "cloudflare.net", "r2.dev", "workers.dev"],
    "Akamai": ["akamai.net", "akamaiedge.net", "akamaihd.net", "edgesuite.net", "edgekey.net"],
    "Apple": ["apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com", "aaplimg.com", "apple-dns.net", "apple-cloudkit.com"],
    "Microsoft": ["microsoft.com", "windowsupdate.com", "office.com", "live.com", "msn.com", "azureedge.net", "office365.com", "outlook.com", "skype.com"],
    "X/Twitter": ["twitter.com", "x.com", "twimg.com"],
    "Naver": ["naver.com", "pstatic.net", "naver.net"],
    "Kwai/Kuaishou": ["kwai.com", "kuaishou.com", "ksapisrv.com", "kslawin.com"],
    "OPPO/Android": ["heytap.com", "heytapdl.com", "coloros.com", "oppomobile.com", "oppo.com"],
    "Tokopedia": ["tokopedia.com", "tokopedia.net", "tokocdn.net"],
    "Grab": ["grab.com", "grabtaxi.com", "grabcdn.com"],
    "Gojek": ["gojek.com", "gojekapi.com", "gopay.co.id"],
    "Roblox": ["roblox.com", "rbxcdn.com", "rbx.com"],
    "LINE": ["line-scdn.net", "line.me", "linecorp.com"],
    "Spotify": ["spotify.com", "spotifycdn.com", "scdn.co"],
    "Video/CDN": ["vidio.com", "hotstar.com", "iqiyi.com", "viu.com"],
}


def init_cdn_db(db_path=DB_PATH):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cdn_offsets (
                log_path TEXT PRIMARY KEY,
                inode INTEGER NOT NULL,
                offset INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cdn_queries (
                bucket TEXT NOT NULL,
                app TEXT NOT NULL,
                domain TEXT NOT NULL,
                qtype TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT NOT NULL,
                PRIMARY KEY (bucket, app, domain, qtype)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cdn_queries_bucket ON cdn_queries(bucket)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cdn_queries_app ON cdn_queries(app)")
        conn.commit()


def _classify(domain):
    d = domain.lower().strip().rstrip(".")
    for app, suffixes in CDN_PATTERNS.items():
        for suffix in suffixes:
            if d == suffix or d.endswith("." + suffix):
                return app
    return "Other"


def _bucket_5m(ts):
    dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    dt = dt.replace(minute=(dt.minute // 5) * 5, second=0, microsecond=0)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def parse_incremental(db_path=DB_PATH):
    init_cdn_db(db_path)
    stats = {"log_path": LOG_PATH, "parsed": 0, "skipped": 0, "bytes": 0, "offset": 0, "inode": None, "error": None}
    if not os.path.exists(LOG_PATH):
        stats["error"] = "log_not_found"
        return stats

    st = os.stat(LOG_PATH)
    inode = st.st_ino
    size = st.st_size
    stats["inode"] = inode

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT inode, offset FROM cdn_offsets WHERE log_path=?", (LOG_PATH,)).fetchone()
        offset = 0
        if row:
            old_inode, old_offset = row
            if old_inode == inode and old_offset <= size:
                offset = old_offset
        stats["offset"] = offset

        aggregates = {}
        read_bytes = 0
        with open(LOG_PATH, "rb") as f:
            f.seek(offset)
            while read_bytes < MAX_BYTES:
                line = f.readline()
                if not line:
                    break
                read_bytes += len(line)
                try:
                    text = line.decode("utf-8", "replace").strip()
                    ts, client_ip, domain, qtype = text.split("|", 3)
                    domain = domain.lower().strip().rstrip(".")
                    qtype = qtype.strip().upper()
                    bucket = _bucket_5m(ts.strip())
                    app = _classify(domain)
                    key = (bucket, app, domain, qtype)
                    if key not in aggregates:
                        aggregates[key] = [0, ts.strip()]
                    aggregates[key][0] += 1
                    aggregates[key][1] = ts.strip()
                    stats["parsed"] += 1
                except Exception:
                    stats["skipped"] += 1
            new_offset = f.tell()

        for (bucket, app, domain, qtype), (count, last_ts) in aggregates.items():
            conn.execute("""
                INSERT INTO cdn_queries (bucket, app, domain, qtype, count, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(bucket, app, domain, qtype) DO UPDATE SET
                    count = count + excluded.count,
                    last_seen = CASE WHEN excluded.last_seen > last_seen THEN excluded.last_seen ELSE last_seen END
            """, (bucket, app, domain, qtype, count, last_ts))

        cutoff = (datetime.now() - timedelta(days=RETENTION_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("DELETE FROM cdn_queries WHERE bucket < ?", (cutoff,))
        conn.execute("""
            INSERT INTO cdn_offsets (log_path, inode, offset, updated_at)
            VALUES (?, ?, ?, datetime('now'))
            ON CONFLICT(log_path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset, updated_at=excluded.updated_at
        """, (LOG_PATH, inode, new_offset))
        conn.commit()

    stats["bytes"] = read_bytes
    stats["offset"] = new_offset
    return stats


def _range_delta(range_str):
    return {"1h": timedelta(hours=1), "1d": timedelta(days=1), "7d": timedelta(days=7), "30d": timedelta(days=30)}.get(range_str, timedelta(days=1))


def get_cdn_data(db_path=DB_PATH, range_str="1d"):
    init_cdn_db(db_path)
    cutoff = (datetime.now() - _range_delta(range_str)).strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute("SELECT COALESCE(SUM(count),0) AS total FROM cdn_queries WHERE bucket >= ?", (cutoff,)).fetchone()["total"]
        apps = [dict(r) for r in conn.execute("""
            SELECT app, SUM(count) AS queries, MAX(last_seen) AS last_seen
            FROM cdn_queries WHERE bucket >= ?
            GROUP BY app ORDER BY queries DESC LIMIT 20
        """, (cutoff,))]
        for r in apps:
            r["percentage"] = round((r["queries"] / total * 100) if total else 0, 2)
        domains = [dict(r) for r in conn.execute("""
            SELECT app, domain, qtype, SUM(count) AS queries, MAX(last_seen) AS last_seen
            FROM cdn_queries WHERE bucket >= ?
            GROUP BY app, domain, qtype ORDER BY queries DESC LIMIT 100
        """, (cutoff,))]
        offset = conn.execute("SELECT inode, offset, updated_at FROM cdn_offsets WHERE log_path=?", (LOG_PATH,)).fetchone()
        stats = {"total_queries": total, "range": range_str, "cutoff": cutoff, "offset": dict(offset) if offset else None}
    return {"apps": apps, "domains": domains, "stats": stats}
