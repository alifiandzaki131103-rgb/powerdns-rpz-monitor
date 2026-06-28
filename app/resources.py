"""System resource collection and time-series storage."""
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import psutil

APP_TZ = timezone(timedelta(hours=7))
RANGES = {"1h": "-1 hour", "6h": "-6 hours", "1d": "-1 day", "7d": "-7 days"}


def init_resource_db(db_path):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS resource_samples(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                ram_used_mb REAL,
                ram_total_mb REAL,
                ram_percent REAL,
                disk_used_gb REAL,
                disk_total_gb REAL,
                disk_percent REAL,
                net_sent_mb REAL,
                net_recv_mb REAL,
                load_1 REAL,
                load_5 REAL,
                load_15 REAL,
                pdns_cpu_percent REAL,
                pdns_rss_mb REAL,
                pdns_fds INTEGER,
                pdns_threads INTEGER
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_resource_samples_ts ON resource_samples(ts)")
        conn.commit()


def _format_uptime(seconds):
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    return f"{hours}h {minutes}m"


def _find_pdns_process():
    names = ("pdns_recursor", "pdns-recursor")
    for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
        try:
            name = proc.info.get("name") or ""
            cmdline = " ".join(proc.info.get("cmdline") or [])
            haystack = f"{name} {cmdline}".lower()
            if any(n in haystack for n in names):
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def get_current_stats():
    cpu_total = psutil.cpu_percent(interval=None)
    cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    load_1, load_5, load_15 = os.getloadavg()
    boot = datetime.fromtimestamp(psutil.boot_time(), APP_TZ)
    uptime_seconds = max(0, int((datetime.now(APP_TZ) - boot).total_seconds()))

    pdns = {"pid": None, "cpu_percent": 0.0, "rss_mb": 0.0, "fds": 0, "threads": 0, "uptime": "N/A", "uptime_seconds": 0}
    proc = _find_pdns_process()
    if proc:
        try:
            with proc.oneshot():
                create_time = datetime.fromtimestamp(proc.create_time(), APP_TZ)
                pdns_uptime_seconds = max(0, int((datetime.now(APP_TZ) - create_time).total_seconds()))
                pdns.update({
                    "pid": proc.pid,
                    "cpu_percent": round(proc.cpu_percent(interval=None), 1),
                    "rss_mb": round(proc.memory_info().rss / 1024 / 1024, 1),
                    "fds": proc.num_fds() if hasattr(proc, "num_fds") else 0,
                    "threads": proc.num_threads(),
                    "uptime": _format_uptime(pdns_uptime_seconds),
                    "uptime_seconds": pdns_uptime_seconds,
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return {
        "timestamp": datetime.now(APP_TZ).strftime("%Y-%m-%d %H:%M:%S WIB"),
        "cpu_percent": round(cpu_total, 1),
        "cpu_per_core": [round(x, 1) for x in cpu_per_core],
        "ram_used_mb": round(mem.used / 1024 / 1024, 1),
        "ram_total_mb": round(mem.total / 1024 / 1024, 1),
        "ram_percent": round(mem.percent, 1),
        "disk_used_gb": round(disk.used / 1024 / 1024 / 1024, 1),
        "disk_total_gb": round(disk.total / 1024 / 1024 / 1024, 1),
        "disk_percent": round(disk.percent, 1),
        "net_sent_mb": round(net.bytes_sent / 1024 / 1024, 1),
        "net_recv_mb": round(net.bytes_recv / 1024 / 1024, 1),
        "load_1": round(load_1, 2),
        "load_5": round(load_5, 2),
        "load_15": round(load_15, 2),
        "pdns": pdns,
        "system_uptime": _format_uptime(uptime_seconds),
        "system_uptime_seconds": uptime_seconds,
    }


def collect_and_store(db_path):
    init_resource_db(db_path)
    s = get_current_stats()
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            INSERT INTO resource_samples(cpu_percent, ram_used_mb, ram_total_mb, ram_percent, disk_used_gb, disk_total_gb, disk_percent, net_sent_mb, net_recv_mb, load_1, load_5, load_15, pdns_cpu_percent, pdns_rss_mb, pdns_fds, pdns_threads)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (s["cpu_percent"], s["ram_used_mb"], s["ram_total_mb"], s["ram_percent"], s["disk_used_gb"], s["disk_total_gb"], s["disk_percent"], s["net_sent_mb"], s["net_recv_mb"], s["load_1"], s["load_5"], s["load_15"], s["pdns"]["cpu_percent"], s["pdns"]["rss_mb"], s["pdns"]["fds"], s["pdns"]["threads"]))
        conn.execute("DELETE FROM resource_samples WHERE ts < datetime('now', '-7 days')")
        conn.commit()
    return s


def get_resource_data(db_path, range_str="1h"):
    range_sql = RANGES.get(range_str, RANGES["1h"])
    init_resource_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM resource_samples WHERE ts >= datetime('now', ?) ORDER BY ts ASC", (range_sql,)).fetchall()

    data = {k: [] for k in ["timestamps", "cpu", "ram_percent", "disk_percent", "load_1", "load_5", "load_15", "pdns_cpu", "pdns_rss", "net_sent_rate", "net_recv_rate"]}
    prev = None
    for row in rows:
        ts = row["ts"]
        try:
            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).astimezone(APP_TZ)
            label = dt.strftime("%H:%M:%S") if range_str in ("1h", "6h") else dt.strftime("%m-%d %H:%M")
        except Exception:
            label = ts
        data["timestamps"].append(label)
        data["cpu"].append(row["cpu_percent"] or 0)
        data["ram_percent"].append(row["ram_percent"] or 0)
        data["disk_percent"].append(row["disk_percent"] or 0)
        data["load_1"].append(row["load_1"] or 0)
        data["load_5"].append(row["load_5"] or 0)
        data["load_15"].append(row["load_15"] or 0)
        data["pdns_cpu"].append(row["pdns_cpu_percent"] or 0)
        data["pdns_rss"].append(row["pdns_rss_mb"] or 0)
        if prev:
            try:
                t1 = datetime.strptime(prev["ts"], "%Y-%m-%d %H:%M:%S")
                t2 = datetime.strptime(row["ts"], "%Y-%m-%d %H:%M:%S")
                seconds = max(1, (t2 - t1).total_seconds())
                data["net_sent_rate"].append(round(max(0, (row["net_sent_mb"] - prev["net_sent_mb"]) / seconds), 3))
                data["net_recv_rate"].append(round(max(0, (row["net_recv_mb"] - prev["net_recv_mb"]) / seconds), 3))
            except Exception:
                data["net_sent_rate"].append(0)
                data["net_recv_rate"].append(0)
        else:
            data["net_sent_rate"].append(0)
            data["net_recv_rate"].append(0)
        prev = row
    return data
