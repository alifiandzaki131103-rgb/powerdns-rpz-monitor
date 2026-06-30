"""PowerDNS RPZ Monitor - FastAPI Web Application"""
import os
import time
import subprocess
import re
import json
import hashlib
import hmac
import secrets
import glob
import asyncio
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import psutil
from fastapi import FastAPI, Request, Form, Depends, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.query_log import read_query_log
from app.cdn_analytics import init_cdn_db, parse_incremental, get_cdn_data
from app.top_blocked import get_top_blocked
import sqlite3 as _sqlite3
from app.resources import init_resource_db, collect_and_store, get_resource_data, get_current_stats
CDN_DB = "/opt/rpz-monitor/data/rpz-monitor.db"

# Config
PDNS_API_URL = os.getenv("PDNS_API_URL", "http://127.0.0.1:8082")
PDNS_API_KEY = os.getenv("PDNS_API_KEY", "rpzmonitor2026")
APP_TZ = os.getenv("APP_TZ", "Asia/Jakarta")
APP_PORT = int(os.getenv("APP_PORT", "8050"))

# Auth config
AUTH_USER = os.getenv("AUTH_USER", "admin")
AUTH_PASS = os.getenv("AUTH_PASS", "admin123")
SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_hex(32))
SESSION_MAX_AGE = 86400  # 24h

# In-memory stats history
stats_history = {"qps": [], "cache_hit_rate": []}
MAX_HISTORY = 360  # 30 min at 5s intervals

prev_questions = 0
prev_time = 0


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def _create_session(username: str) -> str:
    payload = f"{username}:{int(time.time())}:{secrets.token_hex(8)}"
    sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"

def _verify_session(token: str) -> bool:
    try:
        parts = token.rsplit(":", 1)
        if len(parts) != 2:
            return False
        payload, sig = parts
        expected = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        ts = int(payload.split(":")[1])
        return (time.time() - ts) < SESSION_MAX_AGE
    except Exception:
        return False


_valid_sessions: set = set()
# RPZ record count cache
_rpz_record_cache = {}  # {filepath: (mtime, count)}
_cdn_last_parse = 0  # timestamp of last CDN parse
_cdn_parse_cache = {}  # cached parse stats
CDN_PARSE_COOLDOWN = 60  # seconds between parses

# QPS History SQLite persistence
def _init_qps_db():
    conn = _sqlite3.connect(CDN_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS qps_history (
        ts INTEGER PRIMARY KEY, qps REAL, cache_hit_rate REAL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_qps_ts ON qps_history(ts)")
    conn.commit()
    conn.close()

def _store_qps(ts, qps_val, chr_val):
    conn = _sqlite3.connect(CDN_DB)
    conn.execute("INSERT OR REPLACE INTO qps_history (ts, qps, cache_hit_rate) VALUES (?, ?, ?)", (ts, qps_val, chr_val))
    conn.execute("DELETE FROM qps_history WHERE ts < strftime('%s','now') - 3600")
    conn.commit()
    conn.close()

def _read_qps_history(minutes=30):
    conn = _sqlite3.connect(CDN_DB)
    conn.row_factory = _sqlite3.Row
    cutoff = int(__import__('time').time()) - (minutes * 60)
    rows = conn.execute("SELECT ts, qps, cache_hit_rate FROM qps_history WHERE ts >= ? ORDER BY ts ASC", (cutoff,)).fetchall()
    conn.close()
    return {"qps": [{"ts": r["ts"], "val": r["qps"]} for r in rows],
            "cache_hit_rate": [{"ts": r["ts"], "val": r["cache_hit_rate"]} for r in rows]}

def _get_record_count(fpath):
    """Fast record count with mtime-based cache"""
    try:
        mtime = os.path.getmtime(fpath)
        if fpath in _rpz_record_cache:
            cached_mtime, cached_count = _rpz_record_cache[fpath]
            if cached_mtime == mtime:
                return cached_count
        # Fast count: wc -l minus header lines
        result = subprocess.run(['wc', '-l', fpath], capture_output=True, text=True, timeout=10)
        total = int(result.stdout.strip().split()[0])
        # Subtract ~10 header lines (SOA, NS, comments)
        count = max(0, total - 10)
        _rpz_record_cache[fpath] = (mtime, count)
        return count
    except:
        return 0


def _check_auth(request: Request) -> bool:
    token = request.cookies.get("session")
    if token and token in _valid_sessions and _verify_session(token):
        return True
    return False

async def _require_auth(request: Request):
    if not _check_auth(request):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return RedirectResponse("/login", status_code=302)
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_cdn_db(CDN_DB)
    init_resource_db(CDN_DB)
    _init_qps_db()
    collect_and_store(CDN_DB)
    stop_event = asyncio.Event()

    async def resource_collector():
        while not stop_event.is_set():
            try:
                collect_and_store(CDN_DB)
                # Also collect QPS for dashboard chart
                try:
                    import time as _t
                    stats = get_stats()
                    qps_val = calc_qps(stats)
                    now_ts = int(_t.time())
                    cache_hits = int(stats.get("cache-hits", 0))
                    cache_misses = int(stats.get("cache-misses", 0))
                    total = cache_hits + cache_misses
                    chr_val = round((cache_hits / total * 100) if total > 0 else 0, 1)
                    _store_qps(now_ts, qps_val, chr_val)
                    print(f"[QPS] collected qps={qps_val} chr={chr_val} ok", flush=True)
                except Exception as qe:
                    import traceback; traceback.print_exc()
                    print(f"qps collector error: {qe}", flush=True)
                # CDN parse every other cycle (~60s)
                try:
                    parse_incremental(CDN_DB)
                except Exception as ce:
                    print(f"cdn parse error: {ce}", flush=True)
            except Exception as e:
                print(f"resource collector error: {e}")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=30)
            except asyncio.TimeoutError:
                pass

    task = asyncio.create_task(resource_collector())
    try:
        yield
    finally:
        stop_event.set()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

app = FastAPI(title="PowerDNS RPZ Monitor", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="/opt/rpz-monitor/app/static"), name="static")
templates = Jinja2Templates(directory="/opt/rpz-monitor/app/templates")


def api_get(path: str):
    try:
        r = httpx.get(
            f"{PDNS_API_URL}{path}",
            headers={"X-API-Key": PDNS_API_KEY},
            timeout=5,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def get_stats():
    data = api_get("/api/v1/servers/localhost/statistics")
    if isinstance(data, dict) and "error" in data:
        return {}
    stats = {}
    if isinstance(data, list):
        for item in data:
            stats[item["name"]] = item["value"]
    return stats


def get_zones():
    data = api_get("/api/v1/servers/localhost/zones")
    if isinstance(data, dict) and "error" in data:
        return []
    return data if isinstance(data, list) else []


def calc_qps(stats):
    global prev_questions, prev_time
    now = time.time()
    questions = int(stats.get("questions", 0))
    if prev_time > 0 and now > prev_time:
        dt = now - prev_time
        qps = (questions - prev_questions) / dt
    else:
        qps = 0
    prev_questions = questions
    prev_time = now
    return round(qps, 1)


def get_system_metrics():
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "cpu_percent": cpu,
        "mem_total_gb": round(mem.total / 1024**3, 1),
        "mem_used_gb": round(mem.used / 1024**3, 1),
        "mem_percent": mem.percent,
        "disk_total_gb": round(disk.total / 1024**3, 1),
        "disk_used_gb": round(disk.used / 1024**3, 1),
        "disk_percent": disk.percent,
    }


def check_domain(domain: str):
    domain = domain.strip().lower().rstrip(".")
    if not re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", domain):
        return {"error": "Invalid domain format"}
    if len(domain) > 253:
        return {"error": "Domain too long (max 253 chars)"}
    try:
        result = subprocess.run(
            ["dig", "@127.0.0.1", domain, "A",
             "+tries=1", "+time=3", "+noall", "+answer", "+comments"],
            capture_output=True, text=True, timeout=5,
        )
        output = result.stdout.strip()
        blocked = False
        rpz_action = ""
        if "rpz" in output.lower() or "NXDOMAIN" in output:
            blocked = True
            if "NXDOMAIN" in output:
                rpz_action = "NXDOMAIN (blocked)"
            elif "CNAME ." in output:
                rpz_action = "CNAME . (blocked)"
            else:
                rpz_action = "RPZ rewrite detected"
        elif "139.255.196.196" in output or "182.23.79.195" in output:
            blocked = True
            rpz_action = "Komdigi redirect (blocked)"
        elif "lamanlabuh.aduankonten.id" in output:
            blocked = True
            rpz_action = "Komdigi lamanlabuh (blocked)"
        return {
            "domain": domain,
            "blocked": blocked,
            "rpz_action": rpz_action,
            "dig_output": output or "(no A record)",
        }
    except subprocess.TimeoutExpired:
        return {"error": "dig timeout"}
    except Exception as e:
        return {"error": str(e)}


def get_pdns_status():
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "pdns-recursor"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip()
    except:
        return "unknown"


def get_uptime():
    try:
        result = subprocess.run(
            ["systemctl", "show", "pdns-recursor", "--property=ActiveEnterTimestamp"],
            capture_output=True, text=True, timeout=5,
        )
        ts_str = result.stdout.strip().split("=", 1)
        if len(ts_str) == 2 and ts_str[1]:
            # Manual parse: "Thu 2026-06-27 01:44:33 WIB"
            ts_raw = ts_str[1].strip()
            try:
                from dateutil.parser import parse as dateparse
                started = dateparse(ts_raw)
                delta = datetime.now(started.tzinfo) - started
            except:
                return "N/A"
            hours, remainder = divmod(int(delta.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            if hours > 24:
                days = hours // 24
                hours = hours % 24
                return f"{days}d {hours}h {minutes}m"
            return f"{hours}h {minutes}m"
    except:
        pass
    return "N/A"


def get_rpz_zone_info():
    """Get RPZ zone info from filesystem and PowerDNS stats"""
    stats = get_stats()
    zones = []

    # Define known RPZ zones
    rpz_configs = [
        {
            "name": "rpz.local",
            "policy_name": "rpz.local",
            "file_path": "/var/lib/powerdns/rpz-local.zone",
            "source": "Local custom blocklist",
            "type": "local",
        },
        {
            "name": "komdigi",
            "policy_name": "komdigi",
            "file_path": "/var/lib/powerdns/rpz-komdigi.zone",
            "source": "Komdigi TrustPositif (AXFR)",
            "type": "komdigi",
        },
    ]

    for cfg in rpz_configs:
        fpath = cfg["file_path"]
        info = {
            "name": cfg["name"],
            "policy_name": cfg["policy_name"],
            "source": cfg["source"],
            "type": cfg["type"],
            "status": "inactive",
            "record_count": 0,
            "file_size": "N/A",
            "file_size_bytes": 0,
            "last_modified": "N/A",
            "hits": 0,
            "hits_custom": 0,
            "hits_nxdomain": 0,
        }

        # Check if file exists
        if os.path.exists(fpath):
            try:
                
                stat = os.stat(fpath)
                info["file_size_bytes"] = stat.st_size
                if stat.st_size > 1024 * 1024:
                    info["file_size"] = f"{stat.st_size / 1024 / 1024:.1f} MB"
                elif stat.st_size > 1024:
                    info["file_size"] = f"{stat.st_size / 1024:.1f} KB"
                else:
                    info["file_size"] = f"{stat.st_size} B"
                # Last modified
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone(timedelta(hours=7)))
                info["last_modified"] = mtime.strftime("%Y-%m-%d %H:%M:%S")

                # Fast cached record count
                info["record_count"] = _get_record_count(fpath)
                info["status"] = "active"
            except Exception as e:
                info["status"] = f"error: {e}"
        else:
            info["status"] = "file not found"

        # Get hits from PowerDNS stats
        stat_key = f"policy-hits-rpz-{cfg['policy_name']}"
        info["hits"] = int(stats.get(stat_key, 0))

        zones.append(info)

    # Aggregate
    total_hits = sum(z["hits"] for z in zones)
    total_records = sum(z["record_count"] for z in zones)
    active_count = sum(1 for z in zones if z["status"] == "active")

    # Get last sync info
    last_sync = "N/A"
    try:
        if os.path.exists("/var/log/rpz-fetch.log"):
            result = subprocess.run(
                ["tail", "-30", "/var/log/rpz-fetch.log"],
                capture_output=True, text=True, timeout=5,
            )
            lines = result.stdout.strip().split("\n")
            for line in reversed(lines):
                if "records written" in line.lower() or "success" in line.lower() or "synced" in line.lower():
                    last_sync = line.strip()
                    break
                # Match date-like patterns at start of line
                if re.match(r"^\d{4}-\d{2}-\d{2}", line) or re.match(r"^\[.*\]", line):
                    last_sync = line.strip()
                    break
            if last_sync == "N/A" and lines:
                last_sync = lines[-1].strip()[:100]
    except:
        pass

    return {
        "zones": zones,
        "total_hits": total_hits,
        "total_records": total_records,
        "active_count": active_count,
        "last_sync": last_sync,
        "policy_result_custom": int(stats.get("policy-result-custom", 0)),
        "policy_result_nxdomain": int(stats.get("policy-result-nxdomain", 0)),
    }


# ============================================================
# AUTH ROUTES
# ============================================================

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if _check_auth(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": None,
    })


@app.post("/login", response_class=HTMLResponse)
async def login_action(request: Request, username: str = Form(...), password: str = Form(...)):
    user_ok = hmac.compare_digest(username, AUTH_USER)
    pass_ok = hmac.compare_digest(_hash_password(password), _hash_password(AUTH_PASS))
    if user_ok and pass_ok:
        session_token = _create_session(username)
        _valid_sessions.add(session_token)
        response = RedirectResponse("/", status_code=302)
        response.set_cookie(
            key="session",
            value=session_token,
            max_age=SESSION_MAX_AGE,
            httponly=True,
            samesite="lax",
        )
        return response
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": "Username atau password salah",
    })


@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get("session")
    if token:
        _valid_sessions.discard(token)
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("session")
    return response


# ============================================================
# PROTECTED ROUTES
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    auth = await _require_auth(request)
    if auth:
        return auth

    stats = get_stats()
    qps = calc_qps(stats)
    system = get_system_metrics()
    pdns_status = get_pdns_status()
    uptime = get_uptime()

    cache_hits = int(stats.get("cache-hits", 0))
    cache_misses = int(stats.get("cache-misses", 0))
    total = cache_hits + cache_misses
    cache_hit_rate = round((cache_hits / total * 100) if total > 0 else 0, 1)
    rpz_rewrites = int(stats.get("policy-hits", 0))

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "pdns_status": pdns_status,
        "uptime": uptime,
        "qps": qps,
        "total_queries": int(stats.get("questions", 0)),
        "cache_hits": cache_hits,
        "cache_misses": cache_misses,
        "cache_hit_rate": cache_hit_rate,
        "rpz_rewrites": rpz_rewrites,
        "nxdomain": int(stats.get("nxdomain-answers", 0)),
        "noerror": int(stats.get("noerror-answers", 0)),
        "servfail": int(stats.get("servfail-answers", 0)),
        "system": system,
        "stats_history": json.dumps(_read_qps_history(30)),
        "active_page": "dashboard",
    })


@app.get("/rpz", response_class=HTMLResponse)
async def rpz_status(request: Request):
    auth = await _require_auth(request)
    if auth:
        return auth

    rpz_data = get_rpz_zone_info()

    return templates.TemplateResponse("rpz.html", {
        "request": request,
        "rpz_data": rpz_data,
        "active_page": "rpz",
    })


@app.get("/check", response_class=HTMLResponse)
async def check_page(request: Request):
    auth = await _require_auth(request)
    if auth:
        return auth

    return templates.TemplateResponse("check.html", {
        "request": request,
        "result": None,
        "active_page": "check",
    })


@app.post("/check", response_class=HTMLResponse)
async def check_domain_action(request: Request, domain: str = Form(...)):
    auth = await _require_auth(request)
    if auth:
        return auth

    result = check_domain(domain)
    return templates.TemplateResponse("check.html", {
        "request": request,
        "result": result,
        "domain": domain,
        "active_page": "check",
    })


@app.get("/api/stats")
async def api_stats(request: Request):
    auth = await _require_auth(request)
    if auth:
        return auth

    stats = get_stats()
    qps = calc_qps(stats)
    system = get_system_metrics()
    return {
        "qps": qps,
        "questions": int(stats.get("questions", 0)),
        "cache_hits": int(stats.get("cache-hits", 0)),
        "cache_misses": int(stats.get("cache-misses", 0)),
        "rpz_rewrites": int(stats.get("policy-hits", 0)),
        "nxdomain": int(stats.get("nxdomain-answers", 0)),
        "noerror": int(stats.get("noerror-answers", 0)),
        "servfail": int(stats.get("servfail-answers", 0)),
        "system": system,
        "pdns_status": get_pdns_status(),
    }


@app.get("/api/history")
async def api_history(request: Request):
    auth = await _require_auth(request)
    if auth:
        return auth
    return _read_qps_history(30)


@app.post("/api/check")
async def api_check(request: Request, domain: str = Form(...)):
    auth = await _require_auth(request)
    if auth:
        return auth
    return check_domain(domain)


@app.get("/api/rpz/zones")
async def api_rpz_zones(request: Request):
    """API: RPZ zones info — reads from filesystem + PowerDNS stats"""
    auth = await _require_auth(request)
    if auth:
        return auth
    return get_rpz_zone_info()




# ============================================================
# QUERY LOG ROUTES
# ============================================================

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request, q: str = "", ip: str = "", type: str = "", limit: int = 500):
    auth = await _require_auth(request)
    if auth:
        return auth

    data = read_query_log(search=q, client_ip=ip, qtype=type, limit=limit)
    return templates.TemplateResponse("logs.html", {
        "request": request,
        "logs": data["logs"],
        "total_lines": data["total_lines"],
        "displayed": data["displayed"],
        "unique_domains": data["unique_domains"],
        "unique_clients": data["unique_clients"],
        "search": q,
        "client_ip": ip,
        "qtype": type,
        "limit": limit,
        "auto_refresh": True,
        "active_page": "logs",
    })


@app.get("/api/logs")
async def api_logs(request: Request, q: str = "", ip: str = "", type: str = "", limit: int = 100):
    auth = await _require_auth(request)
    if auth:
        return auth
    return read_query_log(search=q, client_ip=ip, qtype=type, limit=limit)

# ============================================================
# CDN ANALYTICS ROUTES
# ============================================================

@app.get("/cdn", response_class=HTMLResponse)
async def cdn_page(request: Request, range: str = "1d"):
    auth = await _require_auth(request)
    if auth:
        return auth
    data = get_cdn_data(CDN_DB, range)
    return templates.TemplateResponse("cdn.html", {
        "request": request,
        "active_page": "cdn",
        "data": data,
        "parse_stats": {},
        "range": range,
    })


@app.get("/api/cdn")
async def api_cdn(request: Request, range: str = "1d"):
    auth = await _require_auth(request)
    if auth:
        return auth
    data = get_cdn_data(CDN_DB, range)
    return {**data, "range": range}


@app.get("/top-blocked", response_class=HTMLResponse)
async def top_blocked_page(request: Request, range: str = "1d"):
    auth = await _require_auth(request)
    if auth:
        return auth
    if range not in ("1h", "1d", "7d", "30d"):
        range = "1d"
    data = get_top_blocked(CDN_DB, range, limit=100)
    return templates.TemplateResponse("top_blocked.html", {
        "request": request,
        "active_page": "top_blocked",
        "data": data,
        "range": range,
    })


@app.get("/api/top-blocked")
async def api_top_blocked(request: Request, range: str = "1d", limit: int = 100):
    auth = await _require_auth(request)
    if auth:
        return auth
    if range not in ("1h", "1d", "7d", "30d"):
        range = "1d"
    return get_top_blocked(CDN_DB, range, limit=min(limit, 500))


# ============================================================
# RESOURCE MONITOR ROUTES
# ============================================================

@app.get("/resources", response_class=HTMLResponse)
async def resources_page(request: Request, range: str = "1h"):
    auth = await _require_auth(request)
    if auth:
        return auth
    if range not in ("1h", "6h", "1d", "7d"):
        range = "1h"
    data = get_resource_data(CDN_DB, range)
    current = get_current_stats()
    return templates.TemplateResponse("resources.html", {
        "request": request,
        "active_page": "resources",
        "data": data,
        "current": current,
        "range": range,
    })


@app.get("/api/resources")
async def api_resources(request: Request, range: str = "1h"):
    auth = await _require_auth(request)
    if auth:
        return auth
    if range not in ("1h", "6h", "1d", "7d"):
        range = "1h"
    return {"range": range, "current": get_current_stats(), **get_resource_data(CDN_DB, range)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=APP_PORT)
