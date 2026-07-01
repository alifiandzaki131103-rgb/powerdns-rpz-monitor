# PowerDNS RPZ Monitor

Web GUI monitoring untuk PowerDNS Recursor dengan RPZ (Response Policy Zone) Komdigi TrustPositif.

![Dashboard](https://img.shields.io/badge/status-production-brightgreen)
![Python](https://img.shields.io/badge/python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)

## Fitur

- 📊 **Dashboard** — QPS, cache hit rate, CPU/RAM/disk, RPZ hits
- 🛡️ **RPZ Zones** — status zone Komdigi, record count, file size, last sync
- 🔍 **Domain Check** — cek apakah domain masuk RPZ blocklist
- 📋 **Query Log** — live query log dengan filter (domain, client IP, tipe)
- 📈 **CDN Analytics** — analisis traffic per app/CDN (TikTok, YouTube, Facebook, Shopee, dll) dari query log
- 🖥️ **Resource Monitor** — CPU, RAM, disk, PowerDNS RSS, system load real-time

## Screenshot

| Dashboard | CDN Analytics |
|-----------|---------------|
| QPS, cache hit, system metrics | Donut chart + top apps & domains |

## Stack

- **Backend**: FastAPI + Jinja2 + SQLite + Uvicorn
- **DNS**: PowerDNS Recursor 4.9.x + Lua RPZ + forward-zones-recurse (Google/Cloudflare fallback)
- **RPZ Source**: Komdigi TrustPositif (rpzFile, loaded from zone file)
- **Reverse Proxy**: Nginx

## Prerequisites

- Ubuntu 24.04 LTS
- PowerDNS Recursor 4.9.x sudah jalan dengan RPZ zone
- Python 3.12+
- Query logging aktif via Lua `preresolve` hook

## Quick Install (Recommended)

Interactive installer — bisa full install atau step-by-step:

```bash
curl -sL https://raw.githubusercontent.com/alifiandzaki131103-rgb/powerdns-rpz-monitor/main/scripts/install.sh | bash
```

Atau clone dulu:

```bash
git clone https://github.com/alifiandzaki131103-rgb/powerdns-rpz-monitor.git
cd powerdns-rpz-monitor
bash scripts/install.sh
```

Menu installer:

```
  1) Full Install (semua steps)

  2) System Preparation (packages, user, dirs)
  3) PowerDNS Recursor Config
  4) Lua RPZ + Query Log Config
  5) App Deploy (clone, venv, .env)
  6) systemd Service
  7) nginx Reverse Proxy
  8) Start & Verify

  9)  Check Status
  10) Fetch Komdigi RPZ Zone (AXFR)
  11) View Logs
```

Installer handle:
- Disable systemd-resolved + fix resolv.conf
- Install pdns-recursor, nginx, python3-venv, dnsutils
- Interactive config: allow-from subnet, API key, password, threads
- Pilih mode Komdigi: rpzFile (manual) atau rpzPrimary (AXFR)
- Lua configs: recursor.lua + query-log.lua (optimized batch flush)
- Clone repo, buat venv, pip install, generate .env
- systemd service (runs as `rpzmon` user, bukan root)
- nginx reverse proxy + SSE endpoint (buffering off)
- Fetch Komdigi zone via AXFR (utility menu)
- Full verification: service status, DNS test, web GUI, API

## Manual Install

### 1. PowerDNS Recursor Setup

Install PowerDNS Recursor:

```bash
# Disable systemd-resolved (port 53 conflict)
systemctl stop systemd-resolved
systemctl disable systemd-resolved
echo "nameserver 127.0.0.1" > /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf

apt update && apt install -y pdns-recursor pdns-tools dnsutils curl
```

Konfigurasi `/etc/powerdns/recursor.conf`:

```ini
local-address=0.0.0.0
local-port=53
allow-from=127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 103.55.252.0/23

# Web API
webserver=yes
webserver-address=0.0.0.0
webserver-port=8082
webserver-allow-from=0.0.0.0/0
webserver-password=admin123
api-key=your-api-key-here

# Lua config
lua-config-file=/etc/powerdns/recursor.lua
lua-dns-script=/etc/powerdns/query-log.lua

# Performance
threads=4
max-cache-entries=1000000
max-negative-ttl=3600
max-cache-ttl=86400

# Stats
stats-ringbuffer-entries=50000

# Network tuning - reduce outgoing timeouts
network-timeout=3000

# Fallback forwarders - reduce SERVFAIL & latency
# Uses forward-zones-recurse so DNSSEC validation still applies
# RPZ policies are checked locally BEFORE forwarding
forward-zones-recurse=.=8.8.8.8;1.1.1.1;8.8.4.4;1.0.0.1
```

**⚠️ Pitfalls:**
- `api-key` ≠ `webserver-password` — keduanya independent
- Jangan pakai `api=yes` (invalid di 4.9.x)
- `stats-ringbuffer-entries` bukan `stats-ring-buffer-entries`

Konfigurasi `/etc/powerdns/recursor.lua`:

```lua
dofile("/usr/share/pdns-recursor/lua-config/rootkeys.lua")

-- Local custom blocklist
rpzFile("/var/lib/powerdns/rpz-local.zone", { policyName = "rpz.local" })

-- Komdigi TrustPositif (loaded from zone file)
rpzFile("/var/lib/powerdns/rpz-komdigi.zone", { policyName = "komdigi" })
```

**⚠️ Pitfalls:**
- `rpzFile()` second arg HARUS options table `{}`, bukan bare string
- `rpzMaster()` deprecated, pakai `rpzPrimary()`
- Hooks (preresolve) HARUS di `lua-dns-script`, BUKAN `lua-config-file`
- Query log JANGAN pakai `io.open()` + `io.close()` setiap query (60x/detik = bottleneck). Pakai persistent fd + batch flush
- JANGAN pakai `os.execute()` di preresolve untuk log rotation (fork shell di hot path). Pakai `os.rename()` atomic rotate
- `forward-zones-recurse` (bukan `forward-zones`) supaya DNSSEC tetap validate

Query logging `/etc/powerdns/query-log.lua` (optimized — persistent file handle, batch flush):

```lua
-- Optimized query logger
-- Persistent file handle + batch flush, no os.execute fork
-- See scripts/query-log.lua for full version

local log_fd = nil
local write_buf = {}
local BUF_SIZE = 50
local MAX_LINES = 200000
local line_count = 0

local qtype_map = {
    [1]="A",[28]="AAAA",[5]="CNAME",[15]="MX",
    [16]="TXT",[2]="NS",[6]="SOA",[12]="PTR",
    [33]="SRV",[255]="ANY",[257]="CAA",
}

local function get_fd()
    if not log_fd then
        log_fd = io.open("/var/log/pdns-query.log", "a")
    end
    return log_fd
end

function preresolve(dq)
    local qt = tonumber(dq.qtype)
    local qts = qtype_map[qt] or tostring(qt)
    local line = os.date("%Y-%m-%d %H:%M:%S") .. "|"
                 .. tostring(dq.remoteaddr) .. "|"
                 .. tostring(dq.qname) .. "|" .. qts

    write_buf[#write_buf + 1] = line
    line_count = line_count + 1

    if #write_buf >= BUF_SIZE then
        local fd = get_fd()
        if fd then
            fd:write(table.concat(write_buf, "\n") .. "\n")
            fd:flush()
        end
        write_buf = {}
    end

    if line_count >= MAX_LINES then
        if log_fd then log_fd:close(); log_fd = nil end
        os.rename("/var/log/pdns-query.log", "/var/log/pdns-query.log.1")
        line_count = 0
        write_buf = {}
    end

    return false
end
```

```bash
touch /var/log/pdns-query.log
chown pdns:pdns /var/log/pdns-query.log
systemctl restart pdns-recursor
```

### 2. Komdigi RPZ Zone

Daftar IP server di https://integrasipenapisan.komdigi.go.id

Fetch zone via AXFR (setelah approval):

```bash
# Option A: rpzPrimary() di recursor.lua (auto-sync)
# Option B: Manual fetch (jika AXFR intermittent)
dig AXFR @182.23.79.202 trustpositifkominfo +noidnout +time=120 > /tmp/rpz.axfr

# Convert ke PowerDNS format dan simpan ke /var/lib/powerdns/rpz-komdigi.zone
```

Atau pakai menu installer (opsi 10):

```bash
bash scripts/install.sh
# → pilih 10) Fetch Komdigi RPZ Zone (AXFR)
```

### 3. Web GUI Install

```bash
git clone https://github.com/alifiandzaki131103-rgb/powerdns-rpz-monitor.git /opt/rpz-monitor
cd /opt/rpz-monitor

# Python venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Config
cp .env.example .env
nano .env  # edit: PDNS_API_KEY, AUTH_PASS, dsb

# Init data dir
mkdir -p data

# Test
python -m uvicorn app.main:app --host 0.0.0.0 --port 8050
```

### 4. Systemd Service

```bash
# Service user (non-root)
useradd --system --home /opt/rpz-monitor --shell /usr/sbin/nologin rpzmon
usermod -aG pdns rpzmon
chown -R rpzmon:rpzmon /opt/rpz-monitor

cp systemd/rpz-monitor.service /etc/systemd/system/
# Edit Environment= AUTH_USER & AUTH_PASS di service file
systemctl daemon-reload
systemctl enable rpz-monitor
systemctl start rpz-monitor
```

### 5. Nginx Reverse Proxy

```bash
cp nginx/rpz-monitor.conf /etc/nginx/sites-available/rpz-monitor
ln -s /etc/nginx/sites-available/rpz-monitor /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

## Arsitektur

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Clients   │────▶│  PowerDNS        │────▶│  Komdigi RPZ    │
│             │◀────│  Recursor :53    │     │  (rpzFile)      │
└─────────────┘     │                  │     └─────────────────┘
                    │  RPZ check       │
                    │  (local, before  │     ┌─────────────────┐
                    │   forwarding)    │────▶│  Google/CF      │
                    │                  │◀────│  Forwarders     │
                    │  ┌────────────┐  │     │  (fallback)     │
                    │  │ query.log  │  │     └─────────────────┘
                    │  └─────┬──────┘  │
                    └────────┼─────────┘
                             │
                    ┌────────▼─────────┐
                    │  RPZ Monitor     │
                    │  FastAPI :8050   │
                    │  ┌─────────────┐ │
                    │  │ CDN Parser  │ │
                    │  │ SQLite DB   │ │
                    │  └─────────────┘ │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  Nginx :80       │
                    │  (reverse proxy) │
                    └──────────────────┘
```

## Project Structure

```
/opt/rpz-monitor/
├── app/
│   ├── main.py              # FastAPI app + routes
│   ├── auth.py              # HMAC session auth
│   ├── config.py            # Config loader
│   ├── database.py          # SQLite helpers
│   ├── cdn_analytics.py     # CDN/app parser + DB
│   ├── top_blocked.py       # Top blocked domains
│   ├── resources.py         # System resource collector
│   ├── query_log.py         # Query log reader
│   ├── services/
│   │   └── ...
│   └── templates/
│       ├── base.html
│       ├── dashboard.html
│       ├── rpz_status.html
│       ├── domain_check.html
│       ├── logs.html
│       ├── cdn.html
│       └── ...
├── data/
│   └── rpz-monitor.db       # SQLite (auto-created)
├── scripts/
│   ├── install.sh           # ← Interactive installer
│   ├── deploy.sh            # Git push + SSH deploy
│   ├── query-log.lua        # Optimized Lua query logger
│   ├── recursor.conf.example
│   └── recursor.lua.example
├── systemd/
│   └── rpz-monitor.service
├── nginx/
│   └── rpz-monitor.conf
├── requirements.txt
├── .env.example
└── .env                     # Local config (git-ignored)
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard |
| `/rpz` | GET | RPZ zone status |
| `/check` | GET/POST | Domain checker |
| `/logs` | GET | Query log viewer |
| `/cdn` | GET | CDN analytics |
| `/resources` | GET | Resource monitor |
| `/top-blocked` | GET | Top blocked domains |
| `/api/stats` | GET | JSON stats |
| `/api/cdn?range=1d` | GET | JSON CDN data (1h/1d/7d/30d) |
| `/api/logs` | GET | JSON query logs |
| `/api/logs/live` | GET | SSE live log stream |
| `/api/rpz/zones` | GET | JSON RPZ zone info |
| `/api/resources` | GET | JSON resource data |
| `/api/top-blocked` | GET | JSON top blocked domains |

## CDN Analytics

Parse query log → classify per app → simpan di SQLite → tampilin di `/cdn`.

Supported apps: YouTube/Google, TikTok, Facebook/Meta, Netflix, Shopee, Telegram, Cloudflare, Akamai, Apple, Microsoft, X/Twitter, Naver, Kwai, OPPO/Android, Tokopedia, Grab, Gojek, Roblox, LINE, Spotify.

## License

MIT
