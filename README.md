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

## Screenshot

| Dashboard | CDN Analytics |
|-----------|---------------|
| QPS, cache hit, system metrics | Donut chart + top apps & domains |

## Stack

- **Backend**: FastAPI + Jinja2 + SQLite + Uvicorn
- **DNS**: PowerDNS Recursor 4.9.x + Lua RPZ
- **RPZ Source**: Komdigi TrustPositif (AXFR zone transfer)
- **Reverse Proxy**: Nginx

## Prerequisites

- Ubuntu 24.04 LTS
- PowerDNS Recursor 4.9.x sudah jalan dengan RPZ zone
- Python 3.12+
- Query logging aktif via Lua `preresolve` hook

## Install

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

# Stats
stats-ringbuffer-entries=50000
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

Query logging `/etc/powerdns/query-log.lua`:

```lua
function preresolve(dq)
    local f = io.open("/var/log/pdns-query.log", "a")
    if f then
        f:write(os.date("%Y-%m-%d %H:%M:%S") .. "|" ..
                dq.remoteaddr:toString() .. "|" ..
                dq.qname:toString() .. "|" ..
                dns.qtype.tostring(dq.qtype) .. "\n")
        f:close()
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

### 3. Web GUI Install

```bash
git clone https://github.com/Alifian13/powerdns-rpz-monitor.git /opt/rpz-monitor
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
cp systemd/rpz-monitor.service /etc/systemd/system/
# Edit Environment= di service file jika tidak pakai .env
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
│             │◀────│  Recursor :53    │◀────│  (AXFR/slave)   │
└─────────────┘     │                  │     └─────────────────┘
                    │  ┌────────────┐  │
                    │  │ query.log  │  │
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

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard |
| `/rpz` | GET | RPZ zone status |
| `/check` | GET/POST | Domain checker |
| `/logs` | GET | Query log viewer |
| `/cdn` | GET | CDN analytics |
| `/api/stats` | GET | JSON stats |
| `/api/cdn?range=1d` | GET | JSON CDN data (1h/1d/7d/30d) |
| `/api/logs` | GET | JSON query logs |
| `/api/rpz/zones` | GET | JSON RPZ zone info |

## CDN Analytics

Parse query log → classify per app → simpan di SQLite → tampilin di `/cdn`.

Supported apps: YouTube/Google, TikTok, Facebook/Meta, Netflix, Shopee, Telegram, Cloudflare, Akamai, Apple, Microsoft, X/Twitter, Naver, Kwai, OPPO/Android, Tokopedia, Grab, Gojek, Roblox, LINE, Spotify.

## License

MIT
