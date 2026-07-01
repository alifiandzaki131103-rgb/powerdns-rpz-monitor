#!/bin/bash
# ============================================================
#  Komdigi RPZ Zone Fetcher — AXFR + convert + restart
#  Run manually or via cron
# ============================================================

set -o pipefail

ZONE_FILE="/var/lib/powerdns/rpz-komdigi.zone"
ZONE_TMP="/var/lib/powerdns/rpz-komdigi.zone.tmp"
LOG_FILE="/var/log/rpz-fetch.log"
MASTERS=("182.23.79.202" "139.255.196.202")
AXFR_TMP="/tmp/komdigi-rpz.axfr"
MAX_RETRY=20
RETRY_INTERVAL=5

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Rotate log if > 5MB
if [[ -f "$LOG_FILE" ]] && [[ $(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt 5242880 ]]; then
    mv "$LOG_FILE" "${LOG_FILE}.1"
fi

log "=== Fetch Komdigi RPZ Zone ==="

success=0
for attempt in $(seq 1 $MAX_RETRY); do
    for master in "${MASTERS[@]}"; do
        log "Attempt $attempt/$MAX_RETRY — AXFR from $master"

        if dig AXFR @"$master" trustpositifkominfo +noidnout +time=120 > "$AXFR_TMP" 2>/dev/null; then
            lines=$(wc -l < "$AXFR_TMP")
            if [[ "$lines" -gt 100 ]]; then
                log "AXFR success from $master — $lines lines"
                success=1
                break 2
            else
                log "AXFR returned only $lines lines — likely SERVFAIL or empty"
            fi
        else
            log "AXFR failed from $master"
        fi
    done

    if [[ "$success" -eq 0 ]]; then
        log "Retry in ${RETRY_INTERVAL}s..."
        sleep $RETRY_INTERVAL
    fi
done

if [[ "$success" -eq 0 ]]; then
    log "ERROR: AXFR failed after $MAX_RETRY attempts"
    rm -f "$AXFR_TMP"
    exit 1
fi

# Convert AXFR to rpzFile format
log "Converting zone format..."

{
    # SOA with proper owner
    grep -m1 "^trustpositifkominfo\..*SOA" "$AXFR_TMP" | sed 's/^trustpositifkominfo\./@       /'
    # NS records
    grep "^trustpositifkominfo\..*NS" "$AXFR_TMP" | sed 's/^trustpositifkominfo\./@       /'
    # All other records (skip SOA/NS at origin, skip comments)
    grep -v "^trustpositifkominfo\..*\(SOA\|NS\)" "$AXFR_TMP" | \
    grep -v "^;" | \
    grep -v "^$" | \
    sed 's/^trustpositifkominfo\./@       /'
} > "$ZONE_TMP"

# Validate
new_lines=$(wc -l < "$ZONE_TMP")
new_size=$(du -h "$ZONE_TMP" | awk '{print $1}')

if [[ "$new_lines" -gt 100 ]]; then
    # Backup old zone
    if [[ -f "$ZONE_FILE" ]]; then
        old_serial=$(grep -m1 "SOA" "$ZONE_FILE" | grep -oP '\d{10}' || echo "unknown")
        cp "$ZONE_FILE" "${ZONE_FILE}.bak.${old_serial}"
    fi

    mv "$ZONE_TMP" "$ZONE_FILE"
    chown pdns:pdns "$ZONE_FILE"
    log "Zone updated: $new_lines records, $new_size"

    # Restart PowerDNS to load new zone
    if systemctl is-active --quiet pdns-recursor; then
        systemctl restart pdns-recursor
        log "pdns-recursor restarted"

        # Wait and verify
        sleep 3
        if systemctl is-active --quiet pdns-recursor; then
            log "pdns-recursor active — zone loaded"
        else
            log "ERROR: pdns-recursor failed to start after restart!"
            journalctl -u pdns-recursor --no-pager -n 10 >> "$LOG_FILE" 2>&1
        fi
    else
        log "WARN: pdns-recursor not running, zone file updated but not loaded"
    fi
else
    log "ERROR: Converted zone too small ($new_lines lines) — keeping old zone"
    rm -f "$ZONE_TMP"
    exit 1
fi

rm -f "$AXFR_TMP"
log "=== Done ==="
