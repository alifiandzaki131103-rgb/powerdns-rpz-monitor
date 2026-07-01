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
ORIGIN="trustpositifkominfo"

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

        if dig AXFR @"$master" "$ORIGIN" +noidnout +time=120 > "$AXFR_TMP" 2>/dev/null; then
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
# Key: strip zone origin suffix so $ORIGIN handles it
log "Converting zone format..."

ORIGIN_ESC="${ORIGIN//./\\.}"

{
    # Zone header
    echo "\$ORIGIN ${ORIGIN}."
    echo "\$TTL 3600"

    # Process AXFR output:
    # 1. Skip comment lines
    # 2. Strip origin suffix from owner names (convert FQDN to relative)
    # 3. Skip SOA and NS at zone apex (we write our own)
    grep -v "^;" "$AXFR_TMP" | \
    grep -v "^$" | \
    grep -viE "^\S+\s+\d+\s+IN\s+(SOA|NS)\s+" | \
    sed -E "s/^([^ ]+)\.${ORIGIN_ESC}\./\1/" | \
    sed -E "s/^${ORIGIN_ESC}\./@/"
} > "$ZONE_TMP"

# Add SOA and NS at the top (after header)
# Merge: header + SOA + NS + records
{
    echo "\$ORIGIN ${ORIGIN}."
    echo "\$TTL 3600"
    echo "@       IN      SOA     ns.${ORIGIN}. admin.${ORIGIN}. ("
    echo "                        $(date +%Y%m%d%H)  ; serial"
    echo "                        3600    ; refresh"
    echo "                        900     ; retry"
    echo "                        604800  ; expire"
    echo "                        3600 )  ; minimum"
    echo "@       IN      NS      localhost."
    echo ""
    # Domain records (already converted above, skip header lines from ZONE_TMP)
    grep -v '^\$' "$ZONE_TMP" | grep -v "^@"
} > "${ZONE_TMP}.final"

mv "${ZONE_TMP}.final" "$ZONE_TMP"

# Validate
new_lines=$(wc -l < "$ZONE_TMP")
new_size=$(du -h "$ZONE_TMP" | awk '{print $1}')

# Sample check: verify records look correct
sample=$(grep -m3 "CNAME\|A " "$ZONE_TMP" | head -3)
log "Sample records:"
log "$sample"

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

            # Quick RPZ test
            test_result=$(dig @127.0.0.1 xnxx.com +short +tries=1 +time=3 2>/dev/null | head -1)
            if [[ -z "$test_result" ]] || [[ "$test_result" == *"139.255"* ]] || [[ "$test_result" == *"182.23"* ]]; then
                log "RPZ test: xnxx.com BLOCKED (expected)"
            else
                log "RPZ test: xnxx.com NOT blocked — check zone format!"
            fi
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
