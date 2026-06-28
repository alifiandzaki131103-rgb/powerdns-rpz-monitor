"""Query log reader for PowerDNS RPZ Monitor"""
import os
import subprocess
import re
from datetime import datetime

LOG_FILE = "/var/log/pdns-query.log"


def read_query_log(search="", client_ip="", qtype="", limit=500):
    """Read query log file with optional filters"""
    logs = []
    total_lines = 0
    unique_domains = set()
    unique_clients = set()

    if not os.path.exists(LOG_FILE):
        return {
            "logs": [],
            "total_lines": 0,
            "displayed": 0,
            "unique_domains": 0,
            "unique_clients": 0,
        }

    try:
        # Use tail for efficiency
        result = subprocess.run(
            ["tail", "-n", str(limit * 3), LOG_FILE],  # read extra for filtering
            capture_output=True, text=True, timeout=5,
        )
        lines = result.stdout.strip().split("\n")

        # Count total lines in file
        wc = subprocess.run(["wc", "-l", LOG_FILE], capture_output=True, text=True, timeout=5)
        try:
            total_lines = int(wc.stdout.strip().split()[0])
        except:
            total_lines = len(lines)

        search_lower = search.lower().strip() if search else ""
        ip_filter = client_ip.strip() if client_ip else ""
        type_filter = qtype.strip().upper() if qtype else ""

        for line in reversed(lines):  # newest first
            parts = line.strip().split("|", 3)
            if len(parts) != 4:
                continue

            ts, client, domain, qtype_str = parts

            # Track unique values
            unique_domains.add(domain.lower())
            unique_clients.add(client)

            # Apply filters
            if search_lower and search_lower not in domain.lower():
                continue
            if ip_filter and ip_filter != client:
                continue
            if type_filter and type_filter != qtype_str:
                continue

            logs.append({
                "time": ts,
                "client": client,
                "domain": domain,
                "qtype": qtype_str,
                "is_rpz": "trustpositifkominfo" in domain.lower() or "aduankonten" in domain.lower(),
            })

            if len(logs) >= limit:
                break

    except Exception as e:
        logs = [{"time": "ERROR", "client": "", "domain": str(e), "qtype": ""}]

    return {
        "logs": logs,
        "total_lines": total_lines,
        "displayed": len(logs),
        "unique_domains": len(unique_domains),
        "unique_clients": len(unique_clients),
    }
