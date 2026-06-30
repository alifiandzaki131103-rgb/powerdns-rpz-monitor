#!/bin/bash
# Deploy RPZ Monitor to production server
# Usage: ./scripts/deploy.sh
set -e

SERVER="root@103.55.253.251"
REMOTE_DIR="/opt/rpz-monitor"

echo "==> Pushing to GitHub..."
git push origin main

echo "==> Deploying to $SERVER..."
ssh "$SERVER" "
    cd $REMOTE_DIR
    git pull --ff-only
    systemctl restart rpz-monitor
    sleep 2
    systemctl is-active rpz-monitor
"

echo "==> Done. Service active on $SERVER"
