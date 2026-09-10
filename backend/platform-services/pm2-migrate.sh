#!/usr/bin/env bash
# Migrate legacy /opt PM2 names → backend/platform-services ecosystem
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

mkdir -p \
  /var/log/spam-detector \
  /var/log/vr-connector \
  /var/log/wazuh-connector \
  /var/log/vr-notifier \
  /var/log/mailbox-monitor \
  /var/log/email-mgmt

# Stop legacy names from /opt deployments
LEGACY=(
  spam-detector
  vr-connector
  universal_connector
  wazuh-connector
  vr-notifier
  mailbox-monitor
  archive-old-logs
)
for name in "${LEGACY[@]}"; do
  pm2 delete "$name" 2>/dev/null || true
done

pm2 start "$ROOT/ecosystem.config.cjs"
pm2 save
pm2 list | grep -E 'platform-|name' || pm2 list

echo ""
echo "Platform services running from: $ROOT"
echo "  stop:    pm2 stop ecosystem.config.cjs"
echo "  restart: pm2 restart ecosystem.config.cjs"
echo "  logs:    pm2 logs platform-spam-detector"
