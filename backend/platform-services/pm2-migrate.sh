#!/usr/bin/env bash
# Migrate legacy /opt processes → backend/platform-services PM2 pack
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
  echo "Loaded .env"
else
  echo "WARN: no .env — using ecosystem defaults. Prefer: cp -n .env.example .env && edit"
fi

mkdir -p \
  /var/log/spam-detector \
  /var/log/vr-connector \
  /var/log/wazuh-connector \
  /var/log/vr-notifier \
  /var/log/mailbox-monitor \
  /var/log/email-mgmt

# 1) Stop systemd units that keep respawning /opt copies
echo "=== Checking systemd units ==="
systemctl list-units --type=service --all 2>/dev/null | grep -iE 'virus|spam-det|mailbox|wazuh|vr-|notifier' || true
for unit in \
  virus-rescuers virus-rescuers.service \
  spam-detector spam-detector.service \
  mailbox-monitor mailbox-monitor.service \
  vr-notifier vr-notifier.service \
  wazuh-connector wazuh-connector.service \
  universal-connector universal-connector.service
do
  if systemctl cat "$unit" &>/dev/null; then
    echo "Disabling systemd unit: $unit"
    systemctl stop "$unit" 2>/dev/null || true
    systemctl disable "$unit" 2>/dev/null || true
  fi
done

# 2) Delete legacy PM2 app names
LEGACY=(
  spam-detector
  vr-connector
  universal_connector
  universal-connector
  wazuh-connector
  vr-notifier
  mailbox-monitor
  archive-old-logs
)
for name in "${LEGACY[@]}"; do
  pm2 delete "$name" 2>/dev/null || true
done

# 3) Kill leftover /opt processes (after systemd disabled)
pkill -f '/opt/virus-rescuers/' 2>/dev/null || true
pkill -f '/opt/spam-detector/spam_detector.py' 2>/dev/null || true
sleep 1

# 4) Quick import check (fail early with clear message)
python3 - <<'PY' || { echo "ERROR: pip3 install mysql-connector-python requests"; exit 1; }
import mysql.connector, requests
print("Python deps OK")
PY

# 5) Replace platform-* with fresh start
pm2 delete ecosystem.config.cjs 2>/dev/null || true
for name in platform-spam-detector platform-vr-connector platform-wazuh-connector \
            platform-vr-notifier platform-mailbox-monitor platform-archive-logs; do
  pm2 delete "$name" 2>/dev/null || true
done

pm2 start "$ROOT/ecosystem.config.cjs"
pm2 save

echo ""
echo "=== Status ==="
pm2 list | grep -E 'platform-|name' || pm2 list
echo ""
echo "If any errored:  pm2 logs platform-spam-detector --err --lines 40"
echo "Expect script paths under: $ROOT (not /opt/...)"
ps -aux | grep -E 'platform-services|/opt/(virus|spam)' | grep -v grep || true
