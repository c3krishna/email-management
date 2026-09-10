#!/usr/bin/env bash
# Migrate legacy shared PM2 agents → agents-app / agents-campaign
#
# Usage:
#   ROLE=app      ./agents-app/pm2-migrate.sh
#   ROLE=campaign ./agents-campaign/pm2-migrate.sh
#
# Or run the matching script from each tree (ROLE inferred from cwd).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(basename "$SCRIPT_DIR")"

if [[ "${ROLE:-}" == "" ]]; then
  if [[ "$BASE" == "agents-campaign" ]]; then
    ROLE=campaign
  else
    ROLE=app
  fi
fi

if [[ "$ROLE" != "app" && "$ROLE" != "campaign" ]]; then
  echo "ROLE must be app or campaign"
  exit 1
fi

echo "==> Stopping legacy shared agent names (if present)"
for n in mail-log-agent firewall-agent spam-milter mailbox-monitor \
         mail-log-agent-app firewall-agent-app spam-milter-app \
         mail-log-agent-campaign firewall-agent-campaign spam-milter-campaign; do
  pm2 delete "$n" 2>/dev/null || true
done

mkdir -p /var/log/email-mgmt /var/log/spam-detector
if [[ "$ROLE" == "app" ]]; then
  mkdir -p /var/lib/mail-agent-app /var/lib/firewall-agent-app
  TARGET="${SCRIPT_DIR}"
  if [[ "$BASE" != "agents-app" ]]; then
    TARGET="$(cd "$SCRIPT_DIR/../agents-app" && pwd)"
  fi
else
  mkdir -p /var/lib/mail-agent-campaign /var/lib/firewall-agent-campaign
  TARGET="${SCRIPT_DIR}"
  if [[ "$BASE" != "agents-campaign" ]]; then
    TARGET="$(cd "$SCRIPT_DIR/../agents-campaign" && pwd)"
  fi
fi

cd "$TARGET"
if [[ ! -f .env && -f .env.example ]]; then
  cp .env.example .env
  echo "==> Created .env from .env.example — review secrets"
fi

echo "==> Starting $ROLE agents from $TARGET"
pm2 start ecosystem.config.cjs
pm2 save
pm2 list
echo "==> Done. Verify AGENT_SERVER=$ROLE in pm2 env: pm2 show mail-log-agent-$ROLE"
