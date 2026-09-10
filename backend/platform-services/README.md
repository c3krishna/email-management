# Platform services (dashboard / AI host)

These are the **extra** processes that used to live under `/opt/virus-rescuers`, `/opt/spam-detector`, and `/opt/threat-platform` on the dashboard host. They are now versioned with this repo so you can start/stop them with PM2 alongside `email-mgmt-api`.

| PM2 name | Source | Role |
|----------|--------|------|
| `platform-spam-detector` | `spam-detector/spam_detector.py` | Poll realtime logs + IMAP for spam |
| `platform-vr-connector` | `virus-rescuers/connectors/universal_connector.py` | Customer mail platform connectors |
| `platform-wazuh-connector` | `virus-rescuers/connectors/wazuh_connector.py` | Wazuh SIEM → events |
| `platform-vr-notifier` | `virus-rescuers/notifications/notifier.py` | Threat email / webhook alerts |
| `platform-mailbox-monitor` | `virus-rescuers/mailbox_monitor.py` | Customer IMAP monitors + AI |
| `platform-archive-logs` | `threat-platform/scripts/archive-old-logs.mjs` | Monthly OCI archive (cron) |

**Not here:** Postfix milters / log agents — use `agents-app` / `agents-campaign` on each MTA.

## Deploy (dashboard host)

```bash
cd /var/www/email-management
git pull
cd backend/platform-services
cp -n .env.example .env
# edit .env — DB_PASSWORD, AGENT_SECRET, IMAP/SMTP, Wazuh

chmod +x pm2-migrate.sh
./pm2-migrate.sh
# first time also:
#   mkdir -p /var/log/{spam-detector,vr-connector,wazuh-connector,vr-notifier,mailbox-monitor,email-mgmt}
```

Optional symlink for old `/opt` paths (if other scripts still point there):

```bash
sudo ln -sfn /var/www/email-management/backend/platform-services/virus-rescuers /opt/virus-rescuers
sudo ln -sfn /var/www/email-management/backend/platform-services/spam-detector /opt/spam-detector
sudo ln -sfn /var/www/email-management/backend/platform-services/threat-platform /opt/threat-platform
```

## Everyday start / stop

```bash
cd /var/www/email-management/backend/platform-services
set -a && source .env && set +a

pm2 start   ecosystem.config.cjs
pm2 stop    ecosystem.config.cjs
pm2 restart ecosystem.config.cjs
pm2 delete  ecosystem.config.cjs   # full remove
pm2 logs platform-spam-detector
pm2 save
```

## Python deps

```bash
pip3 install mysql-connector-python requests
# mailbox monitor extras as needed: pillow pyzbar ...
```
