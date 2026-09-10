/**
 * Dashboard / AI-host platform services
 * (virus-rescuers connectors, spam detector poller, notifier, archive)
 *
 * Deploy path (same machine as email-mgmt-api):
 *   /var/www/email-management/backend/platform-services
 *
 * Start / stop / restart:
 *   cd /var/www/email-management/backend/platform-services
 *   cp -n .env.example .env   # edit secrets
 *   set -a && source .env && set +a
 *   ./pm2-migrate.sh
 *   # or:
 *   pm2 start ecosystem.config.cjs
 *   pm2 stop  ecosystem.config.cjs
 *   pm2 restart ecosystem.config.cjs
 *   pm2 save
 *
 * MTA milters stay in agents-app / agents-campaign (not here).
 */
const path = require('path');
const ROOT = __dirname;

const sharedEnv = {
  DB_HOST: process.env.DB_HOST || '10.180.0.84',
  DB_HOST_CAMPAIGN: process.env.DB_HOST_CAMPAIGN || '10.180.0.203',
  DB_USER: process.env.DB_USER || 'mailmetrics',
  DB_PASSWORD: process.env.DB_PASSWORD || '',
  PLATFORM_DB: process.env.PLATFORM_DB || 'threat_platform',
  OLLAMA_URL: process.env.OLLAMA_URL || 'http://miniai.worktual.tech:11434',
  AI_MODEL: process.env.AI_MODEL || 'qwen2.5:14b-instruct-q4_K_M',
  AI_MODEL_FAST: process.env.AI_MODEL_FAST || 'qwen2.5:7b-instruct-q4_K_M',
  DASHBOARD_URL: process.env.DASHBOARD_URL || 'https://email-management.worktual.tech',
  AGENT_SECRET: process.env.AGENT_SECRET || '',
};

module.exports = {
  apps: [
    {
      name: 'platform-spam-detector',
      script: path.join(ROOT, 'spam-detector/spam_detector.py'),
      interpreter: 'python3',
      cwd: path.join(ROOT, 'spam-detector'),
      instances: 1,
      autorestart: true,
      env: {
        ...sharedEnv,
        POLL_INTERVAL: process.env.SPAM_POLL_INTERVAL || '120',
        IMAP_HOST: process.env.IMAP_HOST || process.env.MAIL_IMAP_HOST || '10.180.0.84',
        IMAP_PORT: process.env.IMAP_PORT || '993',
        IMAP_USER: process.env.IMAP_USER || process.env.MAIL_IMAP_USER || '',
        IMAP_PASS: process.env.IMAP_PASS || process.env.MAIL_IMAP_PASSWORD || '',
        SMTP_HOST: process.env.SMTP_HOST || 'mail.worktual.tech',
        SMTP_PORT: process.env.SMTP_PORT || '587',
        SMTP_USER: process.env.SMTP_USER || '',
        SMTP_PASS: process.env.SMTP_PASS || '',
        ALERT_EMAIL: process.env.ALERT_EMAIL || '',
      },
      out_file: '/var/log/spam-detector/out.log',
      error_file: '/var/log/spam-detector/error.log',
      merge_logs: true,
    },
    {
      name: 'platform-vr-connector',
      script: path.join(ROOT, 'virus-rescuers/connectors/universal_connector.py'),
      interpreter: 'python3',
      cwd: path.join(ROOT, 'virus-rescuers/connectors'),
      instances: 1,
      autorestart: true,
      env: {
        ...sharedEnv,
        POLL_INTERVAL: process.env.CONNECTOR_POLL_INTERVAL || '300',
      },
      out_file: '/var/log/vr-connector/out.log',
      error_file: '/var/log/vr-connector/error.log',
      merge_logs: true,
    },
    {
      name: 'platform-wazuh-connector',
      script: path.join(ROOT, 'virus-rescuers/connectors/wazuh_connector.py'),
      interpreter: 'python3',
      cwd: path.join(ROOT, 'virus-rescuers/connectors'),
      instances: 1,
      autorestart: true,
      env: {
        ...sharedEnv,
        WAZUH_API_URL: process.env.WAZUH_API_URL || '',
        WAZUH_API_USER: process.env.WAZUH_API_USER || '',
        WAZUH_API_PASS: process.env.WAZUH_API_PASS || '',
        WAZUH_INDEXER_URL: process.env.WAZUH_INDEXER_URL || '',
        WAZUH_INDEXER_USER: process.env.WAZUH_INDEXER_USER || '',
        WAZUH_INDEXER_PASS: process.env.WAZUH_INDEXER_PASS || '',
        POLL_INTERVAL: process.env.WAZUH_POLL_INTERVAL || '300',
      },
      out_file: '/var/log/wazuh-connector/out.log',
      error_file: '/var/log/wazuh-connector/error.log',
      merge_logs: true,
    },
    {
      name: 'platform-vr-notifier',
      script: path.join(ROOT, 'virus-rescuers/notifications/notifier.py'),
      interpreter: 'python3',
      cwd: path.join(ROOT, 'virus-rescuers/notifications'),
      instances: 1,
      autorestart: true,
      env: {
        ...sharedEnv,
        SMTP_HOST: process.env.SMTP_HOST || 'mail.worktual.tech',
        SMTP_PORT: process.env.SMTP_PORT || '587',
        SMTP_USER: process.env.SMTP_USER || '',
        SMTP_PASS: process.env.SMTP_PASS || '',
        SMTP_FROM_NAME: process.env.SMTP_FROM_NAME || 'Worktual Security',
        VR_OPS_EMAIL: process.env.VR_OPS_EMAIL || '',
        POLL_INTERVAL: process.env.NOTIFY_POLL_INTERVAL || '30',
        NOTIFY_MIN_CONFIDENCE: process.env.NOTIFY_MIN_CONFIDENCE || '70',
        RATE_LIMIT_PER_HOUR: process.env.RATE_LIMIT_PER_HOUR || '20',
      },
      out_file: '/var/log/vr-notifier/out.log',
      error_file: '/var/log/vr-notifier/error.log',
      merge_logs: true,
    },
    {
      name: 'platform-mailbox-monitor',
      script: path.join(ROOT, 'virus-rescuers/mailbox_monitor.py'),
      interpreter: 'python3',
      cwd: path.join(ROOT, 'virus-rescuers'),
      instances: 1,
      autorestart: true,
      env: {
        ...sharedEnv,
        POLL_INTERVAL: process.env.MAILBOX_POLL_INTERVAL || '120',
      },
      out_file: '/var/log/mailbox-monitor/out.log',
      error_file: '/var/log/mailbox-monitor/error.log',
      merge_logs: true,
    },
    {
      name: 'platform-archive-logs',
      script: path.join(ROOT, 'threat-platform/scripts/archive-old-logs.mjs'),
      cwd: path.join(ROOT, 'threat-platform/scripts'),
      instances: 1,
      autorestart: false,
      cron_restart: '0 2 1 * *',
      env: {
        ...sharedEnv,
        OCI_TENANCY_ID: process.env.OCI_TENANCY_ID || '',
        OCI_USER_ID: process.env.OCI_USER_ID || '',
        OCI_FINGERPRINT: process.env.OCI_FINGERPRINT || '',
        OCI_PRIVATE_KEY_PATH: process.env.OCI_PRIVATE_KEY_PATH || '',
        OCI_REGION: process.env.OCI_REGION || '',
        OCI_NAMESPACE: process.env.OCI_NAMESPACE || '',
        OCI_ARCHIVE_BUCKET: process.env.OCI_ARCHIVE_BUCKET || 'email-log-archive',
      },
      out_file: '/var/log/email-mgmt/archive-logs.out.log',
      error_file: '/var/log/email-mgmt/archive-logs.err.log',
      merge_logs: true,
    },
  ],
};
