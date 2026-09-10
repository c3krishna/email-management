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

// Prefer .env; keep same defaults as agents-app so empty PM2 env does not
// override Python os.getenv("DB_PASSWORD", "default") with "".
const sharedEnv = {
  DB_HOST: process.env.DB_HOST || '10.180.0.84',
  DB_HOST_CAMPAIGN: process.env.DB_HOST_CAMPAIGN || '10.180.0.203',
  DB_USER: process.env.DB_USER || 'mailmetrics',
  DB_PASSWORD: process.env.DB_PASSWORD || 'WorktualMailMetrics@123',
  PLATFORM_DB: process.env.PLATFORM_DB || 'threat_platform',
  OLLAMA_URL: process.env.OLLAMA_URL || 'http://miniai.worktual.tech:11434',
  AI_MODEL: process.env.AI_MODEL || 'qwen2.5:14b-instruct-q4_K_M',
  AI_MODEL_FAST: process.env.AI_MODEL_FAST || 'qwen2.5:7b-instruct-q4_K_M',
  DASHBOARD_URL: process.env.DASHBOARD_URL || 'https://email-management.worktual.tech',
  AGENT_SECRET: process.env.AGENT_SECRET || 'WorktualAgent@2026',
};

function pyApp(name, relScript, cwdRel, extraEnv, logs) {
  return {
    name,
    script: path.join(ROOT, relScript),
    interpreter: 'python3',
    cwd: path.join(ROOT, cwdRel),
    instances: 1,
    exec_mode: 'fork',
    autorestart: true,
    max_restarts: 20,
    min_uptime: '10s',
    env: { ...sharedEnv, ...extraEnv },
    out_file: logs.out,
    error_file: logs.err,
    merge_logs: true,
  };
}

module.exports = {
  apps: [
    pyApp(
      'platform-spam-detector',
      'spam-detector/spam_detector.py',
      'spam-detector',
      {
        POLL_INTERVAL: process.env.SPAM_POLL_INTERVAL || '120',
        IMAP_HOST: process.env.IMAP_HOST || process.env.MAIL_IMAP_HOST || '10.180.0.84',
        IMAP_PORT: process.env.IMAP_PORT || '993',
        IMAP_USER: process.env.IMAP_USER || process.env.MAIL_IMAP_USER || 'admin@worktual.tech',
        IMAP_PASS: process.env.IMAP_PASS || process.env.MAIL_IMAP_PASSWORD || process.env.DB_PASSWORD || 'WorktualAdmin@Secure2026',
        SMTP_HOST: process.env.SMTP_HOST || 'mail.worktual.tech',
        SMTP_PORT: process.env.SMTP_PORT || '587',
        SMTP_USER: process.env.SMTP_USER || 'admin@worktual.tech',
        SMTP_PASS: process.env.SMTP_PASS || process.env.MAIL_IMAP_PASSWORD || 'WorktualAdmin@Secure2026',
        ALERT_EMAIL: process.env.ALERT_EMAIL || 'k.pethiah@worktual.com',
      },
      { out: '/var/log/spam-detector/out.log', err: '/var/log/spam-detector/error.log' }
    ),
    pyApp(
      'platform-vr-connector',
      'virus-rescuers/connectors/universal_connector.py',
      'virus-rescuers/connectors',
      { POLL_INTERVAL: process.env.CONNECTOR_POLL_INTERVAL || '300' },
      { out: '/var/log/vr-connector/out.log', err: '/var/log/vr-connector/error.log' }
    ),
    pyApp(
      'platform-wazuh-connector',
      'virus-rescuers/connectors/wazuh_connector.py',
      'virus-rescuers/connectors',
      {
        WAZUH_API_URL: process.env.WAZUH_API_URL || 'https://10.180.1.221:55000',
        WAZUH_API_USER: process.env.WAZUH_API_USER || 'wazuh-wui',
        WAZUH_API_PASS: process.env.WAZUH_API_PASS || '',
        WAZUH_INDEXER_URL: process.env.WAZUH_INDEXER_URL || '',
        WAZUH_INDEXER_USER: process.env.WAZUH_INDEXER_USER || '',
        WAZUH_INDEXER_PASS: process.env.WAZUH_INDEXER_PASS || '',
        POLL_INTERVAL: process.env.WAZUH_POLL_INTERVAL || '300',
      },
      { out: '/var/log/wazuh-connector/out.log', err: '/var/log/wazuh-connector/error.log' }
    ),
    pyApp(
      'platform-vr-notifier',
      'virus-rescuers/notifications/notifier.py',
      'virus-rescuers/notifications',
      {
        SMTP_HOST: process.env.SMTP_HOST || 'mail.worktual.tech',
        SMTP_PORT: process.env.SMTP_PORT || '587',
        SMTP_USER: process.env.SMTP_USER || 'security@worktual.tech',
        SMTP_PASS: process.env.SMTP_PASS || '',
        SMTP_FROM_NAME: process.env.SMTP_FROM_NAME || 'Worktual Security',
        VR_OPS_EMAIL: process.env.VR_OPS_EMAIL || '',
        POLL_INTERVAL: process.env.NOTIFY_POLL_INTERVAL || '30',
        NOTIFY_MIN_CONFIDENCE: process.env.NOTIFY_MIN_CONFIDENCE || '70',
        RATE_LIMIT_PER_HOUR: process.env.RATE_LIMIT_PER_HOUR || '20',
      },
      { out: '/var/log/vr-notifier/out.log', err: '/var/log/vr-notifier/error.log' }
    ),
    pyApp(
      'platform-mailbox-monitor',
      'virus-rescuers/mailbox_monitor.py',
      'virus-rescuers',
      { POLL_INTERVAL: process.env.MAILBOX_POLL_INTERVAL || '120' },
      { out: '/var/log/mailbox-monitor/out.log', err: '/var/log/mailbox-monitor/error.log' }
    ),
    {
      name: 'platform-archive-logs',
      script: path.join(ROOT, 'threat-platform/scripts/archive-old-logs.mjs'),
      cwd: path.join(ROOT, 'threat-platform/scripts'),
      instances: 1,
      exec_mode: 'fork',
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
