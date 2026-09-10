/**
 * App mailbox monitor (IMAP customer inbox scanning)
 * Prefer dashboard host; App SMTP for alerts.
 *
 * pm2 start ecosystem.config.cjs
 * Path: /var/www/email-management/agents-app/mailbox-monitor
 */
module.exports = {
  apps: [
    {
      name: 'mailbox-monitor-app',
      script: './mailbox_monitor.py',
      cwd: __dirname,
      interpreter: 'python3',
      env: {
        DB_HOST: process.env.DB_HOST || '10.180.0.84',
        DB_USER: process.env.DB_USER || 'mailmetrics',
        DB_PASSWORD: process.env.DB_PASSWORD || 'WorktualMailMetrics@123',
        DASHBOARD_URL: process.env.DASHBOARD_URL || 'https://email-management.worktual.tech',
        AGENT_SECRET: process.env.AGENT_SECRET || 'WorktualAgent@2026',
        OLLAMA_URL: process.env.OLLAMA_URL || 'http://miniai.worktual.tech:11434',
        AI_MODEL: process.env.AI_MODEL || 'llama3.1:8b',
        POLL_INTERVAL: process.env.POLL_INTERVAL || '120',
        SMTP_HOST: process.env.SMTP_HOST || 'mail.worktual.tech',
        SMTP_PORT: process.env.SMTP_PORT || '587',
        SMTP_USER: process.env.SMTP_USER || 'security@worktual.tech',
        SMTP_PASS: process.env.SMTP_PASS || '',
        SMTP_FROM_NAME: process.env.SMTP_FROM_NAME || 'Worktual Security',
        NOTIFY_MIN_CONFIDENCE: process.env.NOTIFY_MIN_CONFIDENCE || '60',
      },
      out_file: '/var/log/mailbox-monitor/app-out.log',
      error_file: '/var/log/mailbox-monitor/app-error.log',
      merge_logs: true,
    },
  ],
};
