/**
 * Mail-host agents PM2 config
 *
 * App host:      AGENT_SERVER=app      (mail.worktual.tech)
 * Campaign host: AGENT_SERVER=campaign (mail.worktual.pl)
 *
 * spam-milter MUST use the venv that has pymilter:
 *   /opt/email-campaign/venv/bin/python3
 * (same as old /opt/spam-detector/ecosystem.config.json)
 */
module.exports = {
  apps: [
    {
      name: 'mail-log-agent',
      script: './mail-log-agent/log-agent.mjs',
      cwd: __dirname,
      env: {
        AGENT_SERVER: process.env.AGENT_SERVER || 'app',
        AGENT_SERVER_NAME: process.env.AGENT_SERVER_NAME || 'mail.worktual.tech',
        AGENT_VIP: process.env.AGENT_VIP || '82.113.72.84',
        DASHBOARD_URL: process.env.DASHBOARD_URL || 'https://email-management.worktual.tech',
        AGENT_SECRET: process.env.AGENT_SECRET || 'WorktualAgent@2026',
        MAIL_LOG: process.env.MAIL_LOG || '/var/log/mail.log',
      },
    },
    {
      name: 'firewall-agent',
      script: './firewall-agent/firewall-agent.mjs',
      cwd: __dirname,
      env: {
        AGENT_SERVER: process.env.AGENT_SERVER || 'app',
        OWN_IP: process.env.OWN_IP || '10.180.0.84',
        DASHBOARD_URL: process.env.DASHBOARD_URL || 'https://email-management.worktual.tech',
        AGENT_SECRET: process.env.AGENT_SECRET || 'WorktualAgent@2026',
      },
    },
    {
      name: 'spam-milter',
      script: './spam-milter/spam_milter.py',
      cwd: __dirname,
      // Critical: use existing venv with Milter installed (do NOT use system python3)
      interpreter: '/opt/email-campaign/venv/bin/python3',
      env: {
        AGENT_SERVER: process.env.AGENT_SERVER || 'app',
        MILTER_SOCKET: 'inet:8891@127.0.0.1',
        OLLAMA_URL: 'http://miniai.worktual.tech:11434',
        AI_MODEL: 'llama3.1:8b',
        DB_HOST: '10.180.0.84',
        DB_USER: 'mailmetrics',
        DB_PASSWORD: 'WorktualMailMetrics@123',
        DASHBOARD_URL: 'https://email-management.worktual.tech',
        AGENT_SECRET: 'WorktualAgent@2026',
        TAG_THRESHOLD: '75',
        QUARANTINE_THRESHOLD: '85',
        REJECT_THRESHOLD: '95',
      },
      out_file: '/var/log/spam-detector/milter.log',
      error_file: '/var/log/spam-detector/error.log',
      merge_logs: true,
    },
  ],
};
