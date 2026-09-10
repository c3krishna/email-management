/**
 * App mail host agents — mail.worktual.tech (10.180.0.84)
 *
 * Deploy path on App MTA:
 *   /var/www/email-management/agents-app
 *
 * PM2:
 *   cd /var/www/email-management/agents-app
 *   pm2 start ecosystem.config.cjs
 *   pm2 save
 *
 * spam-milter MUST use the venv that has pymilter (adjust if needed):
 *   /opt/email-campaign/venv/bin/python3
 */
module.exports = {
  apps: [
    {
      name: 'mail-log-agent-app',
      script: './mail-log-agent/log-agent.mjs',
      cwd: __dirname,
      env: {
        AGENT_SERVER: 'app',
        AGENT_SERVER_NAME: 'mail.worktual.tech',
        AGENT_VIP: '82.113.72.84',
        OWN_DOMAIN: 'worktual.tech',
        DASHBOARD_URL: 'https://email-management.worktual.tech',
        AGENT_SECRET: process.env.AGENT_SECRET || 'WorktualAgent@2026',
        MAIL_LOG: process.env.MAIL_LOG || '/var/log/mail.log',
        STATE_FILE: '/var/lib/mail-agent-app/state.json',
      },
      out_file: '/var/log/email-mgmt/mail-log-agent-app.out.log',
      error_file: '/var/log/email-mgmt/mail-log-agent-app.err.log',
      merge_logs: true,
    },
    {
      name: 'firewall-agent-app',
      script: './firewall-agent/firewall-agent.mjs',
      cwd: __dirname,
      env: {
        AGENT_SERVER: 'app',
        OWN_IP: '10.180.0.84',
        DASHBOARD_URL: 'https://email-management.worktual.tech',
        AGENT_SECRET: process.env.AGENT_SECRET || 'WorktualAgent@2026',
        STATE_FILE: '/var/lib/firewall-agent-app/state.json',
      },
      out_file: '/var/log/email-mgmt/firewall-agent-app.out.log',
      error_file: '/var/log/email-mgmt/firewall-agent-app.err.log',
      merge_logs: true,
    },
    {
      name: 'spam-milter-app',
      script: './spam-milter/spam_milter.py',
      cwd: __dirname,
      interpreter: process.env.SPAM_MILTER_PYTHON || '/opt/email-campaign/venv/bin/python3',
      env: {
        AGENT_SERVER: 'app',
        MILTER_SOCKET: 'inet:8891@127.0.0.1',
        OLLAMA_URL: 'http://miniai.worktual.tech:11434',
        AI_MODEL: 'llama3.1:8b',
        DB_HOST: '10.180.0.84',
        DB_USER: 'mailmetrics',
        DB_PASSWORD: process.env.DB_PASSWORD || 'WorktualMailMetrics@123',
        DASHBOARD_URL: 'https://email-management.worktual.tech',
        AGENT_SECRET: process.env.AGENT_SECRET || 'WorktualAgent@2026',
        TAG_THRESHOLD: '75',
        QUARANTINE_THRESHOLD: '85',
        REJECT_THRESHOLD: '95',
      },
      out_file: '/var/log/spam-detector/milter-app.log',
      error_file: '/var/log/spam-detector/error-app.log',
      merge_logs: true,
    },
  ],
};
