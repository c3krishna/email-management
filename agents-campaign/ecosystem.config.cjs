/**
 * Campaign mail host agents — mail.worktual.pl (10.180.0.89)
 *
 * Deploy path on Campaign MTA:
 *   /var/www/email-management/agents-campaign
 *
 * PM2:
 *   cd /var/www/email-management/agents-campaign
 *   pm2 start ecosystem.config.cjs
 *   pm2 save
 *
 * spam-milter MUST use the venv that has pymilter (adjust if needed):
 *   /opt/email-campaign/venv/bin/python3
 */
module.exports = {
  apps: [
    {
      name: 'mail-log-agent-campaign',
      script: './mail-log-agent/log-agent.mjs',
      cwd: __dirname,
      env: {
        AGENT_SERVER: 'campaign',
        AGENT_SERVER_NAME: 'mail.worktual.pl',
        AGENT_VIP: '82.113.72.80',
        OWN_DOMAIN: 'worktual.pl',
        DASHBOARD_URL: 'https://email-management.worktual.tech',
        AGENT_SECRET: process.env.AGENT_SECRET || 'WorktualAgent@2026',
        MAIL_LOG: process.env.MAIL_LOG || '/var/log/mail.log',
        STATE_FILE: '/var/lib/mail-agent-campaign/state.json',
      },
      out_file: '/var/log/email-mgmt/mail-log-agent-campaign.out.log',
      error_file: '/var/log/email-mgmt/mail-log-agent-campaign.err.log',
      merge_logs: true,
    },
    {
      name: 'firewall-agent-campaign',
      script: './firewall-agent/firewall-agent.mjs',
      cwd: __dirname,
      env: {
        AGENT_SERVER: 'campaign',
        OWN_IP: '10.180.0.89',
        DASHBOARD_URL: 'https://email-management.worktual.tech',
        AGENT_SECRET: process.env.AGENT_SECRET || 'WorktualAgent@2026',
        STATE_FILE: '/var/lib/firewall-agent-campaign/state.json',
      },
      out_file: '/var/log/email-mgmt/firewall-agent-campaign.out.log',
      error_file: '/var/log/email-mgmt/firewall-agent-campaign.err.log',
      merge_logs: true,
    },
    {
      name: 'spam-milter-campaign',
      script: './spam-milter/spam_milter.py',
      cwd: __dirname,
      interpreter: process.env.SPAM_MILTER_PYTHON || '/opt/email-campaign/venv/bin/python3',
      env: {
        AGENT_SERVER: 'campaign',
        MILTER_SOCKET: 'inet:8891@127.0.0.1',
        OLLAMA_URL: 'http://miniai.worktual.tech:11434',
        AI_MODEL: 'llama3.1:8b',
        DB_HOST: process.env.DB_HOST || '10.180.0.203',
        DB_USER: 'mailmetrics',
        DB_PASSWORD: process.env.DB_PASSWORD || 'WorktualMailMetrics@123',
        DASHBOARD_URL: 'https://email-management.worktual.tech',
        AGENT_SECRET: process.env.AGENT_SECRET || 'WorktualAgent@2026',
        TAG_THRESHOLD: '75',
        QUARANTINE_THRESHOLD: '85',
        REJECT_THRESHOLD: '95',
      },
      out_file: '/var/log/spam-detector/milter-campaign.log',
      error_file: '/var/log/spam-detector/error-campaign.log',
      merge_logs: true,
    },
  ],
};
