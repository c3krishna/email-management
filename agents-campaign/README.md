# agents-campaign — Campaign Bulk (`mail.worktual.pl`)

Deploy **only** on the Campaign MTA (`10.180.0.89`).

```bash
cd /var/www/email-management/agents-campaign
cp -n .env.example .env   # edit secrets
mkdir -p /var/log/email-mgmt /var/log/spam-detector \
  /var/lib/mail-agent-campaign /var/lib/firewall-agent-campaign
pm2 start ecosystem.config.cjs
# or: ./pm2-migrate.sh
pm2 save
pm2 list
```

| PM2 name | Role |
|----------|------|
| `mail-log-agent-campaign` | Postfix log → dashboard |
| `firewall-agent-campaign` | iptables / fail2ban |
| `spam-milter-campaign` | content milter (`127.0.0.1:8891`) |

Defaults (baked into `ecosystem.config.cjs` / `.env.example`):

- `AGENT_SERVER=campaign`
- `AGENT_SERVER_NAME=mail.worktual.pl`
- `AGENT_VIP=82.113.72.80`
- `OWN_IP=10.180.0.89`
- `OWN_DOMAIN=worktual.pl`
- `DB_HOST=10.180.0.203` (campaign metrics DB)

Optional IMAP scanner:

```bash
cd mailbox-monitor && pm2 start ecosystem.config.cjs
```

Do **not** run this tree on `mail.worktual.tech`.
