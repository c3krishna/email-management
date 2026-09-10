# agents-app — App Mail (`mail.worktual.tech`)

Deploy **only** on the App MTA (`10.180.0.84`).

```bash
cd /var/www/email-management/agents-app
cp -n .env.example .env   # edit secrets
mkdir -p /var/log/email-mgmt /var/log/spam-detector \
  /var/lib/mail-agent-app /var/lib/firewall-agent-app
pm2 start ecosystem.config.cjs
# or: ./pm2-migrate.sh
pm2 save
pm2 list
```

| PM2 name | Role |
|----------|------|
| `mail-log-agent-app` | Postfix log → dashboard |
| `firewall-agent-app` | iptables / fail2ban |
| `spam-milter-app` | content milter (`127.0.0.1:8891`) |

Optional IMAP scanner (usually dashboard host):

```bash
cd mailbox-monitor && pm2 start ecosystem.config.cjs
```

Do **not** run this tree on `mail.worktual.pl`.
