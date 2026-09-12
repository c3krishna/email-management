# App Mail Platform

**Code key:** `app`  
**SMTP / brand domain:** `mail.worktual.tech`  
**Role:** Application notifications, CCaaS email channel, AI CCaaS, client-domain From via Worktual  

Parent docs: [Application](./Email-Infra-Management-Application.md) · [Architecture](./Architecture.md)

---

## 1. Host & network

| Item | Value |
|------|--------|
| Active IP | `10.180.0.84` |
| VIP | `82.113.72.84` |
| Mail domains (owned) | `worktual.tech`, `worktual.com` |
| Email metrics DB | Host `10.180.0.84` · DB `worktual_email_campaign` |
| Threat / security DB | `threat_platform` (typically same host) |
| Notify SMTP (dashboard) | Often `mail.worktual.tech:25` |

Defined in `backend/mailServers.js` under `MAIL_SERVERS.app`.

---

## 2. What App Mail is for

- Transactional and product notifications  
- CCaaS / AI CCaaS channels using Worktual as sending infrastructure  
- Client-domain From addresses routed through Worktual  
- Lower volume, higher trust — policies usually **stricter** than Campaign bulk  

In the UI, select **App Mail** in the Topbar. All Overview / Email Logs / Quarantine / Policies pages then use the **App** MariaDB pool.

---

## 3. Agents on the App MTA

Deploy tree: `agents-app/` → `/var/www/email-management/agents-app` on `10.180.0.84`.

| PM2 process | Component | Behaviour |
|-------------|-----------|-----------|
| `mail-log-agent-app` | `mail-log-agent/log-agent.mjs` | Tails `/var/log/mail.log`, pushes batches to `/api/agent/ingest` with `X-Agent-Server: app`, queue snapshots ~60s |
| `firewall-agent-app` | `firewall-agent/` | Parses iptables / Fail2Ban logs → `/api/firewall/events` |
| `spam-milter-app` | `spam-milter/spam_milter.py` | Listens `127.0.0.1:8891`, pattern + Ollama fast model, pulls policies & whitelist from dashboard |

Environment highlights (see `agents-app/.env.example`):

```env
AGENT_SERVER=app
AGENT_SERVER_NAME=mail.worktual.tech
AGENT_VIP=82.113.72.84
DASHBOARD_URL=https://email-management.worktual.tech
DB_HOST=10.180.0.84
```

Agent state file (typical): `/var/lib/mail-agent-app/state.json`.

Migration helper: `agents-app/pm2-migrate.sh` · README: [agents-app/README.md](../agents-app/README.md).

---

## 4. Data path (App)

```mermaid
flowchart LR
  MTA[Postfix @ 10.180.0.84] --> LOG[mail.log]
  LOG --> AG[mail-log-agent-app]
  AG --> API[Dashboard API]
  API --> DB[(worktual_email_campaign<br/>@ 10.180.0.84)]
  MTA --> MIL[spam-milter-app :8891]
  MIL --> AI[MiniAI Ollama]
  MIL --> API
  API --> TP[(threat_platform)]
  UI[Topbar = App Mail] --> API
```

Inbound/outbound classification uses App owned domains (`worktual.tech`, `worktual.com`) via `OWN_DOMAIN` / `mailServers.js` helpers.

---

## 5. Dashboard behaviour when App is selected

| Feature | App behaviour |
|---------|----------------|
| Overview KPIs / waveform | Reads App email DB |
| Email Logs | `server=app` realtime + historical |
| Quarantine / Policies | App pool tables only |
| Compare delivery waveform | Can follow Topbar (App) |
| Firewall / Wazuh / TI | Prefer rows with `mail_server=app` (or `both`) |
| Inbox IMAP | App IMAP settings (`MAIL_IMAP_*` for App) |

Auth (`email_mgmt_users`) always lives on the **App** DB host regardless of Topbar.

---

## 6. Policies & spam (App)

- Configure thresholds under **Policies** with Topbar = App Mail.  
- Milter refreshes from `/api/policies/for-agent` and `/api/spam/whitelist/for-agent`.  
- Allowing a sender from App Quarantine writes whitelist scoped for App (or `both`).  

Recommended stance: keep App reject/quarantine bands appropriate for **transactional** mail (fewer false positives on known product senders; still block clear phishing).

---

## 7. Platform services (dashboard) related to App

These run on the **dashboard** host, not the MTA:

| Process | App relevance |
|---------|----------------|
| `platform-spam-detector` | May scan App realtime logs / mailboxes |
| `platform-mailbox-monitor` | Customer monitors often on App |
| `platform-vr-connector` | Connectors tagged per customer `mail_server` |
| `platform-wazuh-connector` | Events stamped `mail_server` |

---

## 8. Ops checklist (App)

1. Agents online: `pm2 status` shows `*-app` processes  
2. Sidebar agent dot for `mail.worktual.tech` green  
3. Topbar **App Mail** → Email Logs showing live traffic  
4. Policies saved for App; milter reload within ~5 minutes after whitelist allow  
5. Smoke: send test mail through App VIP/active IP and confirm ingest + (if scored) spam notification  

Full dual deploy: [DEPLOY.md](../DEPLOY.md).
