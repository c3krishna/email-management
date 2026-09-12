# Campaign Platform

**Code key:** `campaign`  
**SMTP / brand domain:** `mail.worktual.pl`  
**Role:** Bulk campaign sending with delivery, bounce, and complaint reporting  

Parent docs: [Application](./Email-Infra-Management-Application.md) · [Architecture](./Architecture.md)

---

## 1. Host & network

| Item | Value |
|------|--------|
| Active IP | `10.180.0.89` |
| VIP | `82.113.72.80` |
| Mail domains (owned) | `worktual.pl`, plus shared `worktual.tech` / `worktual.com` |
| Email metrics DB | Host **`10.180.0.203`** · DB `worktual_email_campaign` |
| Threat / security DB | Shared `threat_platform` (typically on App DB host `10.180.0.84`) |

Defined in `backend/mailServers.js` under `MAIL_SERVERS.campaign`.

> **IMAP note:** From the dashboard API host, Campaign IMAP should use the **active IP** `10.180.0.89`. Connecting to VIP `82.113.72.80:993` often returns `ECONNREFUSED`.

---

## 2. What Campaign is for

- High-volume bulk / marketing / campaign sends  
- Delivery and bounce analytics for campaign IDs  
- Complaint / failure visibility for list hygiene  
- Policies typically tuned for **bulk** (different thresholds than App transactional)  

In the UI, select **Campaign** in the Topbar. Overview, logs, quarantine, and policies then use the **Campaign** MariaDB pool (`DB_HOST_CAMPAIGN`).

---

## 3. Agents on the Campaign MTA

Deploy tree: `agents-campaign/` → `/var/www/email-management/agents-campaign` on `10.180.0.89`.

| PM2 process | Component | Behaviour |
|-------------|-----------|-----------|
| `mail-log-agent-campaign` | `mail-log-agent/log-agent.mjs` | Tails `/var/log/mail.log`, ingest with `X-Agent-Server: campaign` |
| `firewall-agent-campaign` | `firewall-agent/` | Campaign host firewall events |
| `spam-milter-campaign` | `spam-milter/spam_milter.py` | Milter `:8891`; DB_HOST points at Campaign metrics host where needed |

Environment highlights (see `agents-campaign/.env.example`):

```env
AGENT_SERVER=campaign
AGENT_SERVER_NAME=mail.worktual.pl
AGENT_VIP=82.113.72.80
DASHBOARD_URL=https://email-management.worktual.tech
DB_HOST=10.180.0.203
```

Agent state file (typical): `/var/lib/mail-agent-campaign/state.json`.

Migration helper: `agents-campaign/pm2-migrate.sh` · README: [agents-campaign/README.md](../agents-campaign/README.md).

---

## 4. Data path (Campaign)

```mermaid
flowchart LR
  MTA[Postfix @ 10.180.0.89] --> LOG[mail.log]
  LOG --> AG[mail-log-agent-campaign]
  AG --> API[Dashboard API]
  API --> DB[(worktual_email_campaign<br/>@ 10.180.0.203)]
  MTA --> MIL[spam-milter-campaign :8891]
  MIL --> AI[MiniAI Ollama]
  MIL --> API
  API --> TP[(threat_platform<br/>@ App DB host)]
  UI[Topbar = Campaign] --> API
```

Important: **email KPIs** for Campaign live on `10.180.0.203`, while many **security** tables remain on the shared `threat_platform` database and are filtered by `mail_server=campaign`.

---

## 5. Dashboard behaviour when Campaign is selected

| Feature | Campaign behaviour |
|---------|-------------------|
| Overview KPIs / waveform | Campaign email DB |
| Email Logs | `server=campaign` stream |
| Quarantine / Policies | Campaign pool tables |
| Campaign Reports / Compare | Campaign-oriented analytics; queue tables are Campaign-focused |
| Delivery Status | Queue snapshots from Campaign agent |
| Firewall / Wazuh / TI | Prefer `mail_server=campaign` (or `both`) |
| Inbox | `MAIL_IMAP_CAMPAIGN_HOST=10.180.0.89` (active IP) |

Users still authenticate against App DB; only **mail metrics** switch with Topbar.

---

## 6. Policies & spam (Campaign)

- Set thresholds under **Policies** with Topbar = Campaign.  
- Bulk mail often needs different TAG / QUARANTINE / REJECT cutoffs than App.  
- Quarantine Allow updates whitelist with Campaign (or `both`) scope for the Campaign milter.  

Watch for volume: Campaign log agents and detectors handle higher event rates than App.

---

## 7. Schema / deploy prerequisites

Campaign MariaDB must have the same operational tables as App for:

- `email_log_realtime`, `email_delivery_details`  
- `postfix_queue_snapshot`  
- `email_quarantine`, `app_settings`, policy / blocklist tables  

See `backend/schema_v1_extensions.sql` and `backend/schema_dual_server.sql`. Dashboard `.env`:

```env
DB_HOST=10.180.0.84
DB_HOST_CAMPAIGN=10.180.0.203
DB_NAME=worktual_email_campaign
PLATFORM_DB=threat_platform
```

---

## 8. Ops checklist (Campaign)

1. Agents online on `10.180.0.89`: `*-campaign` PM2 processes  
2. Sidebar agent dot for `mail.worktual.pl` green  
3. Topbar **Campaign** → Email Logs receiving bulk traffic  
4. Confirm API can reach Campaign DB `10.180.0.203`  
5. Inbox / IMAP tests use **active IP**, not VIP  
6. Policies saved for Campaign; milter whitelist refresh verified  

Full dual deploy: [DEPLOY.md](../DEPLOY.md).
