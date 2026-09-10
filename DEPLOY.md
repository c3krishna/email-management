# Email Management + AI Cyber Security — Deployment Guide

Dual mail infrastructure:

| Role | Code key | Domain | Active IP | VIP |
|------|----------|--------|-----------|-----|
| App (notifications, CCaaS, AI CCaaS, client-From via Worktual) | `app` | `mail.worktual.tech` | `10.180.0.84` | `82.113.72.84` |
| Campaign (bulk sending + reports) | `campaign` | `mail.worktual.pl` | `10.180.0.89` | `82.113.72.80` |

Dashboard: `email-management.worktual.tech` → API `:5200`

---

## 1. What to do next (checklist)

1. **Deploy dashboard** (this repo) with `.env` — no secrets in `ecosystem.config.js`
2. **Rotate** any secrets that were previously committed in old configs
3. **Deploy segregated agents** — `agents-app` on App MTA, `agents-campaign` on Campaign MTA (see §3)
4. **Bind customers** to mail server in UI (Customers → `mail_server`: app / campaign / both)
5. **Set separate Policies** per Topbar App | Campaign (thresholds differ for bulk vs transactional)
6. **Smoke-test** quarantine allow, spam tagging, Wazuh clusters, firewall events from both hosts

---

## 2. Dashboard server deploy

### 2.1 Copy code

```bash
# Example path
sudo mkdir -p /var/www/email-management
# rsync or git pull your build into /var/www/email-management
cd /var/www/email-management
```

### 2.2 Backend environment

```bash
cd /var/www/email-management/backend
cp .env.example .env
nano .env
```

**Required variables:**

```env
DB_HOST=10.180.0.84
DB_HOST_CAMPAIGN=10.180.0.203
DB_PORT=3306
DB_USER=...
DB_PASSWORD=...
DB_NAME=worktual_email_campaign
PLATFORM_DB=threat_platform

PORT=5200
NODE_ENV=production
FRONTEND_URL=https://email-management.worktual.tech

JWT_SECRET=<long-random-secret>
AGENT_SECRET=<shared-with-all-agents>
SESSION_EXPIRES=8h

OLLAMA_URL=http://miniai.worktual.tech:11434

NOTIFY_SMTP_HOST=mail.worktual.tech
NOTIFY_SMTP_PORT=25
NOTIFY_FROM=noreply@worktual.tech
```

Optional: `MAIL_IMAP_*` / `MAIL_SMTP_*` for Inbox page.

### 2.3 Install & start API

```bash
cd /var/www/email-management/backend
npm install --omit=dev
pm2 start ecosystem.config.js
# or: pm2 restart email-mgmt-api
pm2 save
```

`ecosystem.config.js` only sets `NODE_ENV` / `PORT` — secrets come from `.env` via dotenv.

### 2.4 Frontend build

```bash
cd /var/www/email-management/frontend
npm install
VITE_API_URL=/api npm run build
```

Point Nginx `root` at `frontend/dist` (or sync into your existing dist path).

### 2.5 Nginx (summary)

- TLS vhost for `email-management.worktual.tech`
- `location /api/` → `http://127.0.0.1:5200`
- SPA fallback to `index.html`

### 2.6 Schema (auto + optional SQL)

Tables for quarantine / policies create on first use.  
For dual-server AI columns, run once on `threat_platform`:

```bash
mysql -h "$DB_HOST" -u "$DB_USER" -p threat_platform < backend/schema_dual_server.sql
```

Also ensure `email_quarantine` / `app_settings` / `policy_blocklist` exist on **both** email DB hosts (`DB_HOST` and `DB_HOST_CAMPAIGN`).

---

## 3. Mail server agents (segregated: agents-app + agents-campaign)

Agent sources are split by infrastructure:

| Tree | Host | Domain | Path on MTA |
|------|------|--------|-------------|
| `agents-app/` | App mail (`10.180.0.84`) | `mail.worktual.tech` | `/var/www/email-management/agents-app` |
| `agents-campaign/` | Campaign mail (`10.180.0.89`) | `mail.worktual.pl` | `/var/www/email-management/agents-campaign` |

Each tree includes:

- `mail-log-agent/log-agent.mjs`
- `firewall-agent/firewall-agent.mjs`
- `spam-milter/spam_milter.py`
- `mailbox-monitor/` (optional; usually dashboard host)
- `ecosystem.config.cjs` + `.env.example`

### 3.1 Migrate from old `agents/` on each MTA

```bash
# On BOTH mail hosts — stop legacy shared names
pm2 stop mail-log-agent firewall-agent spam-milter mailbox-monitor 2>/dev/null || true
pm2 delete mail-log-agent firewall-agent spam-milter mailbox-monitor 2>/dev/null || true

# Pull latest repo under /var/www/email-management
cd /var/www/email-management && git pull

# App host only (mail.worktual.tech)
mkdir -p /var/log/email-mgmt /var/log/spam-detector /var/lib/mail-agent-app /var/lib/firewall-agent-app
cd /var/www/email-management/agents-app
cp -n .env.example .env   # edit secrets if needed
pm2 start ecosystem.config.cjs
pm2 save

# Campaign host only (mail.worktual.pl)
mkdir -p /var/log/email-mgmt /var/log/spam-detector /var/lib/mail-agent-campaign /var/lib/firewall-agent-campaign
cd /var/www/email-management/agents-campaign
cp -n .env.example .env
pm2 start ecosystem.config.cjs
pm2 save
```

PM2 process names after migrate:

| App (`*-app`) | Campaign (`*-campaign`) |
|---------------|-------------------------|
| `mail-log-agent-app` | `mail-log-agent-campaign` |
| `firewall-agent-app` | `firewall-agent-campaign` |
| `spam-milter-app` | `spam-milter-campaign` |

### 3.2 App mail host (`10.180.0.84` / mail.worktual.tech)

```env
AGENT_SERVER=app
AGENT_SERVER_NAME=mail.worktual.tech
AGENT_VIP=82.113.72.84
OWN_IP=10.180.0.84
OWN_DOMAIN=worktual.tech
```

Defaults are baked into `agents-app/ecosystem.config.cjs`.

Postfix (`main.cf`):

```
smtpd_milters = inet:127.0.0.1:8891
non_smtpd_milters = inet:127.0.0.1:8891
milter_default_action = accept
milter_protocol = 6
```

### 3.3 Campaign mail host (`10.180.0.89` / mail.worktual.pl)

```env
AGENT_SERVER=campaign
AGENT_SERVER_NAME=mail.worktual.pl
AGENT_VIP=82.113.72.80
OWN_IP=10.180.0.89
OWN_DOMAIN=worktual.pl
DB_HOST=10.180.0.203
```

Defaults are baked into `agents-campaign/ecosystem.config.cjs` (domains use `.pl`, not `.tech`).

### 3.4 Agent → API endpoints

| Agent | Method | Path | Auth |
|-------|--------|------|------|
| mail-log-agent | POST | `/api/agent/ingest` | `X-Agent-Secret`, `X-Agent-Server` |
| mail-log-agent | POST | `/api/agent/queue-snapshot` | same |
| firewall-agent | POST | `/api/firewall/events` | `X-Agent-Secret` |
| spam milter | POST | `/api/spam/notification` | `X-Agent-Secret` |
| spam milter | GET | `/api/spam/whitelist/for-agent?server=` | `X-Agent-Secret` |
| spam milter | GET | `/api/policies/for-agent?server=` | `X-Agent-Secret` |
| virus-rescuers connector | POST | `/api/connectors/process` | `X-Agent-Secret` |

### 3.5 Spam milter dual-server note

Use the correct tree on each host (`agents-app` vs `agents-campaign`).  
Do **not** run Campaign agents with `AGENT_SERVER=app`.

Milter should:

1. Tag detections with `AGENT_SERVER`
2. Load whitelist for `mail_server IN (AGENT_SERVER, 'both')` including **domain and email**
3. Pull thresholds from `/api/policies/for-agent` (separate App vs Campaign policies)

---

## 4. Policies (separate per infra)

In the dashboard Topbar:

1. Select **App** → Policies → set transactional thresholds → Save  
2. Select **Campaign** → Policies → set bulk-oriented thresholds/reports → Save  

Stored in `app_settings` on the corresponding email DB pool.  
Milters read the matching server’s policy via `/api/policies/for-agent`.

**Guidance:**

- **App:** tighter phishing/BEC/quarantine (CCaaS + client From)
- **Campaign:** spam/abuse + bounce/complaint focus; higher volume-friendly thresholds; strong reporting

---

## 5. Customers & mail_server binding

In **Customers**:

- `mail_server = app` — CCaaS / transactional customer domains via `mail.worktual.tech`
- `mail_server = campaign` — bulk brands via `mail.worktual.pl`
- `mail_server = both` — rare; prefer explicit bindings

API ingest/history use this field (no longer `customer_id === 2` hack).

---

## 6. Wazuh (both mail servers)

1. Ensure Wazuh agents installed on **both** MTA hosts  
2. Run `wazuh_connector` twice (or two PM2 apps) with different cluster/`CUSTOMER_ID` / API URLs  
3. Stamp `mail_server=app|campaign` on synced rows  
4. Dashboard: Wazuh SIEM → filter by Topbar / `mail_server`

Clusters table: `wazuh_clusters` (seeded for App + Campaign).

---

## 7. Quarantine allow sync

1. Topbar select correct server  
2. Quarantine → Sync from logs (optional)  
3. Select items → **Allow sender**  
4. Writes `spam_whitelist` with `mail_server` = that infra  
5. Milter on that host reloads whitelist within ~5 minutes  

Release / Delete are dashboard actions; full Postfix reinjection still depends on your milter/queue tooling.

---

## 8. Smoke test

```bash
# API up
curl -s https://email-management.worktual.tech/api/health

# Agent auth fails without secret
curl -s -o /dev/null -w "%{http_code}" -X POST \
  https://email-management.worktual.tech/api/agent/ingest

# From App host — after agents running
# Dashboard: Topbar App → Email Logs LIVE, Spam, Firewall, Quarantine
# Topbar Campaign → same for bulk
```

UI checks:

- [ ] Login works  
- [ ] App | Campaign toggle changes KPIs / logs  
- [ ] Policies save independently per server  
- [ ] Spam detections show `server` column  
- [ ] Quarantine Allow updates whitelist  
- [ ] VIP / Mailbox Monitors / Wazuh / Firewall open without errors  
- [ ] Agent status dots online for both  

---

## 9. Security panel pages (expected behavior)

| Sidebar item | Dual-server behavior |
|--------------|----------------------|
| Platform Overview | Shows both infra roles + connector summary |
| VR Threat Platform | Threat platform DB (tag by server where available) |
| AI Orchestration | Analyze path; pass/server-aware when scanning logs |
| Threat Intelligence | Indicators; filter by server when tagged |
| AI Threat Engine | Use Topbar `server` on APIs |
| Wazuh SIEM | Filter `mail_server=app\|campaign` |
| Firewall Security | Own App/Campaign/All filter + events from both agents |
| Spam Guard / Spam Analysis | `?server=` from Topbar |
| Quarantine / Policies | Per email DB pool via Topbar |

---

## 10. virus-rescuers / spam-detector host layout

| Component | Typical host |
|-----------|----------------|
| spam_milter | Each MTA |
| spam_detector poller | Dashboard or AI host — must poll **both** `DB_HOST` and `DB_HOST_CAMPAIGN` |
| mailbox_monitor | Dashboard / AI host |
| wazuh_connector | Dashboard / SIEM host (×2 for dual clusters) |
| universal_connector | Dashboard / AI host |
| archive-old-logs | Dashboard (cron/PM2) |

---

## 11. Rollback

```bash
pm2 stop email-mgmt-api
# restore previous release directory
pm2 start email-mgmt-api
```

Keep previous `frontend/dist` backup before overwrite.

---

## 12. Support contacts / ops notes

- Compare (Queue vs Delivery) is **campaign-oriented** by design  
- Inbox IMAP defaults to App mail  
- Never commit `.env` or live passwords in `ecosystem.config.*`  
- After any secret leak from old zip/config: **rotate** JWT, AGENT_SECRET, DB, IMAP/SMTP passwords  

---

*Document version: dual-server AI security deploy — App (`mail.worktual.tech`) + Campaign (`mail.worktual.pl`).*
