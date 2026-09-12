# Email Infra Management Application

**Product:** Email Management — Email Security Gateway  
**Operator URL:** `https://email-management.worktual.tech`  
**Owner:** Worktual Innovations  
**Version:** 2.1.x (API / UI)

---

## 1. Purpose

The Email Infra Management Application is the **operations, analytics, and AI security console** for Worktual’s dual Postfix mail platforms:

1. **App Mail** (`mail.worktual.tech`) — transactional and application email  
2. **Campaign** (`mail.worktual.pl`) — bulk campaign email and reporting  

It unifies:

- Real-time Postfix delivery visibility (per infrastructure)
- Quarantine / policies / spam thresholds (per infrastructure)
- AI threat detection (spam, phishing, BEC, malware, URL threats)
- Threat Intelligence, Virus Rescuers connectors, Wazuh SIEM, firewall
- Customer validation API and VIP / impersonation protection

Operators switch between App and Campaign with the **Topbar** toggle; metrics and policies follow the selected server.

---

## 2. Business platforms

| | App Mail | Campaign |
|--|----------|----------|
| **Code key** | `app` | `campaign` |
| **SMTP domain** | `mail.worktual.tech` | `mail.worktual.pl` |
| **Active IP** | `10.180.0.84` | `10.180.0.89` |
| **VIP** | `82.113.72.84` | `82.113.72.80` |
| **Primary use** | Notifications, CCaaS, AI CCaaS, client-From via Worktual | Bulk sending, bounce/complaint reporting |
| **Owned domains** | `worktual.tech`, `worktual.com` | `worktual.pl`, plus shared Worktual domains |
| **Agent pack** | `agents-app/` | `agents-campaign/` |
| **Email metrics DB host** | `10.180.0.84` | `10.180.0.203` |
| **Email DB name** | `worktual_email_campaign` | `worktual_email_campaign` (same name, different host) |

Customers can be bound to `mail_server` = `app` | `campaign` | `both`.

Detail: [App-Platform.md](./App-Platform.md) · [Campaign-Platform.md](./Campaign-Platform.md)

---

## 3. Solution building blocks

| Layer | Technology | Location |
|-------|------------|----------|
| UI | React 18, Vite, Recharts, Lucide | `frontend/` |
| API | Node.js Express, mysql2, JWT | `backend/` (`server.js`, port **5200**) |
| Reverse proxy | Nginx TLS | `nginx.conf` → SPA + `/api/` |
| Process manager | PM2 | `email-mgmt-api`, agents, platform-* |
| Email metrics DBs | MariaDB (dual hosts) | `worktual_email_campaign` |
| Security / TI DB | MariaDB | `threat_platform` (typically on App DB host) |
| AI | Ollama on MiniAI | `miniai.worktual.tech:11434` |
| MTA agents | Node (log/firewall) + Python milter | `agents-app/`, `agents-campaign/` |
| Platform pollers | Python / Node | `backend/platform-services/` |

Canonical deploy path: `/var/www/email-management`.

---

## 4. Application modules (UI)

Navigation is page-id based (`App.jsx` + `Sidebar.jsx`). Major areas:

### 4.1 Operations (server-scoped via Topbar)

| Module | What it shows / does |
|--------|----------------------|
| **Overview** | KPIs, traffic waveform, breakdown, top senders/recipients |
| **Email Logs** | Live parsed Postfix stream (subjects decoded from RFC 2047) |
| **Delivery Status** | Queue snapshots from mail-log agents |
| **Quarantine** | Hold / release / delete / allow (writes whitelist for milter) |
| **Policies** | Per-server spam thresholds (tag / quarantine / reject) |
| **All Mails / Problematic** | Historical delivery + failure categories |
| **Inbox** | Admin IMAP (Campaign prefers active IP, not VIP) |
| **Compare** | Campaign queue vs delivery waveform |

### 4.2 Analytics

| Module | Scope |
|--------|--------|
| Campaign Reports | Bulk campaign delivery |
| Spam Analysis | Milter / detector trends |
| Reporting | Exportable security/ops reports |
| Top senders / recipients | Volume analytics |

### 4.3 Security & AI

| Module | Scope |
|--------|--------|
| Platform Overview | Dual-infra health |
| VR Threat Platform | Virus Rescuers / connectors UI |
| AI Orchestration | Multi-stage live analysis (long nginx timeout) |
| Validation API | Customer email validate API |
| Threat Intelligence | TI KPIs + **threat waveform** (hourly/daily) |
| Threat Management | AI threat engine indicators |
| VIP Protection | Impersonation / VIP rules |
| Mailbox Monitors | Customer IMAP watchers |
| Wazuh SIEM | Alerts filtered by `mail_server` |
| Firewall | iptables / Fail2Ban events from both MTAs |
| SpamGuard / IP Reputation | Hardening and reputation views |

### 4.4 Administration

| Module | Who |
|--------|-----|
| Customers | Bind customers to app / campaign / both |
| Users | Roles: `super_admin`, `admin`, `viewer` |
| Settings | App settings (`super_admin`) |
| Alerts | Threshold alerts + SMTP notify |

---

## 5. Identity & access

| Mechanism | Use |
|-----------|-----|
| JWT Bearer (`Authorization`) | Dashboard users — session default **8h** |
| Roles | `super_admin`, `admin`, `viewer` |
| Users table | `email_mgmt_users` on **App** email DB |
| `X-Agent-Secret` | Agents / milters / connectors ingest |
| `X-Agent-Server` | `app` \| `campaign` — selects email DB pool |
| Customer API keys | `/api/v1` validation and platform APIs |

Auth endpoints: `/api/auth/login`, OTP reset flow, `me`, `logout`.

---

## 6. API surface (summary)

| Prefix | Audience |
|--------|----------|
| `/api/health` | Public health |
| `/api/auth/*` | Login / session |
| `/api/agent/*` | Log ingest, realtime logs, queue, status |
| `/api/stats/*` | KPIs, hourly, recent logs |
| `/api/quarantine`, `/api/policies` | Hold + thresholds |
| `/api/spam/*` | Detections, whitelist for agents |
| `/api/firewall/*` | Firewall events / waveform |
| `/api/threats/*`, `/api/connectors/*` | TI / connectors |
| `/api/orchestration/*` | Deep AI pipeline |
| `/api/v1/*` | Customer validate API |
| `/api/platform/*` | Customers, keys, platform ops |
| `/api/inbox`, `/api/mails`, `/api/compare`, … | Ops pages |

Full dual-server deploy steps: [DEPLOY.md](../DEPLOY.md).

---

## 7. AI models (MiniAI / Ollama)

Configured in `backend/aiConfig.js` / env:

| Env | Default model | Typical use |
|-----|---------------|-------------|
| `AI_MODEL` | `qwen2.5:14b-instruct-q4_K_M` | Spam / phishing / validation |
| `AI_MODEL_FAST` | `qwen2.5:7b-instruct-q4_K_M` | Postfix milter hot path |
| `AI_MODEL_DEEP` | `deepseek-r1:32b` | Orchestration / BEC-style depth |
| `AI_MODEL_PATTERN` | `gemma3:12b` | Secondary / pattern assist |

Endpoint: `OLLAMA_URL=http://miniai.worktual.tech:11434`.

---

## 8. Runtime processes

### Dashboard host

| PM2 name | Role |
|----------|------|
| `email-mgmt-api` | Express API `:5200` |
| `platform-spam-detector` | Poll logs + IMAP → spam detections |
| `platform-vr-connector` | Customer platform connectors |
| `platform-wazuh-connector` | Wazuh sync |
| `platform-vr-notifier` | Security event notifications |
| `platform-mailbox-monitor` | IMAP monitors |
| `platform-archive-logs` | Monthly log archive to OCI |

### App MTA (`agents-app`)

| PM2 name | Role |
|----------|------|
| `mail-log-agent-app` | Tail `mail.log` → `/api/agent/ingest` |
| `firewall-agent-app` | iptables / Fail2Ban → `/api/firewall/events` |
| `spam-milter-app` | Postfix milter `:8891` |

### Campaign MTA (`agents-campaign`)

| PM2 name | Role |
|----------|------|
| `mail-log-agent-campaign` | Same pattern, tagged `campaign` |
| `firewall-agent-campaign` | Campaign firewall events |
| `spam-milter-campaign` | Campaign milter `:8891` |

---

## 9. Core data stores

| Store | Host(s) | Contents |
|-------|---------|----------|
| `worktual_email_campaign` | App `10.180.0.84` | Auth users, App delivery, realtime logs, quarantine, policies |
| `worktual_email_campaign` | Campaign `10.180.0.203` | Campaign delivery, realtime logs, quarantine, policies |
| `threat_platform` | Usually App DB host | Spam detections, indicators, connectors, Wazuh, firewall, VIP |

Topbar `server=app|campaign` selects which email metrics pool `getPool(server)` uses. Security tables often filter on `mail_server` / `server` columns.

---

## 10. End-to-end flows (brief)

**Delivery visibility**

```text
Postfix mail.log → mail-log-agent → POST /api/agent/ingest
  → email_log_realtime (+ delivery details)
  → Email Logs / Overview (decoded subjects)
```

**Spam / quarantine**

```text
SMTP → spam-milter (pattern + Ollama) → tag / quarantine / reject
  → notification → spam_detections
Quarantine Allow → spam_whitelist → milter refresh (~5 min)
```

**Threat Intelligence waveform**

```text
security_events + spam_detections + threat_indicators
  → /api/connectors/summary threatTrend (hourly ≤48h, else daily)
  → Threat Intelligence AreaChart
```

See [Architecture.md](./Architecture.md) for diagrams.

---

## 11. Non-goals / boundaries

- Not a full replacement for Postfix/Dovecot admin UIs  
- Not the MTA itself — agents and milters run **on** the MTA hosts  
- Campaign IMAP from the dashboard must use the **active IP** (`10.180.0.89`); VIP often refuses connections from the API host  

---

## 12. Document map

| Need | Open |
|------|------|
| Diagrams & topology | [Architecture.md](./Architecture.md) |
| App-only detail | [App-Platform.md](./App-Platform.md) |
| Campaign-only detail | [Campaign-Platform.md](./Campaign-Platform.md) |
| Deploy checklist | [../DEPLOY.md](../DEPLOY.md) |
