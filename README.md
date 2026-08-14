# 📧 Email Management Dashboard
### Worktual Innovations — email-management.worktual.tech

Full-stack email delivery monitoring portal for your Postfix + Dovecot + OpenDKIM + Amavis + SpamAssassin stack.

---

## 🏗️ Architecture

```
email-management.worktual.tech (port 443)
         │
    [Nginx reverse proxy]
    ├── /        → React Frontend (dist/)
    └── /api/*   → Node.js API (port 5200)
                         │
                  [MariaDB 10.180.0.201]
                  worktual_email_campaign
                  email_delivery_details
```

---

## 📦 Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Recharts, Lucide Icons, Vite |
| Backend | Node.js + Express, mysql2, nodemailer |
| Database | MariaDB (read-only on `worktual_email_campaign`) |
| Reverse Proxy | Nginx |
| Process Manager | PM2 |
| SSL | Let's Encrypt (certbot) |

---

## 🚀 Quick Start

### 1. Backend
```bash
cd backend
cp .env.example .env        # Edit with your credentials
npm install
node server.js              # or: pm2 start ecosystem.config.js
```

### 2. Frontend (Development)
```bash
cd frontend
npm install
npm run dev                 # http://localhost:3000
```

### 3. Frontend (Production Build)
```bash
cd frontend
VITE_API_URL=/api npm run build
# Copy dist/ to /var/www/email-management/dist/
```

### 4. MariaDB User (run on 10.180.0.201)
```sql
CREATE USER 'email_mgmt_user'@'APP_SERVER_IP' IDENTIFIED BY 'STRONG_PASSWORD';
GRANT SELECT ON worktual_email_campaign.email_delivery_details TO 'email_mgmt_user'@'APP_SERVER_IP';
FLUSH PRIVILEGES;
```

---

## 📊 Dashboard Features

### 1. Dashboard Overview
- KPI cards: Total / Success / Failed / Bounced / Deferred / Timed Out / Spam Blocked / Invalid / Processing
- Success/Failure/Bounce rate with health bars
- 7d/30d area trend chart
- Status distribution pie chart
- Hourly delivery breakdown bar chart
- Auto-refresh every 2 minutes

### 2. All Mails
- Full paginated table (50 per page)
- Search by email, queue ID, message ID, campaign
- Filter by status, campaign, DSN code
- Click row to expand full details (queue_id, message_id, full reason)
- CSV export

### 3. Problematic Mails
- Category tabs: Failed / Bounced / Deferred / Timed Out / Invalid / Spam Blocked / Malformed
- Multi-select rows
- **Send team notification** with selected mail IDs attached in email
- CSV export per category

### 4. Campaign Analytics
- Per-campaign delivery breakdown table + bar chart
- Top failure reasons with DSN codes
- Top senders with failure rate
- DSN code breakdown with descriptions

### 5. Alerts & Notifications
- Real-time threshold alert display (Critical / High / Warning)
- Auto-notify button: checks all thresholds → emails relevant teams
- Manual notification sender with team selection
- Team config display

### 6. Spam Guard
- **Blacklist recovery checklist** (ordered by priority)
- Spam pattern analysis from DB (30-day sender analysis)
- Quick diagnostic commands for Postfix/DKIM/SPF/DMARC

---

## 🚨 Anti-Spam: Fix Checklist (You Are on Spamhaus)

### Priority 1 — Immediate Actions
1. **Check Spamhaus**: https://www.spamhaus.org/lookup/
2. **Check all blacklists**: https://mxtoolbox.com/blacklists.aspx
3. **Fix root cause FIRST** (see below), then request delisting

### Priority 2 — Authentication
```bash
# SPF check:
dig TXT worktual.tech | grep spf
# Should contain: v=spf1 ip4:YOUR_MAIL_IP ... ~all or -all

# DKIM check:
dig TXT mail._domainkey.worktual.tech
opendkim-testkey -d worktual.tech -s mail -vvv

# DMARC check:
dig TXT _dmarc.worktual.tech
# Should contain: v=DMARC1; p=quarantine; rua=mailto:dmarc@worktual.tech
```

### Priority 3 — PTR/rDNS (Critical for Postfix)
```bash
dig -x YOUR_MAIL_SERVER_IP
# Must return: mail.worktual.tech (or your mail hostname)
# Contact Leaseweb DC support to set PTR record
```

### Priority 4 — Fix Malformed Emails from Application
```bash
# Your Python email parser app may be sending unformatted headers.
# Check these from your DB:
SELECT reason, COUNT(*) FROM email_delivery_details
WHERE reason LIKE '%format%' OR reason LIKE '%invalid%header%'
   OR reason LIKE '%encoding%' OR reason LIKE '%malformed%'
GROUP BY reason ORDER BY COUNT(*) DESC;
```

### Priority 5 — Postfix Rate Limiting
```ini
# /etc/postfix/main.cf
default_destination_rate_delay = 1s
default_destination_concurrency_limit = 5
smtp_destination_rate_delay = 2s
# Restart: systemctl reload postfix
```

### Priority 6 — List Hygiene
```sql
-- Remove hard bounces immediately:
SELECT DISTINCT mail_to FROM email_delivery_details
WHERE (dsn LIKE '5.1.%' OR reason LIKE '%user unknown%' OR reason LIKE '%no such user%')
  AND log_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY);
```

### Priority 7 — Monitoring
- Register at https://postmaster.google.com/
- Enable Gmail Postmaster Tools
- Target complaint rate < 0.1%
- Set up daily mail log analysis in Wazuh (already on 10.180.1.221)

---

## 🔔 Team Notification Routing

| Team | Email | Triggered For |
|------|-------|--------------|
| DevOps | devops-team@worktual.tech | Spam blocks, IP blacklist, Deferred, Timeouts |
| Backend | backend-team@worktual.tech | Failed delivery, Invalid addresses, Malformed mails |
| Email | email-team@worktual.tech | High bounce rate, Campaign failures |

Configure via `.env`:
```bash
NOTIFY_TEAM_DEVOPS=devops-team@worktual.tech
NOTIFY_TEAM_BACKEND=backend-team@worktual.tech
NOTIFY_TEAM_EMAIL=email-team@worktual.tech

# Alert thresholds (per day):
ALERT_FAILED_THRESHOLD=50      # >50 failed → alert backend team
ALERT_BOUNCE_THRESHOLD=20      # >20 bounced → alert email team
ALERT_SPAM_THRESHOLD=10        # >10 spam blocked → alert devops
```

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | 10.180.0.201 | MariaDB host |
| `DB_PORT` | 3306 | MariaDB port |
| `DB_USER` | — | DB username |
| `DB_PASSWORD` | — | DB password |
| `DB_NAME` | worktual_email_campaign | Database name |
| `PORT` | 5200 | API server port |
| `NOTIFY_SMTP_HOST` | localhost | SMTP host for sending alerts |
| `NOTIFY_FROM` | noreply@worktual.tech | From address for alert emails |
| `ALERT_FAILED_THRESHOLD` | 50 | Failed count to trigger alert |
| `ALERT_BOUNCE_THRESHOLD` | 20 | Bounce count to trigger alert |
| `ALERT_SPAM_THRESHOLD` | 10 | Spam count to trigger alert |

---

## 📡 API Endpoints

```
GET  /api/health                    — Health check
GET  /api/stats/summary             — KPI summary
GET  /api/stats/trend               — 7d/30d trend
GET  /api/stats/hourly              — Hourly breakdown
GET  /api/stats/by-campaign         — Campaign analytics
GET  /api/stats/failure-reasons     — Top failure reasons
GET  /api/stats/by-sender           — Per-sender stats
GET  /api/stats/dsn-breakdown       — DSN code breakdown
GET  /api/mails                     — Paginated mail list
GET  /api/mails/problematic         — Problematic mails by category
GET  /api/mails/spam-analysis       — Spam sender patterns
GET  /api/mails/filter-values       — Filter options
GET  /api/alerts/thresholds         — Alert status
POST /api/alerts/notify             — Send manual notification
POST /api/alerts/auto-notify        — Auto-notify all teams
```

---

*Worktual Innovations Pvt Ltd, Chennai*
*Krishnakumar P — Head of Infrastructure & Engineering*
