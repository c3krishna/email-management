#!/usr/bin/env python3
"""
============================================================
Worktual / Virus Rescuers — Real-Time Notification Engine
File: /opt/virus-rescuers/notifications/notifier.py

What it does:
  1. Polls security_events table for unnotified threats
  2. Sends immediate email to:
     - Customer IT Admin / Head
     - Affected end user (recipient of the threat)
     - Virus Rescuers Operations Team (optional)
  3. Supports: Email (SMTP) / Webhook / Teams / Slack
  4. Includes threat details, blocking reason, instructions
  5. Rate-limits to prevent notification floods
  6. Tracks delivery status per notification

Deploy: Dashboard server (82.113.72.52)
PM2: pm2 start notifier.py --interpreter python3 --name vr-notifier
============================================================
"""

import os, json, time, logging, smtplib, hashlib, requests
import mysql.connector
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from email.utils          import formataddr

# ── CONFIG ────────────────────────────────────────────────────
DB_HOST       = os.getenv("DB_HOST",       "10.180.0.84")
DB_USER       = os.getenv("DB_USER",       "mailmetrics")
DB_PASS       = os.getenv("DB_PASSWORD",   "WorktualMailMetrics@123")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))
SMTP_HOST     = os.getenv("SMTP_HOST",     "mail.worktual.tech")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER",     "security@worktual.tech")
SMTP_PASS     = os.getenv("SMTP_PASS",     "")
SMTP_FROM_NAME= os.getenv("SMTP_FROM_NAME","Worktual Security")
VR_OPS_EMAIL  = os.getenv("VR_OPS_EMAIL",  "")  # Virus Rescuers ops team
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "https://email-management.worktual.tech")

# Minimum confidence to trigger notification
NOTIFY_MIN_CONFIDENCE = int(os.getenv("NOTIFY_MIN_CONFIDENCE", "70"))

# Rate limit — max N notifications per customer per hour
RATE_LIMIT_PER_HOUR = int(os.getenv("RATE_LIMIT_PER_HOUR", "20"))

# ── LOGGING ───────────────────────────────────────────────────
os.makedirs("/var/log/vr-notifier", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/var/log/vr-notifier/notifier.log"),
    ]
)
log = logging.getLogger("vr-notifier")

# ── DB ────────────────────────────────────────────────────────
def get_conn(db="threat_platform"):
    return mysql.connector.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASS,
        database=db, autocommit=False, connection_timeout=30
    )

def ensure_schema():
    conn = get_conn()
    cur  = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS notification_log (
      id               BIGINT       NOT NULL AUTO_INCREMENT,
      event_id         BIGINT       NOT NULL,
      customer_id      INT          NOT NULL,
      notification_type ENUM('admin','end_user','ops_team','webhook','slack','teams')
                       NOT NULL DEFAULT 'admin',
      recipient_email  VARCHAR(255) NOT NULL,
      subject          VARCHAR(500) DEFAULT NULL,
      status           ENUM('sent','failed','skipped') DEFAULT 'sent',
      error_message    TEXT         DEFAULT NULL,
      sent_at          DATETIME     DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_event    (event_id),
      KEY idx_customer (customer_id),
      KEY idx_sent     (sent_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS notification_settings (
      id               INT          NOT NULL AUTO_INCREMENT,
      customer_id      INT          NOT NULL,
      notify_admin     TINYINT(1)   DEFAULT 1,
      notify_end_user  TINYINT(1)   DEFAULT 1,
      notify_ops_team  TINYINT(1)   DEFAULT 0,
      admin_emails     TEXT         DEFAULT NULL COMMENT 'JSON array of admin emails',
      webhook_url      VARCHAR(500) DEFAULT NULL,
      slack_webhook    VARCHAR(500) DEFAULT NULL,
      teams_webhook    VARCHAR(500) DEFAULT NULL,
      min_severity     ENUM('low','medium','high','critical') DEFAULT 'medium',
      min_confidence   TINYINT      DEFAULT 70,
      rate_limit_hour  INT          DEFAULT 20,
      notify_blocked   TINYINT(1)   DEFAULT 1,
      notify_delivered TINYINT(1)   DEFAULT 0,
      notify_spam      TINYINT(1)   DEFAULT 1,
      email_template   VARCHAR(50)  DEFAULT 'default',
      active           TINYINT(1)   DEFAULT 1,
      PRIMARY KEY (id),
      UNIQUE KEY uq_customer (customer_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    conn.commit()
    cur.close()
    conn.close()
    log.info("Notification schema ready")

# ── RATE LIMITING ─────────────────────────────────────────────
_rate_cache = {}  # customer_id → list of timestamps

def check_rate_limit(customer_id, limit_per_hour):
    now   = datetime.utcnow()
    cutoff= now - timedelta(hours=1)
    times = _rate_cache.get(customer_id, [])
    times = [t for t in times if t > cutoff]  # keep last hour only
    if len(times) >= limit_per_hour:
        return False  # rate limited
    times.append(now)
    _rate_cache[customer_id] = times
    return True

# ── EMAIL TEMPLATES ───────────────────────────────────────────
THREAT_COLORS_HTML = {
    'phishing':   '#f43f5e',
    'malware':    '#a855f7',
    'spam':       '#f97316',
    'bec':        '#ef4444',
    'url_threat': '#0891b2',
    'scam':       '#eab308',
}

THREAT_ACTIONS = {
    'phishing':   'This email attempted to steal your credentials. Do NOT click any links in it.',
    'malware':    'This email contained malware or malicious attachments. Do NOT open any attachments.',
    'spam':       'This email was identified as unsolicited spam.',
    'bec':        'This appears to be a Business Email Compromise (BEC) attempt targeting your organization.',
    'url_threat': 'This email contained malicious URLs that could compromise your device.',
    'scam':       'This email is a scam attempting to defraud you.',
}

def build_admin_email_html(event, customer):
    """Build rich HTML email for IT Admin."""
    threat_type  = (event.get('threat_category') or 'threat').lower()
    threat_color = THREAT_COLORS_HTML.get(threat_type, '#f97316')
    action_text  = THREAT_ACTIONS.get(threat_type, 'This email was identified as a security threat.')
    event_time   = str(event.get('event_datetime', datetime.utcnow()))[:19]
    platform     = str(event.get('platform', 'unknown')).replace('_',' ').title()

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
  body {{ font-family: -apple-system, Arial, sans-serif; background:#f4f4f5; margin:0; padding:20px; }}
  .container {{ max-width:600px; margin:0 auto; }}
  .header {{ background:{threat_color}; color:#fff; padding:24px; border-radius:12px 12px 0 0; }}
  .header h1 {{ margin:0; font-size:20px; font-weight:800; }}
  .header p  {{ margin:6px 0 0; opacity:0.85; font-size:13px; }}
  .body {{ background:#fff; padding:24px; border:1px solid #e4e4e7; }}
  .threat-box {{ background:#fef2f2; border:2px solid {threat_color}; border-radius:8px; padding:16px; margin-bottom:16px; }}
  .threat-type {{ display:inline-block; background:{threat_color}; color:#fff; padding:3px 12px;
                  border-radius:20px; font-size:12px; font-weight:700; margin-bottom:8px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  td {{ padding:8px 4px; border-bottom:1px solid #f0f0f0; }}
  td:first-child {{ color:#6b7280; width:140px; font-weight:500; }}
  td:last-child {{ color:#111; font-weight:600; word-break:break-all; }}
  .action-box {{ background:#fafafa; border-left:4px solid {threat_color};
                 padding:12px 16px; margin:16px 0; font-size:13px; }}
  .btn {{ display:inline-block; background:#2563eb; color:#fff; padding:10px 24px;
          border-radius:6px; text-decoration:none; font-weight:600; font-size:13px; }}
  .footer {{ background:#f9fafb; padding:14px 24px; border-radius:0 0 12px 12px;
             border:1px solid #e4e4e7; border-top:none; font-size:11px; color:#9ca3af; text-align:center; }}
  .severity {{ padding:2px 10px; border-radius:20px; font-size:11px; font-weight:700;
               background:{threat_color}22; color:{threat_color}; }}
</style></head>
<body><div class="container">

  <!-- Header -->
  <div class="header">
    <h1>🚨 Security Threat Detected</h1>
    <p>{platform} · {event_time} UTC · Customer: {customer.get('name','Unknown')}</p>
  </div>

  <div class="body">
    <!-- Threat badge -->
    <div class="threat-box">
      <span class="threat-type">{threat_type.upper()}</span>
      <div style="font-size:14px;color:#111;font-weight:600;margin-bottom:4px">
        A malicious email has been {event.get('event_type','detected')}
      </div>
      <div style="font-size:12px;color:#6b7280">
        Threat Score: <strong style="color:{threat_color}">
        {event.get('threat_score') or 'High'}</strong>
      </div>
    </div>

    <!-- Email details -->
    <table>
      <tr><td>From:</td>     <td>{event.get('mail_from') or '—'}</td></tr>
      <tr><td>To:</td>       <td>{event.get('mail_to')   or '—'}</td></tr>
      <tr><td>Subject:</td>  <td>{event.get('subject')   or '—'}</td></tr>
      <tr><td>Date/Time:</td><td>{event_time} UTC</td></tr>
      <tr><td>Platform:</td> <td>{platform}</td></tr>
      <tr><td>Action:</td>   <td><strong>{event.get('event_type','Blocked').title()}</strong></td></tr>
      <tr><td>Severity:</td> <td><span class="severity">{threat_type.upper()}</span></td></tr>
    </table>

    <!-- Action required -->
    <div class="action-box">
      <strong>⚠️ Action Required:</strong><br>
      {action_text}<br><br>
      If this email was incorrectly blocked and you need to release it,
      please contact your security administrator or review it in the dashboard.
    </div>

    <!-- Dashboard link -->
    <div style="text-align:center;margin-top:20px">
      <a href="{DASHBOARD_URL}" class="btn">
        View in Security Dashboard →
      </a>
    </div>
  </div>

  <div class="footer">
    This is an automated security alert from <strong>Worktual Email Security Platform</strong><br>
    Powered by Worktual AI Threat Intelligence · {datetime.utcnow().year}<br>
    Do not reply to this email · Contact your IT administrator for assistance
  </div>
</div></body></html>"""


def build_user_email_html(event, customer):
    """Build friendly HTML email for affected end user."""
    threat_type  = (event.get('threat_category') or 'threat').lower()
    threat_color = THREAT_COLORS_HTML.get(threat_type, '#f97316')
    event_time   = str(event.get('event_datetime', datetime.utcnow()))[:19]

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
  body {{ font-family:-apple-system,Arial,sans-serif; background:#f4f4f5; margin:0; padding:20px; }}
  .container {{ max-width:600px; margin:0 auto; }}
  .header {{ background:#1e40af; color:#fff; padding:24px; border-radius:12px 12px 0 0; }}
  .header h1 {{ margin:0; font-size:20px; font-weight:800; }}
  .body {{ background:#fff; padding:24px; border:1px solid #e4e4e7; }}
  .info-box {{ background:#eff6ff; border:1px solid #bfdbfe; border-radius:8px;
               padding:16px; margin:16px 0; }}
  .steps {{ counter-reset:step; list-style:none; padding:0; }}
  .steps li {{ counter-increment:step; padding:10px 10px 10px 40px; position:relative;
               border-bottom:1px solid #f0f0f0; font-size:13px; }}
  .steps li::before {{ content:counter(step); position:absolute; left:8px; top:10px;
                        background:#2563eb; color:#fff; width:20px; height:20px;
                        border-radius:50%; text-align:center; line-height:20px;
                        font-size:11px; font-weight:700; }}
  .footer {{ background:#f9fafb; padding:14px 24px; border-radius:0 0 12px 12px;
             border:1px solid #e4e4e7; border-top:none; font-size:11px;
             color:#9ca3af; text-align:center; }}
</style></head>
<body><div class="container">

  <div class="header">
    <h1>🛡️ Email Blocked for Your Protection</h1>
    <p>Your IT Security System · {event_time} UTC</p>
  </div>

  <div class="body">
    <p style="font-size:14px;color:#374151;margin-bottom:16px">
      Dear User,<br><br>
      Our email security system has <strong>blocked a potentially dangerous email</strong>
      before it reached your inbox. This is to keep you safe.
    </p>

    <div class="info-box">
      <div style="font-size:13px;color:#1e40af;font-weight:700;margin-bottom:8px">
        📧 Blocked Email Details
      </div>
      <div style="font-size:13px;color:#374151;line-height:1.8">
        <strong>From:</strong> {event.get('mail_from') or '—'}<br>
        <strong>Subject:</strong> {event.get('subject') or '—'}<br>
        <strong>Date:</strong> {event_time}<br>
        <strong>Reason:</strong> {threat_type.replace('_',' ').title()} detected
      </div>
    </div>

    <div style="font-size:14px;font-weight:700;color:#111;margin-bottom:8px">
      What should you do?
    </div>
    <ol class="steps">
      <li>No action needed — the email has been safely blocked</li>
      <li>Do NOT attempt to retrieve or open this email</li>
      <li>If you were expecting a legitimate email from this sender,
          contact your IT administrator</li>
      <li>If you have already interacted with this sender,
          notify your IT team immediately</li>
    </ol>

    <div style="background:#fef9c3;border:1px solid #fde047;border-radius:8px;
                padding:14px;margin-top:16px;font-size:13px;color:#713f12">
      <strong>⚠️ Important:</strong> Legitimate organizations will never ask you to
      verify your password or payment details via email. If you are unsure,
      always contact your IT administrator.
    </div>

    <div style="margin-top:20px;padding:14px;background:#f9fafb;border-radius:8px;
                font-size:12px;color:#6b7280">
      Need help? Contact your IT Administrator at
      <strong>{customer.get('admin_email','your IT department')}</strong>
    </div>
  </div>

  <div class="footer">
    This notification was sent by <strong>{customer.get('name','Your Organization')}</strong>
    email security system<br>
    Powered by Worktual AI Threat Intelligence · Do not reply to this email
  </div>
</div></body></html>"""


def build_ops_email_html(event, customer):
    """Build detailed email for Virus Rescuers operations team."""
    threat_type = (event.get('threat_category') or 'threat').lower()
    threat_color= THREAT_COLORS_HTML.get(threat_type, '#f97316')
    event_time  = str(event.get('event_datetime', datetime.utcnow()))[:19]

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
  body {{ font-family:monospace; background:#0d1117; color:#e6edf3;
          margin:0; padding:20px; font-size:13px; }}
  .container {{ max-width:700px; margin:0 auto; }}
  .header {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
             padding:16px; margin-bottom:12px; }}
  .section {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
              padding:14px; margin-bottom:10px; }}
  .label {{ color:#8b949e; font-size:11px; text-transform:uppercase; margin-bottom:4px; }}
  .value {{ color:#e6edf3; font-weight:700; }}
  .badge {{ display:inline-block; padding:2px 10px; border-radius:20px;
            font-size:11px; font-weight:700;
            background:{threat_color}22; color:{threat_color}; }}
  .mono {{ font-family:monospace; font-size:11px; color:#60a5fa; }}
</style></head>
<body><div class="container">

  <div class="header">
    <div style="font-size:16px;font-weight:800;color:{threat_color}">
      🔴 [VR-OPS] Threat Alert: {threat_type.upper()}
    </div>
    <div style="font-size:11px;color:#8b949e;margin-top:4px">
      Customer: {customer.get('name')} | Platform: {event.get('platform')} |
      {event_time} UTC
    </div>
  </div>

  <div class="section">
    <div class="label">Threat Classification</div>
    <span class="badge">{threat_type.upper()}</span>
    &nbsp; Score: <strong style="color:{threat_color}">
    {event.get('threat_score') or 'N/A'}</strong>
    &nbsp; Action: <strong>{event.get('event_type','detected').upper()}</strong>
  </div>

  <div class="section">
    <div class="label">Email Details</div>
    <table style="width:100%;font-size:12px">
      <tr><td style="color:#8b949e;padding:3px 0;width:120px">From:</td>
          <td style="color:#f87171">{event.get('mail_from') or '—'}</td></tr>
      <tr><td style="color:#8b949e;padding:3px 0">To:</td>
          <td>{event.get('mail_to') or '—'}</td></tr>
      <tr><td style="color:#8b949e;padding:3px 0">Subject:</td>
          <td style="color:#fbbf24">{event.get('subject') or '—'}</td></tr>
      <tr><td style="color:#8b949e;padding:3px 0">Sender IP:</td>
          <td class="mono">{event.get('sender_ip') or '—'}</td></tr>
      <tr><td style="color:#8b949e;padding:3px 0">Message ID:</td>
          <td class="mono">{str(event.get('message_id') or '—')[:60]}</td></tr>
    </table>
  </div>

  <div class="section">
    <div class="label">IOC Summary</div>
    <div style="font-size:12px">
      <div>URLs found: <strong>{
        len(json.loads(event.get('urls') or '[]'))
      }</strong></div>
      <div>Attachments: <strong>{
        len(json.loads(event.get('attachment_hashes') or '[]'))
      }</strong></div>
      <div>Sender domain: <strong style="color:#f87171">
        {event.get('sender_domain') or '—'}
      </strong></div>
    </div>
  </div>

  <div style="text-align:center;margin-top:16px">
    <a href="{DASHBOARD_URL}"
       style="background:#2563eb;color:#fff;padding:10px 24px;
              border-radius:6px;text-decoration:none;font-size:13px;font-weight:600">
      View in Dashboard →
    </a>
  </div>
</div></body></html>"""


# ── SMTP SENDER ───────────────────────────────────────────────
def send_email(to_email, subject, html_body, from_name=None):
    """Send HTML email via SMTP."""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = formataddr((from_name or SMTP_FROM_NAME, SMTP_USER))
        msg['To']      = to_email
        msg['X-Priority'] = '1'
        msg['X-Security-Notification'] = 'true'
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        log.info(f"Email sent to {to_email}: {subject[:50]}")
        return True
    except Exception as e:
        log.error(f"SMTP error to {to_email}: {e}")
        return False


# ── WEBHOOK / SLACK / TEAMS ───────────────────────────────────
def send_webhook(url, event, customer):
    """Send JSON webhook notification."""
    try:
        payload = {
            "event_id":       event.get('id'),
            "customer":       customer.get('name'),
            "platform":       event.get('platform'),
            "threat_type":    event.get('threat_category'),
            "threat_score":   event.get('threat_score'),
            "action":         event.get('event_type'),
            "mail_from":      event.get('mail_from'),
            "mail_to":        event.get('mail_to'),
            "subject":        event.get('subject'),
            "timestamp":      str(event.get('event_datetime','')),
            "dashboard_url":  DASHBOARD_URL,
        }
        r = requests.post(url, json=payload, timeout=10)
        return r.status_code < 400
    except Exception as e:
        log.error(f"Webhook error {url}: {e}")
        return False


def send_slack(webhook_url, event, customer):
    """Send Slack notification."""
    threat_type  = event.get('threat_category','threat').upper()
    threat_emojis= {'PHISHING':'🎣','MALWARE':'🦠','SPAM':'📧',
                    'BEC':'💼','URL_THREAT':'🔗','SCAM':'💰'}
    emoji = threat_emojis.get(threat_type, '🚨')
    try:
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type":"plain_text",
                             "text":f"{emoji} {threat_type} Detected — {customer.get('name','')}"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type":"mrkdwn","text":f"*From:*\n{event.get('mail_from','—')}"},
                        {"type":"mrkdwn","text":f"*To:*\n{event.get('mail_to','—')}"},
                        {"type":"mrkdwn","text":f"*Subject:*\n{event.get('subject','—')}"},
                        {"type":"mrkdwn","text":f"*Action:*\n{event.get('event_type','blocked').upper()}"},
                        {"type":"mrkdwn","text":f"*Platform:*\n{event.get('platform','—')}"},
                        {"type":"mrkdwn","text":f"*Score:*\n{event.get('threat_score','—')}"},
                    ]
                },
                {
                    "type": "actions",
                    "elements": [{
                        "type": "button",
                        "text": {"type":"plain_text","text":"View Dashboard"},
                        "url":  DASHBOARD_URL,
                        "style":"primary",
                    }]
                }
            ]
        }
        r = requests.post(webhook_url, json=payload, timeout=10)
        return r.status_code < 400
    except Exception as e:
        log.error(f"Slack error: {e}")
        return False


def send_teams(webhook_url, event, customer):
    """Send Microsoft Teams notification."""
    threat_type = event.get('threat_category','threat').upper()
    try:
        payload = {
            "@type":      "MessageCard",
            "@context":   "http://schema.org/extensions",
            "themeColor": "DC2626",
            "summary":    f"{threat_type} threat detected for {customer.get('name','')}",
            "sections":   [{
                "activityTitle": f"🚨 {threat_type} Detected",
                "activitySubtitle": f"Customer: {customer.get('name','')} | "
                                    f"Platform: {event.get('platform','')}",
                "facts": [
                    {"name":"From",     "value":event.get('mail_from','—')},
                    {"name":"To",       "value":event.get('mail_to','—')},
                    {"name":"Subject",  "value":event.get('subject','—')},
                    {"name":"Action",   "value":event.get('event_type','blocked').upper()},
                    {"name":"Score",    "value":str(event.get('threat_score','—'))},
                ],
                "markdown": True,
            }],
            "potentialAction": [{
                "@type": "OpenUri",
                "name":  "View in Dashboard",
                "targets": [{"os":"default","uri":DASHBOARD_URL}]
            }]
        }
        r = requests.post(webhook_url, json=payload, timeout=10)
        return r.status_code < 400
    except Exception as e:
        log.error(f"Teams error: {e}")
        return False


# ── LOG NOTIFICATION ─────────────────────────────────────────
def log_notification(event_id, customer_id, notif_type,
                     recipient, subject, status, error=None):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO notification_log
              (event_id, customer_id, notification_type,
               recipient_email, subject, status, error_message)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (event_id, customer_id, notif_type,
              recipient, subject, status, error))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        log.error(f"Log notification error: {e}")


def mark_event_notified(event_id):
    try:
        conn = get_conn()
        cur  = conn.cursor()
        cur.execute(
            "UPDATE security_events SET notification_sent=1 WHERE id=%s",
            (event_id,)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        log.error(f"Mark notified error: {e}")


# ── MAIN NOTIFICATION LOOP ────────────────────────────────────
def process_notifications():
    """Find unnotified threat events and send notifications."""
    conn = get_conn()
    cur  = conn.cursor(dictionary=True)

    # Get unnotified threat events with customer + notification settings
    cur.execute("""
        SELECT
          se.*,
          c.name          AS customer_name,
          c.domain        AS customer_domain,
          ns.notify_admin,
          ns.notify_end_user,
          ns.notify_ops_team,
          ns.admin_emails,
          ns.webhook_url,
          ns.slack_webhook,
          ns.teams_webhook,
          ns.min_confidence,
          ns.rate_limit_hour,
          ns.notify_blocked,
          ns.notify_spam,
          ns.email_template
        FROM security_events se
        JOIN customers c ON c.id = se.customer_id
        LEFT JOIN notification_settings ns ON ns.customer_id = se.customer_id
        WHERE se.notification_sent = 0
          AND se.threat_category IS NOT NULL
          AND se.event_datetime >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ORDER BY se.event_datetime DESC
        LIMIT 50
    """)
    events = cur.fetchall()
    cur.close()
    conn.close()

    if not events:
        return 0

    log.info(f"Processing {len(events)} unnotified events...")
    notified = 0

    for event in events:
        customer_id  = event['customer_id']
        event_id     = event['id']
        threat_type  = event.get('threat_category','').lower()
        min_conf     = event.get('min_confidence') or NOTIFY_MIN_CONFIDENCE
        rate_limit   = event.get('rate_limit_hour') or RATE_LIMIT_PER_HOUR

        # Skip if below confidence threshold
        score = event.get('threat_score') or 0
        if score and int(score) < min_conf:
            mark_event_notified(event_id)
            continue

        # Check rate limit
        if not check_rate_limit(customer_id, rate_limit):
            log.warning(f"Rate limit hit for customer {customer_id} — skipping")
            continue

        customer = {
            'name':        event.get('customer_name',''),
            'domain':      event.get('customer_domain',''),
            'admin_email': None,
        }

        # Parse admin emails
        admin_emails = []
        raw_admins   = event.get('admin_emails')
        if raw_admins:
            try:
                admin_emails = json.loads(raw_admins) \
                    if isinstance(raw_admins, str) else (raw_admins or [])
            except Exception:
                if isinstance(raw_admins, str) and '@' in raw_admins:
                    admin_emails = [raw_admins]

        if admin_emails:
            customer['admin_email'] = admin_emails[0]

        event_notified = False

        # ── 1. Admin notification ──────────────────────────────
        if event.get('notify_admin', 1) and admin_emails:
            subject = (
                f"🚨 [{threat_type.upper()}] Security Threat Detected"
                f" — {customer['name']} — "
                f"{str(event.get('event_datetime',''))[:10]}"
            )
            html = build_admin_email_html(event, customer)

            for admin_email in admin_emails[:5]:  # max 5 admins
                ok = send_email(admin_email, subject, html,
                                from_name="Worktual Security Alert")
                log_notification(event_id, customer_id, 'admin',
                                 admin_email, subject,
                                 'sent' if ok else 'failed')
                if ok:
                    event_notified = True

        # ── 2. End user notification ───────────────────────────
        mail_to = event.get('mail_to','')
        if event.get('notify_end_user', 1) and mail_to and '@' in str(mail_to):
            # Only notify for blocked emails, not delivered
            if event.get('event_type','') in ('blocked','quarantined','rejected'):
                user_subject = (
                    f"[Security Alert] An email was blocked for your protection"
                    f" — {str(event.get('event_datetime',''))[:10]}"
                )
                user_html = build_user_email_html(event, customer)
                # Handle multiple recipients
                recipients = [r.strip() for r in str(mail_to).split(',')
                              if '@' in r][:3]  # max 3
                for recipient in recipients:
                    ok = send_email(recipient, user_subject, user_html,
                                    from_name=f"{customer['name']} Security")
                    log_notification(event_id, customer_id, 'end_user',
                                     recipient, user_subject,
                                     'sent' if ok else 'failed')
                    if ok:
                        event_notified = True

        # ── 3. Virus Rescuers Ops Team ─────────────────────────
        if event.get('notify_ops_team', 0) and VR_OPS_EMAIL:
            ops_subject = (
                f"[VR-OPS] {threat_type.upper()} | "
                f"{customer['name']} | "
                f"{event.get('mail_from','')[:30]}"
            )
            ops_html = build_ops_email_html(event, customer)
            ok = send_email(VR_OPS_EMAIL, ops_subject, ops_html,
                            from_name="VR Security Engine")
            log_notification(event_id, customer_id, 'ops_team',
                             VR_OPS_EMAIL, ops_subject,
                             'sent' if ok else 'failed')

        # ── 4. Webhook ─────────────────────────────────────────
        if event.get('webhook_url'):
            ok = send_webhook(event['webhook_url'], event, customer)
            log_notification(event_id, customer_id, 'webhook',
                             event['webhook_url'][:100], 'webhook',
                             'sent' if ok else 'failed')

        # ── 5. Slack ───────────────────────────────────────────
        if event.get('slack_webhook'):
            ok = send_slack(event['slack_webhook'], event, customer)
            log_notification(event_id, customer_id, 'slack',
                             'slack', 'slack_notification',
                             'sent' if ok else 'failed')

        # ── 6. Microsoft Teams ─────────────────────────────────
        if event.get('teams_webhook'):
            ok = send_teams(event['teams_webhook'], event, customer)
            log_notification(event_id, customer_id, 'teams',
                             'teams', 'teams_notification',
                             'sent' if ok else 'failed')

        # Mark event as notified
        mark_event_notified(event_id)
        if event_notified:
            notified += 1
            log.info(f"✅ Notified: [{threat_type}] {event.get('mail_from','')} "
                     f"→ {customer['name']}")

    return notified


# ── ENTRY POINT ───────────────────────────────────────────────
if __name__ == "__main__":
    log.info("=" * 60)
    log.info("Worktual / Virus Rescuers Notification Engine")
    log.info(f"SMTP: {SMTP_HOST}:{SMTP_PORT} user={SMTP_USER}")
    log.info(f"VR Ops: {VR_OPS_EMAIL or 'disabled'}")
    log.info(f"Poll: {POLL_INTERVAL}s | Min confidence: {NOTIFY_MIN_CONFIDENCE}%")
    log.info(f"Rate limit: {RATE_LIMIT_PER_HOUR}/customer/hour")
    log.info("=" * 60)

    ensure_schema()

    while True:
        try:
            n = process_notifications()
            if n > 0:
                log.info(f"Cycle complete — {n} notifications sent")
        except KeyboardInterrupt:
            log.info("Stopped")
            break
        except Exception as e:
            log.error(f"Loop error: {e}")

        time.sleep(POLL_INTERVAL)
