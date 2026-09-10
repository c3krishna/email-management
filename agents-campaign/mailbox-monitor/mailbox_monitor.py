#!/usr/bin/env python3
"""
Worktual Mailbox Monitor Agent — Campaign
=========================================
Path: /var/www/email-management/agents-campaign/mailbox-monitor
PM2:  mailbox-monitor-campaign
SMTP defaults: mail.worktual.pl

  pm2 start ecosystem.config.cjs
"""

from __future__ import annotations

import email as email_lib
import hashlib
import imaplib
import json
import logging
import os
import re
import smtplib
import time
from datetime import datetime
from email.header import decode_header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

import mysql.connector
import requests

DB_HOST = os.getenv("DB_HOST", "10.180.0.84")
DB_USER = os.getenv("DB_USER", "mailmetrics")
DB_PASS = os.getenv("DB_PASSWORD", "WorktualMailMetrics@123")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://miniai.worktual.tech:11434")
AI_MODEL = os.getenv("AI_MODEL", "llama3.1:8b")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "120"))
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "https://email-management.worktual.tech")
AGENT_SECRET = os.getenv("AGENT_SECRET", "WorktualAgent@2026")
SMTP_HOST = os.getenv("SMTP_HOST", "mail.worktual.pl")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "security@worktual.pl")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Worktual Security Campaign")
NOTIFY_MIN_CONF = int(os.getenv("NOTIFY_MIN_CONFIDENCE", "60"))

os.makedirs("/var/log/mailbox-monitor", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/var/log/mailbox-monitor/monitor.log"),
    ],
)
log = logging.getLogger("mailbox-monitor")

PATTERNS = [
    (r"(urgent|immediately).{0,30}(verify|confirm|update).{0,30}(account|password|login)", "phishing", 88),
    (r"(suspend|block|limit).{0,20}(account|access|card)", "phishing", 85),
    (r"(paypal|amazon|apple|microsoft|google).{0,30}(verify|confirm|suspended)", "phishing", 87),
    (r"click.{0,20}(here|below|link).{0,20}(verify|confirm|restore)", "phishing", 82),
    (r"(million|billion).{0,20}(dollar|usd|euro).{0,20}(transfer|beneficiar)", "scam", 92),
    (r"(lottery|winner|prize|won).{0,30}(claim|collect|contact)", "scam", 88),
    (r"(wire|bank).{0,10}transfer.{0,30}(urgent|today|immediately)", "bec", 85),
    (r"(ceo|president|director|boss).{0,20}(requesting|asking|need|wire)", "bec", 78),
    (r"\.(exe|js|vbs|bat|cmd|scr)(\b|$)", "malware", 90),
    (r"(invoice|receipt|document|delivery).{0,10}(attached|enclosed|below)", "malware", 55),
    (r"(buy|order|purchase).{0,20}(cheap|discount|sale).{0,20}(now|today|online)", "spam", 72),
    (r"(bitcoin|ethereum|crypto).{0,20}(double|earn|profit|investment)", "crypto_scam", 85),
    (r"(unsubscribe|opt.?out).{0,40}(marketing|newsletter|promo)", "spam", 50),
    (r"(account.{0,10}locked|unusual.{0,10}activity|security.{0,10}alert)", "phishing", 80),
]


def get_conn(db="threat_platform"):
    return mysql.connector.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASS,
        database=db, autocommit=False, connection_timeout=30,
    )


def parse_email_list(raw):
    if not raw:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(e).strip() for e in raw if e and "@" in str(e)]
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return [str(e).strip() for e in data if e and "@" in str(e)]
        except Exception:
            pass
        return [e.strip() for e in re.split(r"[,;\s]+", raw) if "@" in e]
    return []


def decode_subject(raw):
    if not raw:
        return ""
    parts = []
    for chunk, enc in decode_header(raw):
        if isinstance(chunk, bytes):
            parts.append(chunk.decode(enc or "utf-8", errors="replace"))
        else:
            parts.append(str(chunk))
    return " ".join(parts)


def extract_body(msg):
    text_parts, html_parts = [], []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp.lower():
                continue
            try:
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace")
            except Exception:
                continue
            if ctype == "text/plain":
                text_parts.append(decoded)
            elif ctype == "text/html":
                html_parts.append(re.sub(r"<[^>]+>", " ", decoded))
    else:
        try:
            payload = msg.get_payload(decode=True) or b""
            charset = msg.get_content_charset() or "utf-8"
            text_parts.append(payload.decode(charset, errors="replace"))
        except Exception:
            pass
    return ("\n".join(text_parts) or "\n".join(html_parts))[:8000]


def scan_text(text):
    if not text:
        return None
    best = None
    for pattern, ttype, conf in PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            if not best or conf > best[1]:
                best = (ttype, conf)
    return best


def ai_classify(subject, mail_from, body):
    prompt = f"""You are an email security analyst. Classify conservatively.
FROM: {mail_from}
SUBJECT: {subject}
BODY: {(body or '')[:1000]}
Respond JSON only: {{"is_spam": true/false, "spam_type": "phishing/scam/malware/bec/spam/legitimate", "confidence": 0-100, "reason": "one sentence"}}"""
    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": AI_MODEL, "prompt": prompt, "stream": False,
                  "options": {"temperature": 0.05, "num_predict": 180}},
            timeout=25,
        )
        raw = r.json().get("response", "")
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            return None
        data = json.loads(m.group())
        return {
            "is_spam": bool(data.get("is_spam")),
            "spam_type": data.get("spam_type") or "spam",
            "confidence": int(data.get("confidence") or 0),
            "reason": data.get("reason") or "AI classification",
        }
    except Exception as e:
        log.debug("AI classify skipped: %s", e)
        return None


def resolve_notify_emails(monitor):
    emails = set(parse_email_list(monitor.get("notify_emails")))
    try:
        conn = get_conn()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT admin_emails, notify_admin, active, min_confidence "
            "FROM notification_settings WHERE customer_id=%s LIMIT 1",
            (monitor["customer_id"],),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row and row.get("active") and row.get("notify_admin", 1):
            for e in parse_email_list(row.get("admin_emails")):
                emails.add(e)
            return list(emails), int(row.get("min_confidence") or NOTIFY_MIN_CONF)
    except Exception as e:
        log.warning("notification_settings lookup failed: %s", e)
    return list(emails), NOTIFY_MIN_CONF


def send_alert_emails(recipients, monitor, mail_from, mail_to, subject, result):
    if not recipients or not SMTP_PASS:
        if recipients and not SMTP_PASS:
            log.warning("SMTP_PASS not set - cannot send alert emails")
        return 0
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;
                background:#f9fafb;border-radius:10px;overflow:hidden;border:1px solid #e5e7eb">
      <div style="background:#dc2626;padding:20px 24px">
        <h2 style="margin:0;color:#fff;font-size:18px">
          ?? {(result.get('threat_type') or 'THREAT').upper()} detected in mailbox
        </h2>
        <p style="margin:4px 0 0;color:rgba(255,255,255,0.85);font-size:12px">
          Mailbox: {monitor.get('imap_user')} - Confidence: {result.get('confidence')}%
        </p>
      </div>
      <div style="padding:20px 24px;font-size:13px">
        <p><b>From:</b> {mail_from}<br>
           <b>To:</b> {mail_to}<br>
           <b>Subject:</b> {subject}<br>
           <b>Reason:</b> {result.get('reason')}</p>
        <p style="font-size:12px;color:#6b7280">
          Open dashboard: <a href="{DASHBOARD_URL}">{DASHBOARD_URL}</a>
        </p>
      </div>
    </div>
    """
    sent = 0
    for to in recipients:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[Security Alert] {result.get('threat_type')} - {subject[:60]}"
            msg["From"] = formataddr((SMTP_FROM_NAME, SMTP_USER))
            msg["To"] = to
            msg.attach(MIMEText(html, "html"))
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as s:
                s.starttls()
                s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(SMTP_USER, [to], msg.as_string())
            sent += 1
            log.info("Alert emailed to %s", to)
        except Exception as e:
            log.error("Failed to notify %s: %s", to, e)
    return sent


def vip_detect(monitor, mail_from, mail_to, subject):
    """Notify dashboard VIP protection when From looks like a VIP spoof."""
    try:
        import urllib.request
        payload = json.dumps({
            "customer_id": monitor.get("customer_id"),
            "mail_from": mail_from,
            "mail_to": mail_to,
            "subject": subject,
            "mail_server": monitor.get("mail_server") or "app",
        }).encode()
        req = urllib.request.Request(
            f"{DASHBOARD_URL}/api/protection/detect",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Agent-Secret": os.getenv("AGENT_SECRET", "WorktualAgent@2026"),
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read().decode() or "{}")
    except Exception as e:
        log.debug("vip_detect: %s", e)
        return None


def process_email(monitor, mail_from, mail_to, subject, body):
    text = f"{subject}\n{mail_from}\n{body or ''}"
    pattern_match = scan_text(text)
    final_type, final_conf, method, reason = None, 0, "clean", "No indicators"

    if pattern_match:
        final_type, final_conf = pattern_match
        method = "pattern"
        reason = f"Pattern match ({final_type})"

    ai_result = ai_classify(subject, mail_from, body)
    if ai_result and ai_result.get("is_spam") and ai_result["confidence"] > final_conf:
        final_type = ai_result["spam_type"]
        final_conf = ai_result["confidence"]
        method = "ai" if method == "clean" else method + "+ai"
        reason = ai_result.get("reason") or reason

    # Always run VIP impersonation check (writes alerts when matched)
    vip_hit = vip_detect(monitor, mail_from, mail_to, subject)
    if vip_hit and vip_hit.get("matched"):
        if final_conf < 80:
            final_type = "vip_impersonation"
            final_conf = max(final_conf, 85)
            method = method + "+vip" if method != "clean" else "vip"
            reason = "VIP display-name impersonation"

    is_threat = final_conf >= NOTIFY_MIN_CONF
    result = {
        "is_threat": is_threat,
        "threat_type": final_type if is_threat else "legitimate",
        "confidence": final_conf,
        "method": method,
        "reason": reason,
    }

    sender_domain = mail_from.split("@")[-1].lower() if mail_from and "@" in mail_from else None
    try:
        conn = get_conn()
        cur = conn.cursor()
        dedup = hashlib.md5(f"{mail_from}{mail_to}{subject}{datetime.utcnow().date()}".encode()).hexdigest()
        cur.execute(
            """
            INSERT IGNORE INTO security_events
              (customer_id, platform, event_type, mail_from, mail_to, subject,
               event_datetime, threat_category, threat_score, sender_domain,
               ai_processed, ai_threat_type, ai_confidence, ai_explanation, dedup_hash)
            VALUES (%s,'mailbox_monitor',%s,%s,%s,%s,NOW(),%s,%s,%s,1,%s,%s,%s,%s)
            """,
            (
                monitor["customer_id"],
                "blocked" if is_threat else "delivered",
                mail_from, mail_to, subject,
                result["threat_type"] if is_threat else None,
                final_conf, sender_domain,
                result["threat_type"], final_conf, reason, dedup,
            ),
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        log.error("Save error: %s", e)

    if is_threat:
        recipients, min_conf = resolve_notify_emails(monitor)
        if final_conf >= min_conf and recipients:
            send_alert_emails(recipients, monitor, mail_from, mail_to, subject, result)
        try:
            requests.post(
                f"{DASHBOARD_URL}/api/spam/notification",
                json={
                    "server": "mailbox_monitor",
                    "customer_id": monitor["customer_id"],
                    "mail_from": mail_from,
                    "mail_to": mail_to,
                    "subject": subject,
                    "spam_type": result["threat_type"],
                    "confidence": final_conf,
                    "detection_method": method,
                    "ai_explanation": reason,
                    "notify_emails": recipients,
                },
                headers={"X-Agent-Secret": AGENT_SECRET},
                timeout=8,
            )
        except Exception:
            pass

    return result


def poll_mailbox(monitor):
    try:
        if monitor.get("use_ssl"):
            M = imaplib.IMAP4_SSL(monitor["imap_host"], int(monitor["imap_port"] or 993))
        else:
            M = imaplib.IMAP4(monitor["imap_host"], int(monitor["imap_port"] or 143))
        M.login(monitor["imap_user"], monitor["imap_pass"])
        M.select(monitor.get("folder") or "INBOX")

        if monitor.get("last_uid"):
            _, data = M.uid("search", None, f'UID {int(monitor["last_uid"])+1}:*')
        else:
            _, data = M.uid("search", None, "UNSEEN")

        uids = data[0].split() if data and data[0] else []
        uids = uids[-40:]
        if not uids:
            M.logout()
            return 0, 0

        scanned, threats = 0, 0
        max_uid = monitor.get("last_uid") or "0"

        for uid in uids:
            try:
                _, msg_data = M.uid("fetch", uid, "(RFC822)")
                if not msg_data or not msg_data[0]:
                    continue
                msg = email_lib.message_from_bytes(msg_data[0][1])
                subject = decode_subject(msg.get("Subject", ""))
                mail_from = msg.get("From", "")
                mail_to = msg.get("To", "")
                body = extract_body(msg)
                result = process_email(monitor, mail_from, mail_to, subject, body)
                scanned += 1
                if result and result["is_threat"]:
                    threats += 1
                    log.info(
                        "THREAT [%s%%] %s: %s - %s",
                        result["confidence"], result["threat_type"], mail_from, subject[:50],
                    )
                uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)
                if int(uid_str) > int(max_uid or 0):
                    max_uid = uid_str
            except Exception as e:
                log.error("Email process error uid=%s: %s", uid, e)

        M.logout()
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE mailbox_monitors
            SET last_uid=%s, last_checked=NOW(),
                total_scanned=total_scanned+%s, total_threats=total_threats+%s
            WHERE id=%s
            """,
            (max_uid, scanned, threats, monitor["id"]),
        )
        conn.commit()
        cur.close()
        conn.close()
        return scanned, threats
    except Exception as e:
        log.error("IMAP poll error for %s: %s", monitor.get("imap_user"), e)
        return 0, 0


def main_loop():
    log.info("=" * 60)
    log.info("Worktual Mailbox Monitor Agent")
    log.info("Poll interval: %ss | AI: %s", POLL_INTERVAL, AI_MODEL)
    log.info("=" * 60)
    while True:
        try:
            conn = get_conn()
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT * FROM mailbox_monitors WHERE active=1")
            monitors = cur.fetchall()
            cur.close()
            conn.close()
            if not monitors:
                log.info("No active mailbox monitors")
            for monitor in monitors:
                log.info("Polling %s (customer_id=%s)...", monitor["imap_user"], monitor["customer_id"])
                scanned, threats = poll_mailbox(monitor)
                if scanned:
                    log.info("  Scanned %s emails, %s threats", scanned, threats)
        except Exception as e:
            log.error("Main loop error: %s", e)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main_loop()
