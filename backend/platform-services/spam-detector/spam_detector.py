#!/usr/bin/env python3
"""
============================================================
Worktual Spam Content Detection Engine
File: /opt/spam-detector/spam_detector.py
Deploy: Dashboard server (82.113.72.52)
Method:
  1. Poll email_log_realtime for new inbound emails
  2. Extract subject + try to get body via IMAP
  3. Pattern match (instant) + AI classify (Ollama)
  4. If spam detected → save to spam_detections table
  5. Send email alert + dashboard notification
PM2: pm2 start /opt/spam-detector/spam_detector.py
       --interpreter python3 --name spam-detector
============================================================
"""

import os, re, json, time, logging, imaplib, email
import email.header, requests
from datetime import datetime
import mysql.connector

# ── CONFIG ───────────────────────────────────────────────────
DB_HOST     = os.getenv("DB_HOST",     "10.180.0.84")
DB_USER     = os.getenv("DB_USER",     "mailmetrics")
DB_PASS     = os.getenv("DB_PASSWORD", "WorktualMailMetrics@123")
OLLAMA_URL  = os.getenv("OLLAMA_URL",  "http://miniai.worktual.tech:11434")
AI_MODEL    = os.getenv("AI_MODEL",    "qwen2.5:14b-instruct-q4_K_M")
POLL_SEC    = int(os.getenv("POLL_INTERVAL", "60"))
IMAP_HOST   = os.getenv("IMAP_HOST",   "mail.worktual.tech")
IMAP_PORT   = int(os.getenv("IMAP_PORT", "993"))
IMAP_USER   = os.getenv("IMAP_USER",   "admin@worktual.tech")
IMAP_PASS   = os.getenv("IMAP_PASS",   "WorktualAdmin@Secure2026")
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "k.pethiah@worktual.com")
SMTP_HOST   = os.getenv("SMTP_HOST",   "mail.worktual.tech")
SMTP_PORT   = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER   = os.getenv("SMTP_USER",   "admin@worktual.tech")
SMTP_PASS   = os.getenv("SMTP_PASS",   "WorktualAdmin@Secure2026")
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "https://email-management.worktual.tech")
AGENT_SECRET  = os.getenv("AGENT_SECRET",  "WorktualAgent@2026")

# ── LOGGING ──────────────────────────────────────────────────
os.makedirs("/var/log/spam-detector", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/var/log/spam-detector/engine.log"),
    ]
)
log = logging.getLogger("spam-detector")

# ── SPAM PATTERNS ────────────────────────────────────────────
# Subject patterns (regex)
SUBJECT_PATTERNS = [
    # Financial scams
    (r'(?i)(urgent|action required).{0,20}(bank|account|payment)', 'phishing',  90),
    (r'(?i)you.{0,10}(won|winner|prize|lottery)',                  'scam',       85),
    (r'(?i)(bitcoin|crypto|investment).{0,20}(profit|return|earn)','scam',       80),
    (r'(?i)transfer.{0,20}(million|funds|inheritance)',             'scam',       85),
    (r'(?i)(verify|confirm|update).{0,20}(account|password|login)','phishing',   88),
    (r'(?i)your.{0,10}(account|card).{0,10}(suspended|blocked)',   'phishing',   87),
    (r'(?i)(free|gift|reward).{0,20}(claim|click|limited)',        'spam',        75),
    # BEC patterns
    (r'(?i)(ceo|director|manager).{0,20}(wire|transfer|payment)',  'bec',         82),
    (r'(?i)confidential.{0,20}(wire|transfer|urgent)',             'bec',         80),
    # Malware
    (r'(?i)(invoice|receipt|delivery).{0,10}#?\d+',               'malware',     60),
    (r'(?i)(doc|document|file).{0,10}(attached|enclosed)',         'malware',     55),
    # Adult/inappropriate
    (r'(?i)(adult|xxx|sex|dating).{0,20}(offer|meet|click)',       'adult',       92),
    # Phishing URLs
    (r'(?i)click.{0,20}(here|link|below).{0,20}(verify|confirm)', 'phishing',   83),
]

# Body keyword patterns
BODY_PATTERNS = [
    (r'(?i)dear.{0,20}(beneficiary|friend|sir)',                   'scam',       70),
    (r'(?i)(nigerian|prince|royal).{0,30}(transfer|funds)',        'scam',       90),
    (r'(?i)ssn|social security.{0,10}number',                      'phishing',   85),
    (r'(?i)credit card.{0,20}(number|cvv|expiry)',                 'phishing',   88),
    (r'(?i)(paypal|bank|amazon).{0,20}account.{0,20}suspended',    'phishing',   86),
    (r'(?i)unsubscribe.{0,100}click.{0,50}link',                   'spam',       65),
    (r'(?i)make money.{0,20}(fast|easy|home)',                     'scam',       78),
    (r'(?i)weight loss.{0,20}(pill|product|guarantee)',            'spam',       72),
    (r'(?i)pharmacy.{0,20}(cheap|discount|online)',                'spam',       75),
    (r'(?i)wire.{0,10}transfer.{0,30}(urgent|immediately)',        'bec',        80),
]

# Whitelist — never flag these senders
WHITELIST_DOMAINS = [
    'worktual.tech', 'worktual.pl', 'worktual.com',
    'google.com', 'microsoft.com', 'amazonaws.com',
]

# ── DB HELPERS ────────────────────────────────────────────────
def get_conn(database='worktual_email_campaign'):
    return mysql.connector.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASS,
        database=database, autocommit=False, connection_timeout=30
    )

def ensure_tables():
    """Create spam detection tables if not exist."""
    conn = get_conn('threat_platform')
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS spam_detections (
          id              BIGINT       NOT NULL AUTO_INCREMENT,
          log_id          BIGINT       DEFAULT NULL,
          server          VARCHAR(20)  DEFAULT 'app',
          detected_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
          mail_from       VARCHAR(255) DEFAULT NULL,
          mail_to         VARCHAR(255) DEFAULT NULL,
          subject         VARCHAR(500) DEFAULT NULL,
          body_snippet    TEXT         DEFAULT NULL,
          spam_type       VARCHAR(50)  DEFAULT 'spam',
          confidence      TINYINT      DEFAULT 50,
          detection_method VARCHAR(30) DEFAULT 'pattern',
          ai_explanation  TEXT         DEFAULT NULL,
          pattern_matched VARCHAR(200) DEFAULT NULL,
          action_taken    VARCHAR(50)  DEFAULT 'flagged',
          alert_sent      TINYINT(1)   DEFAULT 0,
          reviewed        TINYINT(1)   DEFAULT 0,
          false_positive  TINYINT(1)   DEFAULT 0,
          PRIMARY KEY (id),
          KEY idx_date     (detected_at),
          KEY idx_type     (spam_type),
          KEY idx_server   (server),
          KEY idx_reviewed (reviewed)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS spam_rules (
          id          INT          NOT NULL AUTO_INCREMENT,
          rule_name   VARCHAR(100) NOT NULL,
          rule_type   ENUM('subject','body','sender','header') DEFAULT 'subject',
          pattern     VARCHAR(500) NOT NULL,
          spam_type   VARCHAR(50)  DEFAULT 'spam',
          confidence  TINYINT      DEFAULT 70,
          active      TINYINT(1)   DEFAULT 1,
          hit_count   INT          DEFAULT 0,
          created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    conn.commit()
    cur.close()
    conn.close()
    log.info("Spam detection tables ready")

# ── PATTERN SCANNER ───────────────────────────────────────────
def scan_patterns(text, patterns):
    """Run regex patterns against text, return highest match."""
    if not text:
        return None, 0, None
    best_type = None
    best_conf = 0
    best_pat  = None
    for pattern, spam_type, confidence in patterns:
        if re.search(pattern, text):
            if confidence > best_conf:
                best_type = spam_type
                best_conf = confidence
                best_pat  = pattern
    return best_type, best_conf, best_pat

# ── AI CLASSIFIER ─────────────────────────────────────────────
SPAM_PROMPT = """You are an email security expert. Analyze this email and determine if it is spam/malicious.

Subject: {subject}
From: {mail_from}
Body snippet: {body}

Reply with JSON only:
{{"is_spam": true/false, "spam_type": "spam/phishing/malware/bec/scam/legitimate", "confidence": 0-100, "reason": "brief explanation"}}"""

def ai_classify(subject, mail_from, body=""):
    """Use Ollama to classify email content."""
    try:
        prompt = SPAM_PROMPT.format(
            subject   = str(subject or "")[:300],
            mail_from = str(mail_from or ""),
            body      = str(body or "")[:500],
        )
        r = requests.post(f"{OLLAMA_URL}/api/generate",
            json={"model": AI_MODEL, "prompt": prompt,
                  "stream": False, "options": {"temperature": 0.1, "num_predict": 150}},
            timeout=30)
        if r.status_code == 200:
            text = r.json().get("response", "")
            m    = re.search(r'\{[^}]+\}', text, re.DOTALL)
            if m:
                d = json.loads(m.group())
                return {
                    "is_spam":   bool(d.get("is_spam", False)),
                    "spam_type": str(d.get("spam_type", "unknown")),
                    "confidence":int(d.get("confidence", 50)),
                    "reason":    str(d.get("reason", ""))[:400],
                }
    except Exception as e:
        log.warning(f"AI classify error: {e}")
    return None

# ── IMAP BODY FETCH ───────────────────────────────────────────
def fetch_email_body(subject, mail_from):
    """Try to fetch email body from IMAP by subject match."""
    try:
        M = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
        M.login(IMAP_USER, IMAP_PASS)
        M.select('INBOX')

        # Search by subject
        subj_search = subject[:50].encode('utf-7').decode() if subject else ''
        _, msgs = M.search(None, f'SUBJECT "{subj_search}"')

        if msgs[0]:
            # Get most recent match
            msg_ids = msgs[0].split()[-3:]
            for mid in reversed(msg_ids):
                _, data = M.fetch(mid, '(RFC822)')
                if data and data[0]:
                    msg  = email.message_from_bytes(data[0][1])
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == 'text/plain':
                                try:
                                    body = part.get_payload(decode=True).decode('utf-8', errors='replace')
                                    break
                                except Exception:
                                    pass
                    else:
                        try:
                            body = msg.get_payload(decode=True).decode('utf-8', errors='replace')
                        except Exception:
                            pass
                    M.logout()
                    return body[:2000]

        M.logout()
    except Exception as e:
        log.debug(f"IMAP fetch error: {e}")
    return ""

# ── SEND ALERT EMAIL ──────────────────────────────────────────
def send_alert(detection):
    """Send email notification about detected spam."""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"🚨 [Spam Alert] {detection['spam_type'].upper()} detected — {detection['subject'][:60]}"
        msg['From']    = SMTP_USER
        msg['To']      = ALERT_EMAIL

        html = f"""
<html><body style="font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:20px">
<div style="max-width:600px;margin:0 auto;background:#1c2128;border:1px solid #30363d;border-radius:10px;overflow:hidden">
  <div style="background:{'#dc2626' if detection['spam_type'] in ('phishing','malware','bec') else '#d97706'};padding:16px 20px">
    <h2 style="margin:0;color:#fff">🚨 Spam Email Detected</h2>
    <p style="margin:4px 0 0;color:rgba(255,255,255,0.8);font-size:13px">
      {detection['spam_type'].upper()} · Confidence: {detection['confidence']}% · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} IST
    </p>
  </div>
  <div style="padding:20px">
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <tr><td style="color:#8b949e;padding:6px 0;width:120px">From:</td>
          <td style="color:#f87171;font-weight:bold">{detection['mail_from'] or '—'}</td></tr>
      <tr><td style="color:#8b949e;padding:6px 0">To:</td>
          <td>{detection['mail_to'] or '—'}</td></tr>
      <tr><td style="color:#8b949e;padding:6px 0">Subject:</td>
          <td style="color:#fbbf24;font-weight:bold">{detection['subject'] or '—'}</td></tr>
      <tr><td style="color:#8b949e;padding:6px 0">Server:</td>
          <td>{detection['server']}</td></tr>
      <tr><td style="color:#8b949e;padding:6px 0">Method:</td>
          <td>{detection['detection_method']}</td></tr>
      <tr><td style="color:#8b949e;padding:6px 0">Pattern:</td>
          <td style="font-family:monospace;font-size:11px;color:#60a5fa">{detection.get('pattern_matched','—')}</td></tr>
    </table>
    {f'<div style="background:#0d1117;border-radius:6px;padding:12px;margin-top:12px;font-size:12px;color:#8b949e"><strong style="color:#e6edf3">AI Analysis:</strong><br>{detection.get("ai_explanation","")}</div>' if detection.get("ai_explanation") else ''}
    {f'<div style="background:#0d1117;border-radius:6px;padding:12px;margin-top:10px;font-size:12px;color:#8b949e"><strong style="color:#e6edf3">Body snippet:</strong><br>{str(detection.get("body_snippet",""))[:300]}</div>' if detection.get("body_snippet") else ''}
    <div style="margin-top:16px;text-align:center">
      <a href="{DASHBOARD_URL}/#spamguard" style="background:#2563eb;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:600">
        View in Dashboard →
      </a>
    </div>
  </div>
  <div style="padding:12px 20px;border-top:1px solid #30363d;font-size:11px;color:#8b949e;text-align:center">
    Worktual Email Management Platform · Spam Detection Engine · {datetime.now().year}
  </div>
</div>
</body></html>"""

        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        log.info(f"Alert email sent to {ALERT_EMAIL}")
        return True
    except Exception as e:
        log.error(f"Alert email failed: {e}")
        return False

# ── SAVE DETECTION ────────────────────────────────────────────
def save_detection(detection):
    conn = get_conn('threat_platform')
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO spam_detections
          (log_id, server, mail_from, mail_to, subject, body_snippet,
           spam_type, confidence, detection_method, ai_explanation,
           pattern_matched, action_taken)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'flagged')
    """, (
        detection.get('log_id'),
        detection.get('server','app'),
        detection.get('mail_from'),
        detection.get('mail_to'),
        detection.get('subject'),
        str(detection.get('body_snippet',''))[:500] or None,
        detection.get('spam_type','spam'),
        detection.get('confidence',50),
        detection.get('detection_method','pattern'),
        detection.get('ai_explanation'),
        detection.get('pattern_matched'),
    ))
    detection_id = cur.lastrowid
    conn.commit()
    cur.close()
    conn.close()
    return detection_id

# ── PUSH DASHBOARD NOTIFICATION ───────────────────────────────
def push_dashboard_notification(detection):
    try:
        requests.post(
            f"{DASHBOARD_URL}/api/spam/notification",
            json=detection,
            headers={"X-Agent-Secret": AGENT_SECRET},
            timeout=5
        )
    except Exception:
        pass

# ── MAIN SCAN LOOP ────────────────────────────────────────────
def scan_for_spam():
    """Scan recent inbound emails for spam content."""
    conn = get_conn('worktual_email_campaign')
    cur  = conn.cursor(dictionary=True)

    # Get last processed ID
    fw_conn = get_conn('threat_platform')
    fw_cur  = fw_conn.cursor(dictionary=True)
    fw_cur.execute("SELECT COALESCE(MAX(log_id),0) AS last FROM spam_detections")
    last_id = int((fw_cur.fetchone() or {}).get('last', 0) or 0)
    fw_cur.close()
    fw_conn.close()

    # Fetch new inbound emails
    cur.execute("""
        SELECT id, server, log_datetime, mail_from, mail_to,
               subject, direction, status, reason, spam_score
        FROM email_log_realtime
        WHERE id > %s
          AND direction IN ('inbound','in','In')
          AND event_type IN ('delivery','amavis','queued','connection')
          AND mail_from IS NOT NULL
        ORDER BY id ASC
        LIMIT 50
    """, (last_id,))
    emails = cur.fetchall()
    cur.close()
    conn.close()

    if not emails:
        return 0

    log.info(f"Scanning {len(emails)} inbound emails...")
    detected = 0

    for ev in emails:
        mail_from = str(ev.get('mail_from') or '')
        subject   = str(ev.get('subject')   or '')
        server    = str(ev.get('server')    or 'app')

        # Skip whitelisted senders
        sender_domain = mail_from.split('@')[-1].lower() if '@' in mail_from else ''
        if any(w in sender_domain for w in WHITELIST_DOMAINS):
            continue

        # Skip if Amavis already scored as clean (score < -2)
        spam_score = float(ev.get('spam_score') or 0)
        if spam_score < -3:
            continue

        detection = {
            'log_id':           ev['id'],
            'server':           server,
            'mail_from':        mail_from,
            'mail_to':          str(ev.get('mail_to') or ''),
            'subject':          subject,
            'spam_type':        None,
            'confidence':       0,
            'detection_method': None,
            'pattern_matched':  None,
            'ai_explanation':   None,
            'body_snippet':     None,
        }

        # ── Step 1: Subject pattern scan ──────────────────────
        s_type, s_conf, s_pat = scan_patterns(subject, SUBJECT_PATTERNS)
        if s_type and s_conf >= 70:
            detection.update({
                'spam_type':        s_type,
                'confidence':       s_conf,
                'detection_method': 'subject_pattern',
                'pattern_matched':  s_pat,
            })
            log.info(f"  SUBJECT MATCH [{s_conf}%] {s_type}: {subject[:60]}")

        # ── Step 2: Fetch body from IMAP and scan ─────────────
        body = ""
        if subject:
            body = fetch_email_body(subject, mail_from)
            if body:
                detection['body_snippet'] = body[:300]
                b_type, b_conf, b_pat = scan_patterns(body, BODY_PATTERNS)
                if b_type and b_conf > (detection['confidence'] or 0):
                    detection.update({
                        'spam_type':        b_type,
                        'confidence':       b_conf,
                        'detection_method': 'body_pattern',
                        'pattern_matched':  b_pat,
                    })
                    log.info(f"  BODY MATCH [{b_conf}%] {b_type}")

        # ── Step 3: AI classification (if pattern found or high spam score) ──
        if detection['confidence'] >= 60 or spam_score >= 5:
            ai = ai_classify(subject, mail_from, body)
            if ai and ai['is_spam'] and ai['confidence'] >= 60:
                # AI confirms or upgrades confidence
                if ai['confidence'] >= detection.get('confidence', 0):
                    detection.update({
                        'spam_type':        ai['spam_type'],
                        'confidence':       ai['confidence'],
                        'detection_method': 'ai+' + (detection.get('detection_method') or 'scan'),
                        'ai_explanation':   ai['reason'],
                    })
                    log.info(f"  AI CONFIRM [{ai['confidence']}%] {ai['spam_type']}: {ai['reason'][:60]}")
            elif ai and not ai['is_spam'] and detection['confidence'] < 80:
                # AI says clean — lower confidence
                detection['confidence'] = max(0, detection['confidence'] - 20)
                log.info(f"  AI CLEARED: {ai['reason'][:60]}")

        # ── Step 4: Save + Alert if confident enough ──────────
        if detection['spam_type'] and detection['confidence'] >= 65:
            save_detection(detection)
            push_dashboard_notification(detection)
            if detection['confidence'] >= 75:
                sent = send_alert(detection)
                if sent:
                    # Mark alert_sent in DB
                    try:
                        ac = get_conn('threat_platform')
                        ac.cursor().execute(
                            "UPDATE spam_detections SET alert_sent=1 WHERE log_id=%s",
                            (ev['id'],)
                        )
                        ac.commit()
                        ac.close()
                    except Exception:
                        pass
            detected += 1
            log.info(f"  ✅ SPAM SAVED: {detection['spam_type']} ({detection['confidence']}%) from {mail_from}")

    if detected:
        log.info(f"Scan complete — {detected} spam emails detected out of {len(emails)} scanned")
    return detected

# ── ENTRY POINT ───────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    log.info("=" * 60)
    log.info("Worktual Spam Content Detection Engine")
    log.info(f"Ollama: {OLLAMA_URL} model:{AI_MODEL}")
    log.info(f"IMAP:   {IMAP_HOST}:{IMAP_PORT}")
    log.info(f"Alerts: {ALERT_EMAIL}")
    log.info(f"Poll:   {POLL_SEC}s")
    log.info("=" * 60)

    # Setup tables
    ensure_tables()

    # Test Ollama
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        models = [m['name'] for m in r.json().get('models', [])]
        log.info(f"Ollama OK — {len(models)} models available")
    except Exception as e:
        log.warning(f"Ollama not reachable: {e} — AI classification disabled")

    # Single run mode for testing
    if "--once" in sys.argv:
        n = scan_for_spam()
        log.info(f"Test run complete — {n} detections")
        sys.exit(0)

    # Continuous loop
    while True:
        try:
            scan_for_spam()
        except KeyboardInterrupt:
            log.info("Stopped")
            break
        except Exception as e:
            log.error(f"Loop error: {e}")
        log.info(f"Sleeping {POLL_SEC}s...")
        time.sleep(POLL_SEC)
