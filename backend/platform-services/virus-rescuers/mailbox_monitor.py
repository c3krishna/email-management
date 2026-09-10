#!/usr/bin/env python3
"""
============================================================
Worktual Mailbox Monitor Agent
File: /opt/virus-rescuers/mailbox_monitor.py

Customer configures an email account (IMAP). This agent:
  1. Polls the mailbox every N minutes
  2. Fetches new emails since last checked UID
  3. Extracts full content: headers, body (text+html), attachments
  4. Decodes attachments, computes SHA256 hash
  5. Runs EVERY email through the full AI pipeline:
       - Pattern matching (14 rules)
       - Typosquat detection
       - Domain DNS check
       - AI classification (qwen2.5:14b-instruct-q4_K_M) on subject+body
       - Attachment hash reputation check
  6. Saves result to security_events
  7. Sends notification if threat detected

Deploy: Dashboard server (82.113.72.52)
PM2: pm2 start mailbox_monitor.py --interpreter python3 --name mailbox-monitor
============================================================
"""

import os, re, json, time, logging, hashlib, imaplib, email as email_lib
import sys
# detection modules next to this file (repo layout; also works under /opt via symlink)
_DET = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'detection')
if _DET not in sys.path:
    sys.path.insert(0, _DET)
import attachment_analyzer
import thread_tracker
import qr_scanner
import sender_behavior
import impersonation_detector
import outbound_dlp
import email.header, requests, mysql.connector
from datetime import datetime

DB_HOST       = os.getenv("DB_HOST",       "10.180.0.84")
DB_USER       = os.getenv("DB_USER",       "mailmetrics")
DB_PASS       = os.getenv("DB_PASSWORD",   "WorktualMailMetrics@123")
OLLAMA_URL    = os.getenv("OLLAMA_URL",    "http://miniai.worktual.tech:11434")
AI_MODEL      = os.getenv("AI_MODEL",      "qwen2.5:14b-instruct-q4_K_M")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "120"))
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "https://email-management.worktual.tech")
AGENT_SECRET  = os.getenv("AGENT_SECRET",  "WorktualAgent@2026")

os.makedirs("/var/log/mailbox-monitor", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(),
              logging.FileHandler("/var/log/mailbox-monitor/monitor.log")]
)
log = logging.getLogger("mailbox-monitor")

PATTERNS = [
    (r'(urgent|immediately).{0,30}(verify|confirm|update).{0,30}(account|password|login)', 'phishing', 88),
    (r'(suspend|block|limit).{0,20}(account|access|card)',                                  'phishing', 85),
    (r'(paypal|amazon|apple|microsoft|google).{0,30}(verify|confirm|suspended)',            'phishing', 87),
    (r'click.{0,20}(here|below|link).{0,20}(verify|confirm|restore)',                       'phishing', 82),
    (r'(million|billion).{0,20}(dollar|usd|euro).{0,20}(transfer|beneficiar)',               'scam',     92),
    (r'(lottery|winner|prize|won).{0,30}(claim|collect|contact)',                            'scam',     88),
    (r'(wire|bank).{0,10}transfer.{0,30}(urgent|today|immediately)',                         'bec',      85),
    (r'(ceo|president|director|boss).{0,20}(requesting|asking|need|wire)',                   'bec',      78),
    (r'\.(exe|js|vbs|bat|cmd|scr)(\b|$)',                                                    'malware',  90),
    (r'(invoice|receipt|document|delivery).{0,10}(attached|enclosed|below)',                 'malware',  55),
    (r'(buy|order|purchase).{0,20}(cheap|discount|sale).{0,20}(now|today|online)',            'spam',     72),
    (r'(bitcoin|ethereum|crypto).{0,20}(double|earn|profit|investment)',                      'crypto_scam', 85),
]
WHITELIST_DOMAINS = ['worktual.tech','worktual.pl','worktual.com','google.com','microsoft.com','amazonaws.com']
KNOWN_BRANDS = ['microsoft','google','paypal','amazon','apple','facebook','netflix','office365','outlook']

def scan_text(text):
    if not text: return None
    best = None
    for pattern, ttype, conf in PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            if not best or conf > best[1]: best = (ttype, conf)
    return best

def detect_typosquat(domain):
    if not domain: return None
    normalized = re.sub(r'[0-9]', lambda m: {'0':'o','1':'l','3':'e','5':'s','7':'t'}.get(m.group(),m.group()), domain)
    for brand in KNOWN_BRANDS:
        if brand in normalized and brand not in domain:
            return f'Domain resembles "{brand}" using character substitution'
        if brand in domain and not domain.endswith(f'{brand}.com'):
            return f'Contains "{brand}" but is not the official domain'
    return None

def ai_classify(subject, mail_from, body):
    prompt = f"""You are an email security analyst. Classify strictly and conservatively.
FROM: {mail_from}
SUBJECT: {subject}
BODY: {(body or '')[:1000]}
Respond JSON only: {{"is_spam": true/false, "spam_type": "phishing/scam/malware/bec/spam/legitimate", "confidence": 0-100, "reason": "one sentence"}}"""
    try:
        r = requests.post(f"{OLLAMA_URL}/api/generate", json={
            "model": AI_MODEL, "prompt": prompt, "stream": False,
            "options": {"temperature": 0.05, "num_predict": 180}
        }, timeout=25)
        m = re.search(r'\{[^}]+\}', r.json().get("response",""), re.DOTALL)
        if m:
            d = json.loads(m.group())
            return {"is_spam": bool(d.get("is_spam")), "spam_type": d.get("spam_type","unknown"),
                    "confidence": int(d.get("confidence",0)), "reason": str(d.get("reason",""))[:300]}
    except Exception as e:
        log.warning(f"AI classify error: {e}")
    return None

def get_conn():
    return mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASS,
        database='threat_platform', autocommit=True, connection_timeout=15)

def check_attachment_reputation(sha256_hash):
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM security_events WHERE attachment_hashes LIKE %s",
                    (f'%{sha256_hash}%',))
        count = cur.fetchone()[0]
        cur.close(); conn.close()
        return count > 0
    except Exception:
        return False

def ensure_schema():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS mailbox_monitors (
      id            INT          NOT NULL AUTO_INCREMENT,
      customer_id   INT          NOT NULL,
      display_name  VARCHAR(100) DEFAULT NULL,
      imap_host     VARCHAR(255) NOT NULL,
      imap_port     INT          DEFAULT 993,
      imap_user     VARCHAR(255) NOT NULL,
      imap_pass     VARCHAR(500) NOT NULL,
      folder        VARCHAR(100) DEFAULT 'INBOX',
      use_ssl       TINYINT(1)   DEFAULT 1,
      poll_interval INT          DEFAULT 120,
      last_uid      VARCHAR(50)  DEFAULT NULL,
      last_checked  DATETIME     DEFAULT NULL,
      total_scanned INT          DEFAULT 0,
      total_threats INT          DEFAULT 0,
      active        TINYINT(1)   DEFAULT 1,
      created_at    DATETIME     DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    conn.commit(); cur.close(); conn.close()
    log.info("mailbox_monitors table ready")

def decode_subject(raw):
    if not raw: return ""
    try:
        parts = email.header.decode_header(raw)
        return ' '.join(p.decode(c or 'utf-8', errors='replace') if isinstance(p, bytes) else p for p, c in parts)
    except Exception:
        return str(raw)

def extract_email_content(msg):
    # Capture threading headers for reply-chain analysis
    threading_headers = {
        'message_id':   msg.get('Message-ID', ''),
        'references':   msg.get('References', ''),
        'in_reply_to':  msg.get('In-Reply-To', ''),
    }
    body_text, body_html = "", ""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp  = str(part.get('Content-Disposition', ''))
            if 'attachment' in disp or part.get_filename():
                filename = part.get_filename() or 'unknown'
                payload  = part.get_payload(decode=True) or b''
                sha256   = hashlib.sha256(payload).hexdigest()
                attachments.append({'filename': filename, 'size': len(payload),
                                     'sha256': sha256, 'data': payload})
            elif ctype == 'text/plain' and not body_text:
                try: body_text = part.get_payload(decode=True).decode('utf-8', errors='replace')
                except Exception: pass
            elif ctype == 'text/html' and not body_html:
                try: body_html = part.get_payload(decode=True).decode('utf-8', errors='replace')
                except Exception: pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            body_text = payload.decode('utf-8', errors='replace') if payload else str(msg.get_payload())
        except Exception:
            body_text = str(msg.get_payload())

    body = body_text or re.sub(r'<[^>]+>', ' ', body_html)
    return body[:3000], attachments, threading_headers

def process_email(monitor, mail_from, mail_to, subject, body, attachments, threading_headers=None):
    sender_domain = mail_from.split('@')[-1].lower() if mail_from and '@' in mail_from else None
    if sender_domain and any(w in sender_domain for w in WHITELIST_DOMAINS):
        return None

    pattern_match = scan_text(f"{subject} {body}")
    typosquat = detect_typosquat(sender_domain)

    # ── NEW: Static attachment analysis (catches novel malware, no hash needed) ──
    attachment_findings = []
    for att in attachments:
        if 'data' in att and att['data']:
            analysis = attachment_analyzer.analyze_attachment(att['filename'], att['data'])
            attachment_findings.append(analysis)
            if analysis['is_malicious'] and analysis['risk_score'] > 60:
                log.info(f"  ATTACHMENT RISK [{analysis['risk_score']}]: {att['filename']} — {analysis['findings']}")

    # ── NEW: QR code / quishing scan ──
    qr_result = qr_scanner.scan_email_for_qr(attachments)
    if qr_result.get('has_threat'):
        log.info(f"  QR THREAT: {qr_result['malicious_qr_count']} malicious QR code(s) found")

    # ── NEW: Reply-chain hijack detection ──
    hijack_result = None
    if threading_headers and (threading_headers.get('references') or threading_headers.get('in_reply_to')):
        from datetime import datetime as _dt
        hijack_result = thread_tracker.check_thread(
            monitor['customer_id'],
            threading_headers.get('message_id'),
            threading_headers.get('references'),
            threading_headers.get('in_reply_to'),
            mail_from, subject, body, _dt.utcnow()
        )
        if hijack_result.get('hijack_suspected'):
            log.info(f"  THREAD HIJACK SUSPECTED: {hijack_result['reasons']}")


    final_type, final_conf, method = None, 0, 'clean'
    if pattern_match:
        final_type, final_conf, method = pattern_match[0], pattern_match[1], 'pattern'

    malicious_attachment = None
    for att in attachments:
        if check_attachment_reputation(att['sha256']):
            malicious_attachment = att
            final_type, final_conf, method = 'malware', 95, 'hash_match'
        elif re.search(r'\.(exe|scr|bat|cmd|js|vbs)$', att['filename'], re.IGNORECASE):
            if final_conf < 85:
                final_type, final_conf, method = 'malware', 85, 'attachment_type'

    ai_result = None
    if final_conf >= 50 or (not pattern_match and not attachments):
        ai_result = ai_classify(subject, mail_from, body)
        if ai_result and ai_result['is_spam'] and ai_result['confidence'] > final_conf:
            final_type, final_conf, method = ai_result['spam_type'], ai_result['confidence'], 'ai'

    # Fold in attachment analysis
    max_attachment_risk = max([a['risk_score'] for a in attachment_findings], default=0)
    if max_attachment_risk >= 60 and max_attachment_risk > final_conf:
        final_conf = max_attachment_risk
        final_type = 'malware'
        method = 'static_attachment_analysis'

    # Fold in QR threat
    if qr_result.get('has_threat') and final_conf < 80:
        final_conf = 80
        final_type = final_type or 'phishing'
        method += '+qr_phishing' if final_type else 'qr_phishing'

    # Fold in thread hijack
    if hijack_result and hijack_result.get('hijack_suspected') and final_conf < 75:
        final_conf = 75
        final_type = final_type or 'bec'
        method += '+thread_hijack' if method != 'clean' else 'thread_hijack'

    if typosquat and final_conf < 85:
        final_conf = 85
        final_type = final_type or 'phishing'
        method += '+typosquat'

    # ── NEW: Sender behavioral anomaly (account takeover detection) ──
    behavior_result = sender_behavior.check_and_update(
        monitor['customer_id'], mail_from, mail_to, subject, body
    )
    if behavior_result.get('anomaly_suspected') and final_conf < behavior_result['confidence']:
        final_conf = behavior_result['confidence']
        final_type = final_type or 'account_takeover'
        method = (method + '+behavioral_anomaly') if method != 'clean' else 'behavioral_anomaly'
        log.info(f"  BEHAVIORAL ANOMALY: {behavior_result['reasons']}")

    # ── NEW: VIP impersonation + spear-phishing language detection ──
    impersonation_result = impersonation_detector.check_impersonation(
        monitor['customer_id'], mail_from, subject, body
    )
    if impersonation_result.get('impersonation_suspected'):
        final_conf = max(final_conf, impersonation_result['confidence'])
        final_type = 'phishing'
        method = (method + '+vip_impersonation') if method != 'clean' else 'vip_impersonation'
        log.info(f"  VIP IMPERSONATION: {impersonation_result['reasons']}")
    elif impersonation_result.get('authority_language_detected') and final_conf < 65:
        final_conf = max(final_conf, 65)
        final_type = final_type or 'phishing'
        method = (method + '+spear_phishing_language') if method != 'clean' else 'spear_phishing_language'
        log.info(f"  SPEAR-PHISHING LANGUAGE: {impersonation_result['reasons']}")

    is_threat = final_conf >= 60
    result = {
        'is_threat': is_threat, 'threat_type': final_type if is_threat else 'legitimate',
        'confidence': final_conf, 'method': method,
        'reason': (ai_result['reason'] if ai_result else None) or typosquat or
                  (f"Malicious attachment: {malicious_attachment['filename']}" if malicious_attachment else None) or
                  ('Pattern match' if pattern_match else 'No indicators'),
        'attachments': attachments,
    }

    try:
        conn = get_conn(); cur = conn.cursor()
        dedup = hashlib.md5(f"{mail_from}{mail_to}{subject}{datetime.utcnow()}".encode()).hexdigest()
        cur.execute("""
            INSERT IGNORE INTO security_events
              (customer_id, platform, event_type, mail_from, mail_to, subject,
               event_datetime, threat_category, threat_score, sender_domain,
               attachment_hashes, ai_processed, ai_threat_type, ai_confidence, ai_explanation, dedup_hash)
            VALUES (%s,'mailbox_monitor',%s,%s,%s,%s,NOW(),%s,%s,%s,%s,1,%s,%s,%s,%s)
        """, (
            monitor['customer_id'], 'blocked' if is_threat else 'delivered',
            mail_from, mail_to, subject,
            result['threat_type'] if is_threat else None, final_conf, sender_domain,
            json.dumps([a['sha256'] for a in attachments]), result['threat_type'], final_conf,
            result['reason'], dedup,
        ))
        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        log.error(f"Save error: {e}")

    if is_threat:
        try:
            requests.post(f"{DASHBOARD_URL}/api/spam/notification", json={
                'server': 'mailbox_monitor', 'mail_from': mail_from, 'mail_to': mail_to,
                'subject': subject, 'spam_type': result['threat_type'],
                'confidence': final_conf, 'detection_method': method,
                'ai_explanation': result['reason'],
            }, headers={'X-Agent-Secret': os.getenv('AGENT_SECRET','WorktualAgent@2026')}, timeout=5)
        except Exception:
            pass

    return result

def poll_mailbox(monitor):
    try:
        M = imaplib.IMAP4_SSL(monitor['imap_host'], monitor['imap_port']) if monitor['use_ssl'] \
            else imaplib.IMAP4(monitor['imap_host'], monitor['imap_port'])
        M.login(monitor['imap_user'], monitor['imap_pass'])
        M.select(monitor['folder'])

        if monitor['last_uid']:
            _, data = M.uid('search', None, f'UID {int(monitor["last_uid"])+1}:*')
        else:
            _, data = M.uid('search', None, 'ALL')

        uids = data[0].split() if data and data[0] else []
        uids = uids[-50:]

        if not uids:
            M.logout()
            return 0, 0

        scanned, threats = 0, 0
        max_uid = monitor['last_uid'] or '0'

        for uid in uids:
            try:
                _, msg_data = M.uid('fetch', uid, '(RFC822)')
                if not msg_data or not msg_data[0]:
                    continue
                msg = email_lib.message_from_bytes(msg_data[0][1])

                subject = decode_subject(msg.get('Subject', ''))
                mail_from = msg.get('From', '')
                mail_to = msg.get('To', '')
                body, attachments, threading_headers = extract_email_content(msg)

                result = process_email(monitor, mail_from, mail_to, subject, body, attachments, threading_headers)
                scanned += 1
                if result and result['is_threat']:
                    threats += 1
                    log.info(f"  THREAT [{result['confidence']}%] {result['threat_type']}: {mail_from} - {subject[:50]}")

                uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)
                if int(uid_str) > int(max_uid):
                    max_uid = uid_str
            except Exception as e:
                log.error(f"  Email process error uid={uid}: {e}")

        M.logout()

        conn = get_conn(); cur = conn.cursor()
        cur.execute("""
            UPDATE mailbox_monitors
            SET last_uid=%s, last_checked=NOW(),
                total_scanned=total_scanned+%s, total_threats=total_threats+%s
            WHERE id=%s
        """, (max_uid, scanned, threats, monitor['id']))
        conn.commit(); cur.close(); conn.close()

        return scanned, threats
    except Exception as e:
        log.error(f"IMAP poll error for {monitor['imap_user']}: {e}")
        return 0, 0

def main_loop():
    while True:
        try:
            conn = get_conn(); cur = conn.cursor(dictionary=True)
            cur.execute("SELECT * FROM mailbox_monitors WHERE active=1")
            monitors = cur.fetchall()
            cur.close(); conn.close()

            if not monitors:
                log.info("No active mailbox monitors configured")
            for monitor in monitors:
                log.info(f"Polling {monitor['imap_user']} (customer_id={monitor['customer_id']})...")
                scanned, threats = poll_mailbox(monitor)
                if scanned:
                    log.info(f"  Scanned {scanned} emails, {threats} threats found")
        except Exception as e:
            log.error(f"Main loop error: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    log.info("=" * 60)
    log.info("Worktual Mailbox Monitor Agent")
    log.info(f"Poll interval: {POLL_INTERVAL}s | AI: {AI_MODEL}")
    log.info("=" * 60)
    ensure_schema()
    main_loop()
