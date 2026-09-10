#!/usr/bin/env python3
"""
============================================================
Worktual Spam Content Milter — App (mail.worktual.tech)
Path: /var/www/email-management/agents-app/spam-milter
PM2:  spam-milter-app

How it works:
  1. Postfix passes EVERY email through this milter
  2. Milter reads: from, to, subject, full body
  3. Pattern scan (instant, no network)
  4. If suspicious → send to miniai Ollama for AI check
  5. Decision: ACCEPT / TAG as [SPAM] / REJECT
  6. Push detection to dashboard

Configure Postfix (/etc/postfix/main.cf):
  smtpd_milters = inet:127.0.0.1:8891
  non_smtpd_milters = inet:127.0.0.1:8891
  milter_default_action = accept
  milter_protocol = 6
============================================================
"""

import os, re, json, time, logging, socket, struct, threading
import requests, Milter
from email import message_from_bytes
from io import BytesIO
import mysql.connector

# ── CONFIG ──────────────────────────────────────────────────
MILTER_SOCKET = os.getenv("MILTER_SOCKET", "inet:8891@127.0.0.1")
OLLAMA_URL    = os.getenv("OLLAMA_URL",    "http://miniai.worktual.tech:11434")
AI_MODEL      = os.getenv("AI_MODEL",      "llama3.1:8b")
DB_HOST       = os.getenv("DB_HOST",       "10.180.0.84")
DB_USER       = os.getenv("DB_USER",       "mailmetrics")
DB_PASS       = os.getenv("DB_PASSWORD",   "WorktualMailMetrics@123")
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "https://email-management.worktual.tech")
AGENT_SECRET  = os.getenv("AGENT_SECRET",  "")
# REQUIRED per host: app (mail.worktual.tech) | campaign (mail.worktual.pl)
AGENT_SERVER  = os.getenv("AGENT_SERVER",  "app")

# Action thresholds (overridden from /api/policies/for-agent when available)
REJECT_THRESHOLD  = int(os.getenv("REJECT_THRESHOLD",  "95"))
TAG_THRESHOLD     = int(os.getenv("TAG_THRESHOLD",     "75"))
QUARANTINE_THRESHOLD = int(os.getenv("QUARANTINE_THRESHOLD", "85"))
AI_THRESHOLD      = int(os.getenv("AI_THRESHOLD",     "60"))

WHITELIST_DOMAINS = [
    'worktual.tech','worktual.pl','worktual.com',
    'google.com','microsoft.com','amazonaws.com',
    'mailchimp.com','sendgrid.net',
]

# ── LOGGING ─────────────────────────────────────────────────
os.makedirs("/var/log/spam-detector", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/var/log/spam-detector/milter.log"),
    ]
)
log = logging.getLogger("spam-milter")

# ── SPAM PATTERNS ────────────────────────────────────────────
PATTERNS = [
    # (regex, spam_type, confidence, check_body)
    # --- HIGH confidence phishing ---
    (r'(?i)(urgent|immediately).{0,30}(verify|confirm|update).{0,30}(account|password|login)',
     'phishing', 88, True),
    (r'(?i)(suspend|block|limit).{0,20}(account|access|card)',
     'phishing', 85, True),
    (r'(?i)(paypal|amazon|apple|microsoft|google).{0,30}(verify|confirm|suspended)',
     'phishing', 87, True),
    (r'(?i)click.{0,20}(here|below|link).{0,20}(verify|confirm|restore)',
     'phishing', 82, True),
    # --- Scam ---
    (r'(?i)(million|billion).{0,20}(dollar|usd|euro).{0,20}(transfer|beneficiar)',
     'scam', 92, True),
    (r'(?i)(lottery|winner|prize|won).{0,30}(claim|collect|contact)',
     'scam', 88, True),
    (r'(?i)(nigerian|prince|royal|inheritance).{0,30}(funds|transfer|million)',
     'scam', 95, False),  # no need for AI — very obvious
    (r'(?i)(investment|profit|return).{0,20}(guaranteed|100%|risk.free)',
     'scam', 80, True),
    # --- BEC ---
    (r'(?i)(wire|bank).{0,10}transfer.{0,30}(urgent|today|immediately)',
     'bec', 85, True),
    (r'(?i)(ceo|president|director|boss).{0,20}(requesting|asking|need)',
     'bec', 78, True),
    # --- Malware ---
    (r'(?i)(invoice|receipt|document|delivery).{0,10}(attached|enclosed|below)',
     'malware', 65, True),
    (r'(?i)\.(exe|js|vbs|bat|cmd|zip|rar).{0,10}(attached|download)',
     'malware', 88, False),
    # --- Spam ---
    (r'(?i)(buy|order|purchase).{0,20}(cheap|discount|sale).{0,20}(now|today|online)',
     'spam', 72, True),
    (r'(?i)(weight loss|diet pill|slim|fat burn).{0,20}(fast|quick|easy)',
     'spam', 78, False),
    (r'(?i)(pharmacy|medication|prescription).{0,20}(cheap|online|no prescription)',
     'spam', 82, False),
    (r'(?i)(adult|xxx|porn|sex|dating).{0,20}(meet|click|join|free)',
     'adult', 92, False),
    # --- Crypto ---
    (r'(?i)(bitcoin|ethereum|crypto).{0,20}(double|earn|profit|investment)',
     'crypto_scam', 85, True),
]

# ── AI CLASSIFICATION ────────────────────────────────────────
AI_PROMPT = """You are an email security analyst. Classify this email strictly.

FROM: {mail_from}
SUBJECT: {subject}
BODY:
{body}

Rules:
- Look for phishing, scam, malware, BEC, spam, or legitimate
- Be conservative — only flag if clearly malicious
- Transactional emails from known services are LEGITIMATE

Respond with JSON only:
{{"is_spam": true/false, "spam_type": "phishing/scam/malware/bec/spam/legitimate", "confidence": 0-100, "reason": "one sentence"}}"""

_ai_cache = {}  # simple dedup cache

def ai_classify(subject, mail_from, body):
    """Send to miniai Ollama for classification."""
    cache_key = hash(f"{subject}{mail_from}{body[:100]}")
    if cache_key in _ai_cache:
        return _ai_cache[cache_key]

    try:
        prompt = AI_PROMPT.format(
            mail_from = str(mail_from or '')[:100],
            subject   = str(subject   or '')[:300],
            body      = str(body      or '')[:800],
        )
        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model":   AI_MODEL,
                "prompt":  prompt,
                "stream":  False,
                "options": {"temperature": 0.05, "num_predict": 200},
            },
            timeout=20,
        )
        if r.status_code == 200:
            text = r.json().get("response", "")
            m    = re.search(r'\{[^}]+\}', text, re.DOTALL)
            if m:
                d = json.loads(m.group())
                result = {
                    "is_spam":   bool(d.get("is_spam", False)),
                    "spam_type": str(d.get("spam_type", "unknown")),
                    "confidence":min(100, max(0, int(d.get("confidence", 50)))),
                    "reason":    str(d.get("reason", ""))[:300],
                }
                _ai_cache[cache_key] = result
                return result
    except Exception as e:
        log.warning(f"AI error: {e}")
    return None

# ── PATTERN SCAN ─────────────────────────────────────────────
def scan_text(text, patterns=None):
    """Scan text against patterns, return best match."""
    if not text:
        return None, 0, None, False
    if patterns is None:
        patterns = PATTERNS
    best_type = None
    best_conf = 0
    best_pat  = None
    best_ai   = False
    for pattern, spam_type, confidence, use_ai in patterns:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            if confidence > best_conf:
                best_type = spam_type
                best_conf = confidence
                best_pat  = pattern
                best_ai   = use_ai
    return best_type, best_conf, best_pat, best_ai

# ── DB SAVE (async, non-blocking) ────────────────────────────
def save_detection_async(detection):
    def _save():
        try:
            conn = mysql.connector.connect(
                host=DB_HOST, user=DB_USER, password=DB_PASS,
                database='threat_platform', autocommit=True
            )
            conn.cursor().execute("""
                INSERT INTO spam_detections
                  (server, mail_from, mail_to, subject, body_snippet,
                   spam_type, confidence, detection_method,
                   ai_explanation, pattern_matched, action_taken, alert_sent)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0)
            """, (
                detection.get('server','app'),
                detection.get('mail_from'),
                detection.get('mail_to'),
                detection.get('subject'),
                str(detection.get('body',''))[:300] or None,
                detection.get('spam_type'),
                detection.get('confidence'),
                detection.get('method'),
                detection.get('reason'),
                detection.get('pattern'),
                detection.get('action','tagged'),
            ))
            conn.close()

            # Push to dashboard
            requests.post(
                f"{DASHBOARD_URL}/api/spam/notification",
                json=detection,
                headers={"X-Agent-Secret": AGENT_SECRET},
                timeout=3,
            )
        except Exception as e:
            log.error(f"Save async error: {e}")

    threading.Thread(target=_save, daemon=True).start()

# ── MILTER CLASS ─────────────────────────────────────────────
class SpamMilter(Milter.Base):

    def __init__(self):
        self.id       = Milter.uniqueID()
        self._from    = None
        self._to      = []
        self._headers = {}
        self._body    = BytesIO()
        self._subject = None

    @Milter.noreply
    def connect(self, IPname, family, hostaddr):
        self._ip = hostaddr[0] if hostaddr else ''
        return Milter.CONTINUE

    @Milter.noreply
    def envfrom(self, mailfrom, *rest):
        self._from = mailfrom.strip('<>').strip()
        return Milter.CONTINUE

    @Milter.noreply
    def envrcpt(self, to, *rest):
        self._to.append(to.strip('<>').strip())
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, name, value):
        self._headers[name.lower()] = value
        if name.lower() == 'subject':
            # Decode RFC2047
            try:
                import email.header as eh
                parts = eh.decode_header(value)
                decoded = []
                for part, charset in parts:
                    if isinstance(part, bytes):
                        decoded.append(part.decode(charset or 'utf-8', errors='replace'))
                    else:
                        decoded.append(str(part))
                self._subject = ' '.join(decoded).strip()
            except Exception:
                self._subject = value
        return Milter.CONTINUE

    @Milter.noreply
    def body(self, chunk):
        self._body.write(chunk)
        return Milter.CONTINUE

    def eom(self):
        """End of message — analyse and decide."""
        mail_from = self._from or ''
        subject   = self._subject or ''
        to_list   = ', '.join(self._to[:3])

        # Extract plain text body
        try:
            self._body.seek(0)
            msg  = message_from_bytes(self._body.read())
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    ct = part.get_content_type()
                    if ct == 'text/plain':
                        body = part.get_payload(decode=True).decode('utf-8', errors='replace')
                        break
                    elif ct == 'text/html' and not body:
                        raw = part.get_payload(decode=True).decode('utf-8', errors='replace')
                        body = re.sub(r'<[^>]+>', ' ', raw)
            else:
                body = msg.get_payload(decode=True).decode('utf-8', errors='replace') if isinstance(msg.get_payload(), bytes) else str(msg.get_payload())
        except Exception:
            body = ""

        body = body[:2000]

        # Skip whitelisted senders
        sender_domain = mail_from.split('@')[-1].lower() if '@' in mail_from else ''
        if any(w in sender_domain for w in WHITELIST_DOMAINS):
            return Milter.ACCEPT

        # ── Scan subject ──────────────────────────────────────
        s_type, s_conf, s_pat, s_ai = scan_text(subject)

        # ── Scan body ─────────────────────────────────────────
        b_type, b_conf, b_pat, b_ai = scan_text(body)

        # Use highest confidence detection
        spam_type  = None
        confidence = 0
        pattern    = None
        use_ai     = False
        method     = 'pattern'

        if s_conf >= b_conf and s_conf > 0:
            spam_type, confidence, pattern, use_ai = s_type, s_conf, s_pat, s_ai
        elif b_conf > 0:
            spam_type, confidence, pattern, use_ai = b_type, b_conf, b_pat, b_ai
            method = 'body_pattern'

        reason = None

        # ── AI check if pattern hit and threshold met ─────────
        if use_ai and confidence >= AI_THRESHOLD:
            ai = ai_classify(subject, mail_from, body)
            if ai:
                if ai['is_spam'] and ai['confidence'] > confidence:
                    spam_type  = ai['spam_type']
                    confidence = ai['confidence']
                    reason     = ai['reason']
                    method     = 'ai+pattern'
                    log.info(f"AI upgraded: {spam_type} {confidence}% — {reason[:60]}")
                elif not ai['is_spam'] and ai['confidence'] >= 70:
                    # AI cleared it
                    log.info(f"AI cleared [{mail_from}]: {ai['reason'][:60]}")
                    confidence = max(0, confidence - 25)

        # ── No pattern match — still check via AI if high spam score ──
        elif confidence == 0:
            # Check X-Spam-Score header
            spam_score_hdr = self._headers.get('x-spam-score', '') or \
                             self._headers.get('x-spam-status', '')
            if spam_score_hdr:
                score_match = re.search(r'[\d.]+', spam_score_hdr)
                if score_match and float(score_match.group()) >= 5:
                    ai = ai_classify(subject, mail_from, body)
                    if ai and ai['is_spam'] and ai['confidence'] >= 70:
                        spam_type  = ai['spam_type']
                        confidence = ai['confidence']
                        reason     = ai['reason']
                        method     = 'ai_only'

        # ── Decision ──────────────────────────────────────────
        if not spam_type or confidence < 65:
            return Milter.ACCEPT

        log.info(f"SPAM DETECTED [{confidence}%] {spam_type}: "
                 f"from={mail_from} subj={subject[:50]}")

        detection = {
            'server':    AGENT_SERVER,
            'mail_from': mail_from,
            'mail_to':   to_list,
            'subject':   subject,
            'body':      body[:300],
            'spam_type': spam_type,
            'confidence':confidence,
            'method':    method,
            'detection_method': method,
            'pattern':   str(pattern)[:200] if pattern else None,
            'pattern_matched': str(pattern)[:200] if pattern else None,
            'reason':    reason,
            'ai_explanation': reason,
        }

        # Save async (don't block mail flow)
        save_detection_async(detection)

        # ── Apply action based on confidence ──────────────────
        if confidence >= REJECT_THRESHOLD:
            log.info(f"  ACTION: REJECT ({confidence}% ≥ {REJECT_THRESHOLD}%)")
            self.setreply('550', '5.7.1',
                f'Message rejected: {spam_type} detected ({confidence}% confidence)')
            return Milter.REJECT

        if confidence >= QUARANTINE_THRESHOLD:
            log.info(f"  ACTION: QUARANTINE ({confidence}%)")
            # Add quarantine header
            self.addheader('X-Worktual-Spam',     f'YES; {spam_type}; confidence={confidence}%')
            self.addheader('X-Spam-Flag',          'YES')
            self.addheader('X-Spam-Status',        f'Yes, score={confidence}')
            self.addheader('X-Worktual-Action',    'QUARANTINE')
            # Modify subject
            if subject and '[SPAM]' not in subject:
                self.chgheader('Subject', 1, f'[SPAM-{spam_type.upper()}] {subject}')
            detection['action'] = 'quarantined'
            return Milter.ACCEPT

        if confidence >= TAG_THRESHOLD:
            log.info(f"  ACTION: TAG ({confidence}%)")
            self.addheader('X-Worktual-Spam',  f'YES; {spam_type}; confidence={confidence}%')
            self.addheader('X-Spam-Flag',       'YES')
            if subject and '[SPAM]' not in subject:
                self.chgheader('Subject', 1, f'[SPAM] {subject}')
            detection['action'] = 'tagged'
            return Milter.ACCEPT

        # Below tag threshold — just flag with header, don't modify
        self.addheader('X-Worktual-Spam-Check', f'{spam_type}; confidence={confidence}%')
        detection['action'] = 'flagged'
        return Milter.ACCEPT

# ── MAIN ─────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("=" * 60)
    log.info("Worktual Spam Content Milter starting")
    log.info(f"Socket:  {MILTER_SOCKET}")
    log.info(f"Ollama:  {OLLAMA_URL} model:{AI_MODEL}")
    log.info(f"Reject ≥ {REJECT_THRESHOLD}% | Quarantine ≥ {QUARANTINE_THRESHOLD}% | Tag ≥ {TAG_THRESHOLD}%")
    log.info("=" * 60)

    # Test Ollama connectivity
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        models = [m['name'] for m in r.json().get('models', [])]
        log.info(f"Ollama OK — models: {models}")
    except Exception as e:
        log.warning(f"Ollama not reachable: {e} — AI disabled, pattern-only mode")

    # Register and run milter
    Milter.factory = SpamMilter
    Milter.set_flags(Milter.CHGHDRS + Milter.ADDHDRS)
    Milter.runmilter("spammilter", MILTER_SOCKET, timeout=30)
    log.info("Milter stopped")

# ── DYNAMIC WHITELIST + POLICIES ─────────────────────────────
import threading as _threading
_whitelist_cache = {"domains": set(), "emails": set()}
_whitelist_lock  = _threading.Lock()

def refresh_policies_from_dashboard():
    global REJECT_THRESHOLD, TAG_THRESHOLD, QUARANTINE_THRESHOLD, AI_THRESHOLD
    if not AGENT_SECRET:
        return
    try:
        r = requests.get(
            f"{DASHBOARD_URL}/api/policies/for-agent",
            headers={"X-Agent-Secret": AGENT_SECRET, "X-Agent-Server": AGENT_SERVER},
            params={"server": AGENT_SERVER},
            timeout=8,
        )
        if not r.ok:
            return
        th = r.json().get("thresholds") or {}
        if th.get("reject") is not None:
            REJECT_THRESHOLD = int(float(th["reject"]))
        if th.get("tag") is not None:
            TAG_THRESHOLD = int(float(th["tag"]))
        if th.get("quarantine") is not None:
            QUARANTINE_THRESHOLD = int(float(th["quarantine"]))
        if th.get("ai") is not None:
            AI_THRESHOLD = int(float(th["ai"]))
        log.info(
            "Policies refreshed for %s: reject=%s tag=%s quarantine=%s ai=%s",
            AGENT_SERVER, REJECT_THRESHOLD, TAG_THRESHOLD, QUARANTINE_THRESHOLD, AI_THRESHOLD,
        )
    except Exception as e:
        log.warning("policy refresh failed: %s", e)

def load_whitelist():
    global _whitelist_cache
    domains = set(WHITELIST_DOMAINS)
    emails = set()
    if AGENT_SECRET:
        try:
            r = requests.get(
                f"{DASHBOARD_URL}/api/spam/whitelist/for-agent",
                headers={"X-Agent-Secret": AGENT_SECRET, "X-Agent-Server": AGENT_SERVER},
                params={"server": AGENT_SERVER},
                timeout=8,
            )
            if r.ok:
                for row in r.json().get("data", []):
                    val = str(row.get("value", "")).lower()
                    if row.get("type") == "email":
                        emails.add(val)
                    else:
                        domains.add(val)
        except Exception as e:
            log.warning("whitelist API refresh failed: %s", e)
    try:
        conn = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASS,
            database='threat_platform', connection_timeout=5
        )
        cur = conn.cursor()
        try:
            cur.execute(
                """SELECT type, value FROM spam_whitelist
                   WHERE active=1 AND type IN ('domain','email')
                     AND (mail_server=%s OR mail_server='both' OR mail_server IS NULL)""",
                (AGENT_SERVER,),
            )
        except Exception:
            cur.execute("SELECT 'domain', value FROM spam_whitelist WHERE active=1 AND type='domain'")
        for typ, val in cur.fetchall():
            if typ == "email":
                emails.add(str(val).lower())
            else:
                domains.add(str(val).lower())
        cur.close()
        conn.close()
    except Exception as e:
        log.warning(f"Whitelist DB load error: {e}")
    with _whitelist_lock:
        _whitelist_cache = {"domains": domains, "emails": emails}
    log.info("Whitelist loaded for %s: %d domains, %d emails", AGENT_SERVER, len(domains), len(emails))

def is_whitelisted(mail_from):
    if not mail_from or '@' not in mail_from:
        return False
    addr = mail_from.lower().strip().strip('>')
    domain = addr.split('@')[-1]
    with _whitelist_lock:
        cache = _whitelist_cache
        if isinstance(cache, set):
            return domain in cache or any(w in domain for w in WHITELIST_DOMAINS)
        if addr in cache.get("emails", set()):
            return True
        if domain in cache.get("domains", set()):
            return True
        if any(w in domain for w in WHITELIST_DOMAINS):
            return True
    return False

def _whitelist_refresher():
    while True:
        load_whitelist()
        refresh_policies_from_dashboard()
        time.sleep(300)

_wl_thread = _threading.Thread(target=_whitelist_refresher, daemon=True)
_wl_thread.start()
log.info("Spam milter configured for AGENT_SERVER=%s", AGENT_SERVER)
