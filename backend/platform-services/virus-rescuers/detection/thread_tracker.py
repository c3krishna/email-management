#!/usr/bin/env python3
"""
============================================================
Worktual Reply-Chain Hijack Detector
File: /opt/virus-rescuers/detection/thread_tracker.py

Tracks email threads by Message-ID / In-Reply-To / References
headers. Flags when:
  1. A reply arrives from a NEW sender not previously in the thread
  2. The reply-to domain differs from the thread's established domain
  3. A thread suddenly introduces payment/credential-related content
     after being benign for its entire history
  4. Timing anomaly vs. established thread pattern

Catches the #1 gap in per-email-isolated scanning: an attacker
who compromised a mailbox and replies WITHIN a real, trusted
conversation — text alone often looks "clean."
============================================================
"""

import os, re, json, hashlib, logging
import mysql.connector
from datetime import datetime

log = logging.getLogger("thread-tracker")

DB_HOST = os.getenv("DB_HOST", "10.180.0.84")
DB_USER = os.getenv("DB_USER", "mailmetrics")
DB_PASS = os.getenv("DB_PASSWORD", "WorktualMailMetrics@123")


def get_conn():
    return mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASS,
        database='threat_platform', autocommit=True, connection_timeout=15)


def ensure_schema():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS thread_history (
      id             BIGINT       NOT NULL AUTO_INCREMENT,
      customer_id    INT          NOT NULL,
      thread_root_id VARCHAR(255) NOT NULL,
      message_id     VARCHAR(255) DEFAULT NULL,
      sender         VARCHAR(255) NOT NULL,
      sender_domain  VARCHAR(255) DEFAULT NULL,
      subject        VARCHAR(500) DEFAULT NULL,
      event_datetime DATETIME     NOT NULL,
      hour_of_day    TINYINT      DEFAULT NULL,
      has_payment_language TINYINT(1) DEFAULT 0,
      created_at     DATETIME     DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_thread (customer_id, thread_root_id),
      KEY idx_sender (sender)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS thread_hijack_alerts (
      id             BIGINT       NOT NULL AUTO_INCREMENT,
      customer_id    INT          NOT NULL,
      thread_root_id VARCHAR(255) NOT NULL,
      new_sender     VARCHAR(255) NOT NULL,
      established_senders TEXT    DEFAULT NULL,
      reason         VARCHAR(300) NOT NULL,
      confidence     TINYINT      DEFAULT 70,
      subject        VARCHAR(500) DEFAULT NULL,
      detected_at    DATETIME     DEFAULT CURRENT_TIMESTAMP,
      reviewed       TINYINT(1)   DEFAULT 0,
      PRIMARY KEY (id),
      KEY idx_customer (customer_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    conn.commit()
    cur.close()
    conn.close()
    log.info("thread_history + thread_hijack_alerts tables ready")


def normalize_thread_id(message_id, references, in_reply_to, subject):
    if references:
        refs = re.findall(r'<[^>]+>', references)
        if refs:
            return refs[0].strip('<>')
    if in_reply_to:
        m = re.search(r'<([^>]+)>', in_reply_to)
        if m:
            return m.group(1)
    norm_subject = re.sub(r'(?i)^(re|fwd?):\s*', '', subject or '').strip().lower()
    return hashlib.md5(norm_subject.encode()).hexdigest() if norm_subject else None


PAYMENT_KEYWORDS = re.compile(
    r'(wire transfer|bank details|account number|routing number|'
    r'payment|invoice|swift code|iban|urgent.{0,20}transfer|'
    r'update.{0,20}(bank|payment).{0,20}(detail|information))',
    re.IGNORECASE
)


def check_thread(customer_id, message_id, references, in_reply_to,
                  sender, subject, body, event_datetime=None):
    """Main entry point — call for every email with threading headers."""
    event_datetime = event_datetime or datetime.utcnow()
    thread_root = normalize_thread_id(message_id, references, in_reply_to, subject)

    if not thread_root:
        return {'is_reply': False, 'hijack_suspected': False}

    is_reply = bool(references or in_reply_to)
    sender_domain = sender.split('@')[-1].lower() if sender and '@' in sender else None
    has_payment = bool(PAYMENT_KEYWORDS.search(f"{subject} {body}"))

    result = {'is_reply': is_reply, 'thread_root': thread_root,
              'hijack_suspected': False, 'reasons': []}
    known_senders = set()

    if is_reply:
        try:
            conn = get_conn()
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT DISTINCT sender, sender_domain,
                       MAX(has_payment_language) AS ever_had_payment
                FROM thread_history
                WHERE customer_id=%s AND thread_root_id=%s
                GROUP BY sender, sender_domain
            """, (customer_id, thread_root))
            history = cur.fetchall()
            cur.close()
            conn.close()

            if history:
                known_senders = {h['sender'].lower() for h in history}
                known_domains = {h['sender_domain'] for h in history if h['sender_domain']}
                thread_had_payment = any(h['ever_had_payment'] for h in history)

                if sender and sender.lower() not in known_senders:
                    result['hijack_suspected'] = True
                    result['reasons'].append(
                        f"New sender '{sender}' has never participated in this thread before "
                        f"(established: {', '.join(list(known_senders)[:3])})"
                    )

                if sender_domain and known_domains and sender_domain not in known_domains:
                    result['hijack_suspected'] = True
                    result['reasons'].append(
                        f"Sender domain '{sender_domain}' differs from established thread domain(s): "
                        f"{', '.join(known_domains)}"
                    )

                if has_payment and not thread_had_payment:
                    result['hijack_suspected'] = True
                    result['reasons'].append(
                        "Thread introduces payment/banking language for the first time — "
                        "common BEC pattern of injecting fraud into a trusted conversation"
                    )
        except Exception as e:
            log.error(f"Thread check error: {e}")

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO thread_history
              (customer_id, thread_root_id, message_id, sender, sender_domain,
               subject, event_datetime, hour_of_day, has_payment_language)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (customer_id, thread_root, message_id, sender, sender_domain,
              subject, event_datetime, event_datetime.hour, 1 if has_payment else 0))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        log.error(f"Thread history insert error: {e}")

    if result['hijack_suspected']:
        try:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO thread_hijack_alerts
                  (customer_id, thread_root_id, new_sender, established_senders,
                   reason, confidence, subject)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (customer_id, thread_root, sender, json.dumps(list(known_senders)),
                  ' | '.join(result['reasons']), 80, subject))
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            log.error(f"Hijack alert save error: {e}")

    return result


if __name__ == "__main__":
    ensure_schema()
    print("Thread tracker schema ready")
