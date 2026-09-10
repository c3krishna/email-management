#!/usr/bin/env python3
"""
============================================================
Worktual Sender Behavioral Baseline
File: /opt/virus-rescuers/detection/sender_behavior.py

Builds a rolling profile per sender:
  - Typical sending hours (histogram by hour-of-day)
  - Typical recipient set (who they usually email)
  - Average email length / writing style fingerprint
  - Typical sending volume (emails/day baseline)

Flags deviations that suggest a COMPROMISED account:
  - Sending at wildly unusual hours vs. their own history
  - Suddenly emailing recipients they've never contacted
  - Sudden volume spike (mass-mail behavior after takeover)
  - Dramatic writing-style shift (short generic phishing text
    vs. their normal detailed writing)

This is genuinely different from cross-customer correlation —
it catches a FIRST-TIME compromise before the same attacker
IOCs are seen anywhere else.
============================================================
"""

import os, re, math, logging, hashlib
import mysql.connector
from datetime import datetime

log = logging.getLogger("sender-behavior")

DB_HOST = os.getenv("DB_HOST", "10.180.0.84")
DB_USER = os.getenv("DB_USER", "mailmetrics")
DB_PASS = os.getenv("DB_PASSWORD", "WorktualMailMetrics@123")

MIN_HISTORY_FOR_BASELINE = 10  # need at least N prior emails before flagging anomalies


def get_conn():
    return mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASS,
        database='threat_platform', autocommit=True, connection_timeout=15)


def ensure_schema():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sender_behavior_profile (
      id                BIGINT       NOT NULL AUTO_INCREMENT,
      customer_id       INT          NOT NULL,
      sender            VARCHAR(255) NOT NULL,
      total_emails      INT          DEFAULT 0,
      hour_histogram    VARCHAR(200) DEFAULT NULL COMMENT '24 comma-separated counts, one per hour',
      known_recipients  MEDIUMTEXT   DEFAULT NULL COMMENT 'JSON array of recipient domains/addresses seen',
      avg_body_length   INT          DEFAULT 0,
      avg_word_count    INT          DEFAULT 0,
      last_7d_count     INT          DEFAULT 0,
      last_updated       DATETIME    DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      created_at        DATETIME     DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uq_sender (customer_id, sender)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sender_anomaly_alerts (
      id             BIGINT       NOT NULL AUTO_INCREMENT,
      customer_id    INT          NOT NULL,
      sender         VARCHAR(255) NOT NULL,
      anomaly_type   VARCHAR(50)  NOT NULL,
      reason         VARCHAR(500) NOT NULL,
      confidence     TINYINT      DEFAULT 65,
      subject        VARCHAR(500) DEFAULT NULL,
      detected_at    DATETIME     DEFAULT CURRENT_TIMESTAMP,
      reviewed       TINYINT(1)   DEFAULT 0,
      PRIMARY KEY (id),
      KEY idx_customer (customer_id, detected_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    conn.commit(); cur.close(); conn.close()
    log.info("sender_behavior_profile + sender_anomaly_alerts tables ready")


def _hist_to_list(hist_str):
    if not hist_str:
        return [0] * 24
    try:
        parts = [int(x) for x in hist_str.split(',')]
        return parts if len(parts) == 24 else [0] * 24
    except Exception:
        return [0] * 24


def _list_to_hist(hist_list):
    return ','.join(str(x) for x in hist_list)


def check_and_update(customer_id: int, sender: str, recipient: str, subject: str,
                       body: str, event_datetime: datetime = None) -> dict:
    """
    Main entry point. Call for every outbound-attributable email
    (or any email where 'sender' is one of the customer's own users).

    Returns anomaly assessment, then updates the sender's baseline
    with this new data point.
    """
    event_datetime = event_datetime or datetime.utcnow()
    result = {'anomaly_suspected': False, 'reasons': [], 'confidence': 0}

    if not sender:
        return result

    recipient_domain = recipient.split('@')[-1].lower() if recipient and '@' in recipient else None
    body_len = len(body or '')
    word_count = len((body or '').split())
    hour = event_datetime.hour

    try:
        conn = get_conn()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT * FROM sender_behavior_profile
            WHERE customer_id=%s AND sender=%s
        """, (customer_id, sender))
        profile = cur.fetchone()

        if profile and profile['total_emails'] >= MIN_HISTORY_FOR_BASELINE:
            hist = _hist_to_list(profile['hour_histogram'])
            total = sum(hist) or 1

            # ── Check 1: Unusual sending hour ──
            hour_freq = hist[hour] / total
            if hour_freq < 0.02 and total >= 30:  # this sender almost never sends at this hour
                result['anomaly_suspected'] = True
                result['reasons'].append(
                    f"Sender never sends at {hour}:00 based on {total} prior emails "
                    f"(only {hist[hour]} times, {hour_freq*100:.1f}%)"
                )
                result['confidence'] = max(result['confidence'], 55)

            # ── Check 2: Never-before-seen recipient domain ──
            import json
            try:
                known = json.loads(profile['known_recipients'] or '[]')
            except Exception:
                known = []
            if recipient_domain and recipient_domain not in known and len(known) >= 5:
                result['anomaly_suspected'] = True
                result['reasons'].append(
                    f"First-ever email to domain '{recipient_domain}' "
                    f"(sender has {len(known)} established recipient domains, none matching)"
                )
                result['confidence'] = max(result['confidence'], 50)

            # ── Check 3: Dramatic body-length deviation (short generic vs. normal) ──
            avg_len = profile['avg_body_length'] or 0
            if avg_len > 200 and body_len < avg_len * 0.15 and body_len < 150:
                result['anomaly_suspected'] = True
                result['reasons'].append(
                    f"Email unusually short ({body_len} chars) vs. sender's average "
                    f"({avg_len} chars) — common in mass-phishing sent from compromised accounts"
                )
                result['confidence'] = max(result['confidence'], 45)

            # ── Check 4: Sudden volume spike (last 7 days vs. historical average) ──
            days_active = max(1, (event_datetime - profile['created_at']).days) if profile.get('created_at') else 1
            historical_daily_avg = profile['total_emails'] / days_active
            if profile['last_7d_count'] > historical_daily_avg * 7 * 4 and profile['last_7d_count'] > 20:
                result['anomaly_suspected'] = True
                result['reasons'].append(
                    f"Volume spike: {profile['last_7d_count']} emails in last 7 days vs. "
                    f"historical average of {historical_daily_avg:.1f}/day — possible mass-mail abuse"
                )
                result['confidence'] = max(result['confidence'], 70)

        cur.close(); conn.close()

    except Exception as e:
        log.error(f"Behavior check error: {e}")

    # ── Save alert if anomaly detected ──
    if result['anomaly_suspected']:
        try:
            conn = get_conn(); cur = conn.cursor()
            cur.execute("""
                INSERT INTO sender_anomaly_alerts
                  (customer_id, sender, anomaly_type, reason, confidence, subject)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (customer_id, sender, 'behavioral_deviation',
                  ' | '.join(result['reasons']), result['confidence'], subject))
            conn.commit(); cur.close(); conn.close()
        except Exception as e:
            log.error(f"Anomaly alert save error: {e}")

    # ── Update the sender's rolling profile with this new data point ──
    _update_profile(customer_id, sender, recipient_domain, body_len, word_count, hour, event_datetime)

    return result


def _update_profile(customer_id, sender, recipient_domain, body_len, word_count, hour, event_datetime):
    import json
    try:
        conn = get_conn()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM sender_behavior_profile WHERE customer_id=%s AND sender=%s",
                    (customer_id, sender))
        profile = cur.fetchone()

        if not profile:
            hist = [0] * 24
            hist[hour] = 1
            known = [recipient_domain] if recipient_domain else []
            cur.execute("""
                INSERT INTO sender_behavior_profile
                  (customer_id, sender, total_emails, hour_histogram, known_recipients,
                   avg_body_length, avg_word_count, last_7d_count)
                VALUES (%s,%s,1,%s,%s,%s,%s,1)
            """, (customer_id, sender, _list_to_hist(hist), json.dumps(known), body_len, word_count))
        else:
            hist = _hist_to_list(profile['hour_histogram'])
            hist[hour] += 1
            try:
                known = json.loads(profile['known_recipients'] or '[]')
            except Exception:
                known = []
            if recipient_domain and recipient_domain not in known:
                known.append(recipient_domain)
                known = known[-100:]  # cap list size

            n = profile['total_emails']
            new_avg_len = int((profile['avg_body_length'] * n + body_len) / (n + 1))
            new_avg_words = int((profile['avg_word_count'] * n + word_count) / (n + 1))

            cur.execute("""
                UPDATE sender_behavior_profile
                SET total_emails=total_emails+1,
                    hour_histogram=%s,
                    known_recipients=%s,
                    avg_body_length=%s,
                    avg_word_count=%s,
                    last_7d_count=last_7d_count+1
                WHERE customer_id=%s AND sender=%s
            """, (_list_to_hist(hist), json.dumps(known), new_avg_len, new_avg_words,
                  customer_id, sender))

        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        log.error(f"Profile update error: {e}")


def decay_7day_counts():
    """Run daily via cron/scheduler — resets the rolling 7-day counter.
    Simple approach: halve it daily (approximate decay) rather than
    tracking exact per-day buckets, keeps the schema simple."""
    try:
        conn = get_conn(); cur = conn.cursor()
        cur.execute("UPDATE sender_behavior_profile SET last_7d_count = FLOOR(last_7d_count * 0.85)")
        conn.commit(); cur.close(); conn.close()
        log.info("7-day counts decayed")
    except Exception as e:
        log.error(f"Decay error: {e}")


if __name__ == "__main__":
    ensure_schema()
    print("Sender behavior schema ready")
