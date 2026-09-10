#!/usr/bin/env python3
"""
============================================================
Worktual Impersonation & Spear-Phishing Detector
File: /opt/virus-rescuers/detection/impersonation_detector.py

Closes the #1 gap in pure content-pattern detection: spear
phishing that impersonates a SPECIFIC known person (CEO, CFO,
IT admin) using a display name trick, with NO domain spoofing
and NO generic phishing keywords.

Two techniques:
  1. VIP display-name impersonation — customer registers their
     executives/key contacts once; any email claiming to be
     "John Smith (CEO)" from an address that ISN'T John's real
     address gets flagged immediately.
  2. Authority + urgency + isolation language — the specific
     combination spear-phishing uses regardless of who it
     impersonates.
============================================================
"""

import os, re, logging
import mysql.connector

log = logging.getLogger("impersonation-detector")

DB_HOST = os.getenv("DB_HOST", "10.180.0.84")
DB_USER = os.getenv("DB_USER", "mailmetrics")
DB_PASS = os.getenv("DB_PASSWORD", "WorktualMailMetrics@123")


def get_conn():
    return mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASS,
        database='threat_platform', autocommit=True, connection_timeout=15)


def ensure_schema():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vip_contacts (
      id             INT          NOT NULL AUTO_INCREMENT,
      customer_id    INT          NOT NULL,
      display_name   VARCHAR(200) NOT NULL,
      real_email     VARCHAR(255) NOT NULL,
      title          VARCHAR(100) DEFAULT NULL,
      active         TINYINT(1)   DEFAULT 1,
      created_at     DATETIME     DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_customer (customer_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS impersonation_alerts (
      id                BIGINT       NOT NULL AUTO_INCREMENT,
      customer_id       INT          NOT NULL,
      impersonated_name VARCHAR(200) DEFAULT NULL,
      real_email        VARCHAR(255) DEFAULT NULL,
      used_email        VARCHAR(255) NOT NULL,
      reason            VARCHAR(500) NOT NULL,
      confidence        TINYINT      DEFAULT 80,
      subject           VARCHAR(500) DEFAULT NULL,
      detected_at       DATETIME     DEFAULT CURRENT_TIMESTAMP,
      reviewed          TINYINT(1)   DEFAULT 0,
      PRIMARY KEY (id),
      KEY idx_customer (customer_id, detected_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    conn.commit(); cur.close(); conn.close()
    log.info("vip_contacts + impersonation_alerts tables ready")


AUTHORITY_URGENCY_PATTERNS = [
    (r'(?i)keep this (between us|confidential|discreet|private)', 'isolation', 30),
    (r"(?i)(don'?t|do not) (tell|mention|discuss) (this|it) (to anyone|with anyone)", 'isolation', 30),
    (r'(?i)(i\'?m|i am) (in a meeting|on a flight|traveling|unavailable).{0,40}(can\'?t talk|call me later|handle this)', 'authority_unavailable', 25),
    (r'(?i)(urgent|asap|right away|immediately).{0,30}(wire|transfer|payment|gift card|purchase)', 'urgency_payment', 35),
    (r'(?i)(need you to|can you).{0,20}(handle|process|complete) this (quickly|discreetly|quietly)', 'authority_pressure', 25),
    (r'(?i)(are you (at your desk|available)|do you have a (moment|minute))\??\s*$', 'authority_probe', 15),
]


def load_vip_contacts(customer_id: int) -> list:
    try:
        conn = get_conn()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT display_name, real_email, title FROM vip_contacts WHERE customer_id=%s AND active=1",
                    (customer_id,))
        rows = cur.fetchall()
        cur.close(); conn.close()
        return rows
    except Exception as e:
        log.error(f"Load VIP contacts error: {e}")
        return []


def check_impersonation(customer_id: int, mail_from_header: str, subject: str, body: str) -> dict:
    """
    Main entry point. mail_from_header should be the FULL From
    header, e.g. '"John Smith" <attacker@evil-domain.com>'.
    """
    result = {'impersonation_suspected': False, 'authority_language_detected': False,
               'reasons': [], 'confidence': 0}

    m = re.match(r'^\s*"?([^"<]*)"?\s*<([^>]+)>', mail_from_header or '')
    if m:
        display_name = m.group(1).strip()
        actual_email = m.group(2).strip().lower()
    else:
        display_name = ''
        actual_email = (mail_from_header or '').strip().lower()

    if display_name:
        vips = load_vip_contacts(customer_id)
        for vip in vips:
            vip_name_normalized = re.sub(r'\s*\([^)]*\)', '', vip['display_name']).strip().lower()
            display_normalized = display_name.lower()

            name_matches = (vip_name_normalized in display_normalized or
                            display_normalized in vip_name_normalized) and len(vip_name_normalized) > 3

            if name_matches and actual_email != vip['real_email'].lower():
                title_suffix = f", {vip['title']}" if vip.get('title') else ''
                reason = (f"Email claims to be '{display_name}' (matches registered contact "
                          f"'{vip['display_name']}'{title_suffix}) but was sent from "
                          f"'{actual_email}', not their real address '{vip['real_email']}'")
                result['impersonation_suspected'] = True
                result['reasons'].append(reason)
                result['confidence'] = max(result['confidence'], 90)

                try:
                    conn = get_conn(); cur = conn.cursor()
                    cur.execute("""
                        INSERT INTO impersonation_alerts
                          (customer_id, impersonated_name, real_email, used_email, reason, confidence, subject)
                        VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """, (customer_id, vip['display_name'], vip['real_email'], actual_email,
                          reason, result['confidence'], subject))
                    conn.commit(); cur.close(); conn.close()
                except Exception as e:
                    log.error(f"Impersonation alert save error: {e}")
                break

    text = f"{subject or ''} {body or ''}"
    matched_patterns = []
    for pattern, ptype, weight in AUTHORITY_URGENCY_PATTERNS:
        if re.search(pattern, text):
            matched_patterns.append(ptype)
            result['confidence'] = min(100, result['confidence'] + weight)

    if len(matched_patterns) >= 2:
        result['authority_language_detected'] = True
        result['reasons'].append(
            f"Multiple spear-phishing language patterns detected: {', '.join(set(matched_patterns))}"
        )

    return result


if __name__ == "__main__":
    ensure_schema()
    print("Impersonation detector schema ready")
