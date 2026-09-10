#!/usr/bin/env python3
"""
============================================================
Worktual Outbound DLP Scanner
File: /opt/virus-rescuers/detection/outbound_dlp.py

Scans OUTGOING mail (the "send" half of "send and receive")
for data leaks: credit cards, SSNs, credentials, API keys,
and compromised-account abuse patterns.

Completes bidirectional coverage for customers who need both
inbound threat protection AND outbound data-leak prevention.
============================================================
"""

import re, os, logging, requests

log = logging.getLogger("outbound-dlp")

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://miniai.worktual.tech:11434")
AI_MODEL   = os.getenv("AI_MODEL",   "qwen2.5:14b-instruct-q4_K_M")

DLP_PATTERNS = [
    (r'\b(?:\d[ -]*?){13,16}\b', 'credit_card', 70),
    (r'\b\d{3}-\d{2}-\d{4}\b', 'ssn', 85),
    (r'\b784-\d{4}-\d{7}-\d\b', 'emirates_id', 85),
    (r'\b(sk|pk|api|key)[-_][a-zA-Z0-9]{20,}\b', 'api_key', 80),
    (r'\bAKIA[0-9A-Z]{16}\b', 'aws_key', 95),
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*\S{4,}', 'plaintext_password', 75),
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', 'private_key', 98),
    (r'\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b', 'iban', 60),
    (r'(mongodb|mysql|postgres|postgresql)://[^\s]+:[^\s]+@', 'db_connection_string', 90),
]

ABUSE_INDICATORS = [
    (r'(?i)(click here|verify now|urgent action).{0,30}(account|password)', 'possible_account_compromise', 60),
    (r'(?i)bulk (email|mail|send)', 'possible_spam_relay_abuse', 50),
]


def luhn_check(number: str) -> bool:
    digits = [int(d) for d in re.sub(r'\D', '', number)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _redact(value: str, dtype: str) -> str:
    if dtype in ('credit_card', 'ssn', 'emirates_id', 'iban'):
        clean = re.sub(r'\D', '', value)
        return f"{'*' * max(0, len(clean)-4)}{clean[-4:]}" if len(clean) > 4 else "****"
    if dtype in ('api_key', 'aws_key', 'private_key', 'db_connection_string'):
        return f"{value[:6]}...{'*' * 10}"
    return "[REDACTED]"


def _ai_assess_leak(subject, body, detected_types):
    try:
        redacted_body = body
        for pattern, dtype, _ in DLP_PATTERNS:
            redacted_body = re.sub(pattern, f'[REDACTED-{dtype.upper()}]', redacted_body)
        prompt = (f"An outgoing email was flagged for potentially leaking: {', '.join(detected_types)}.\n"
                  f"Subject: {subject}\nRedacted body: {redacted_body[:600]}\n\n"
                  f"In one sentence, assess whether this looks like a legitimate business "
                  f"need or a genuine data leak risk.")
        r = requests.post(f"{OLLAMA_URL}/api/generate", json={
            "model": AI_MODEL, "prompt": prompt, "stream": False,
            "options": {"temperature": 0.1, "num_predict": 120}
        }, timeout=20)
        return r.json().get("response", "").strip()[:300]
    except Exception as e:
        log.warning(f"AI leak assessment error: {e}")
        return None


def scan_outbound_content(subject, body, recipient_domain=None, sender_domain=None):
    """Main entry point — scan an OUTGOING email for data leaks."""
    text = f"{subject or ''} {body or ''}"
    findings = []
    risk = 0
    detected_types = []

    for pattern, dtype, base_risk in DLP_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            if dtype == 'credit_card':
                valid_matches = [m for m in matches if luhn_check(m)]
                if not valid_matches:
                    continue
                matches = valid_matches
            findings.append({'type': dtype, 'count': len(matches), 'sample': _redact(matches[0], dtype)})
            risk = max(risk, base_risk)
            detected_types.append(dtype)

    is_external = (recipient_domain and sender_domain and
                   recipient_domain.lower() != sender_domain.lower())
    if findings and is_external:
        risk = min(100, risk + 15)
        findings.append({'type': 'external_recipient', 'count': 1,
                          'sample': f'Sent to external domain: {recipient_domain}'})

    for pattern, dtype, base_risk in ABUSE_INDICATORS:
        if re.search(pattern, text):
            findings.append({'type': dtype, 'count': 1, 'sample': None})
            risk = max(risk, base_risk)
            detected_types.append(dtype)

    is_leak = risk >= 60
    ai_summary = _ai_assess_leak(subject, body, detected_types) if (is_leak and body) else None

    return {
        'is_data_leak': is_leak,
        'risk_score': risk,
        'detected_types': detected_types,
        'findings': findings,
        'is_external_recipient': is_external,
        'ai_summary': ai_summary,
        'recommended_action': (
            'hold_for_review' if risk >= 80 else
            'flag_and_notify' if risk >= 60 else
            'log_only'
        ),
    }


if __name__ == "__main__":
    test_body = """
    Hi team, here's the customer record for verification:
    Card: 4532 0151 1283 0366
    SSN: 123-45-6789
    Please process the refund.
    """
    result = scan_outbound_content("Customer refund", test_body,
                                     recipient_domain="external-partner.com",
                                     sender_domain="customer.ae")
    import json
    print(json.dumps(result, indent=2))
