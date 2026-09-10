#!/usr/bin/env python3
"""
============================================================
Worktual Mailchimp Pre-Send Validator
File: /opt/virus-rescuers/connectors/mailchimp_validator.py

DIFFERENT PATTERN from mailbox monitoring — Mailchimp has no
inbox to poll. Instead:

  1. Mailchimp webhook fires on 'campaign' events (or we poll
     the Campaigns API for status='save'/'schedule' before send)
  2. We fetch the campaign HTML/text content via API
  3. Run through outbound_dlp.py (PII/credential leak check)
     + AI content review (compromised-account phishing check)
  4. If risk detected: call Mailchimp API to PAUSE/cancel the
     scheduled send, notify admin immediately
  5. If clean: allow send to proceed (webhook returns 200 fast,
     or we simply don't block — Mailchimp doesn't support a
     true "hold for approval" gate via API, so for HIGH-risk
     items we cancel and require manual admin resend)

Setup required from customer:
  - Mailchimp API Key (Account → Extras → API keys)
  - Webhook URL registered in Mailchimp: Audience → Settings →
    Webhooks → pointing to our /api/connectors/webhook/mailchimp
============================================================
"""

import os, sys, json, requests, logging
_DET = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'detection')
if _DET not in sys.path:
    sys.path.insert(0, os.path.abspath(_DET))
import outbound_dlp

log = logging.getLogger("mailchimp-validator")

DASHBOARD_URL = os.getenv("DASHBOARD_URL", "https://email-management.worktual.tech")
AGENT_SECRET  = os.getenv("AGENT_SECRET",  "WorktualAgent@2026")


def get_mailchimp_datacenter(api_key: str) -> str:
    """Mailchimp API keys encode their datacenter as a suffix, e.g. xxxx-us21."""
    return api_key.split('-')[-1]


def fetch_campaign_content(api_key: str, campaign_id: str) -> dict:
    """Fetch the HTML/plain-text content of a Mailchimp campaign before it sends."""
    dc = get_mailchimp_datacenter(api_key)
    url = f"https://{dc}.api.mailchimp.com/3.0/campaigns/{campaign_id}/content"
    r = requests.get(url, auth=('anystring', api_key), timeout=15)
    r.raise_for_status()
    data = r.json()
    return {
        'html': data.get('html', ''),
        'plain_text': data.get('plain_text', ''),
    }


def fetch_campaign_meta(api_key: str, campaign_id: str) -> dict:
    dc = get_mailchimp_datacenter(api_key)
    url = f"https://{dc}.api.mailchimp.com/3.0/campaigns/{campaign_id}"
    r = requests.get(url, auth=('anystring', api_key), timeout=15)
    r.raise_for_status()
    data = r.json()
    return {
        'subject': data.get('settings', {}).get('subject_line', ''),
        'from_email': data.get('settings', {}).get('reply_to', ''),
        'status': data.get('status'),
        'recipient_count': data.get('recipients', {}).get('recipient_count', 0),
    }


def cancel_campaign_send(api_key: str, campaign_id: str) -> bool:
    """Pause/unschedule a Mailchimp campaign that failed validation."""
    dc = get_mailchimp_datacenter(api_key)
    url = f"https://{dc}.api.mailchimp.com/3.0/campaigns/{campaign_id}/actions/unschedule"
    try:
        r = requests.post(url, auth=('anystring', api_key), timeout=15)
        return r.status_code in (200, 204)
    except Exception as e:
        log.error(f"Cancel campaign error: {e}")
        return False


def validate_mailchimp_campaign(customer_id: int, api_key: str, campaign_id: str) -> dict:
    """
    Main entry point. Call this when a webhook fires (campaign
    created/updated) or when polling finds a campaign about to send.
    """
    meta = fetch_campaign_meta(api_key, campaign_id)
    content = fetch_campaign_content(api_key, campaign_id)

    body_text = content.get('plain_text') or content.get('html', '')
    # Strip HTML tags for cleaner scanning if only HTML available
    import re
    if not content.get('plain_text'):
        body_text = re.sub(r'<[^>]+>', ' ', body_text)

    dlp_result = outbound_dlp.scan_outbound_content(
        subject=meta['subject'],
        body=body_text,
        recipient_domain='mailchimp_subscriber_list',
        sender_domain=meta.get('from_email', '').split('@')[-1] if '@' in meta.get('from_email', '') else None,
    )

    result = {
        'campaign_id': campaign_id,
        'subject': meta['subject'],
        'recipient_count': meta['recipient_count'],
        'is_risk': dlp_result['is_data_leak'],
        'risk_score': dlp_result['risk_score'],
        'findings': dlp_result['findings'],
        'ai_summary': dlp_result['ai_summary'],
        'action_taken': None,
    }

    # High risk → cancel the send automatically
    if dlp_result['risk_score'] >= 80 and meta['status'] in ('scheduled', 'save'):
        cancelled = cancel_campaign_send(api_key, campaign_id)
        result['action_taken'] = 'send_cancelled' if cancelled else 'cancel_failed'
        log.warning(f"HIGH RISK campaign {campaign_id} — cancel {'succeeded' if cancelled else 'FAILED, manual action needed'}")
    elif dlp_result['risk_score'] >= 60:
        result['action_taken'] = 'flagged_for_review'
    else:
        result['action_taken'] = 'approved'

    # Notify + save regardless of outcome
    try:
        requests.post(f"{DASHBOARD_URL}/api/spam/notification", json={
            'server': 'mailchimp', 'mail_from': meta.get('from_email'),
            'mail_to': f"{meta['recipient_count']} subscribers",
            'subject': meta['subject'],
            'spam_type': 'data_leak' if dlp_result['is_data_leak'] else 'clean',
            'confidence': dlp_result['risk_score'],
            'detection_method': 'mailchimp_presend_dlp',
            'ai_explanation': dlp_result.get('ai_summary') or f"Campaign {result['action_taken']}",
        }, headers={'X-Agent-Secret': AGENT_SECRET}, timeout=5)
    except Exception:
        pass

    return result


if __name__ == "__main__":
    # Example usage
    import sys
    if len(sys.argv) >= 3:
        api_key, campaign_id = sys.argv[1], sys.argv[2]
        result = validate_mailchimp_campaign(1, api_key, campaign_id)
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python3 mailchimp_validator.py <api_key> <campaign_id>")
