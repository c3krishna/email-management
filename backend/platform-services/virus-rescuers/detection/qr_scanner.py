#!/usr/bin/env python3
"""
============================================================
Worktual QR Code Phishing ("Quishing") Detector
File: /opt/virus-rescuers/detection/qr_scanner.py

Scans inline images and image attachments for QR codes,
decodes them, and runs the extracted URL through the same
threat pipeline used for regular email URLs (typosquat check,
domain resolution, pattern match).

Requires: pip3 install pyzbar pillow
System:   apt-get install libzbar0

Import into mailbox_monitor.py / validate.js pipeline.
============================================================
"""

import os, re, io, logging

log = logging.getLogger("qr-scanner")

try:
    from pyzbar.pyzbar import decode as zbar_decode
    from PIL import Image
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False
    log.warning("pyzbar/PIL not installed — QR scanning disabled. "
                "Install with: pip3 install pyzbar pillow && apt-get install libzbar0")

IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}

KNOWN_BRANDS = ['microsoft','google','paypal','amazon','apple','facebook',
                'netflix','office365','outlook','docusign','adobe']


def is_image_attachment(filename: str) -> bool:
    ext = os.path.splitext(filename.lower())[1]
    return ext in IMAGE_EXTENSIONS


def extract_qr_urls(image_data: bytes) -> list:
    """
    Decode any QR codes found in an image. Returns list of
    decoded payloads (usually URLs, sometimes plain text).
    """
    if not QR_AVAILABLE:
        return []

    try:
        img = Image.open(io.BytesIO(image_data))
        decoded = zbar_decode(img)
        results = []
        for d in decoded:
            try:
                payload = d.data.decode('utf-8', errors='replace')
                results.append(payload)
            except Exception:
                pass
        return results
    except Exception as e:
        log.debug(f"QR decode error: {e}")
        return []


def analyze_qr_payload(payload: str) -> dict:
    """
    Assess a decoded QR payload for phishing indicators —
    reuses the same typosquat/URL logic as the main pipeline.
    """
    findings = []
    risk = 0
    is_url = payload.strip().lower().startswith(('http://', 'https://'))

    if not is_url:
        return {
            'payload': payload[:200],
            'is_url': False,
            'risk_score': 5,
            'findings': ['QR contains non-URL text — low risk unless context suggests otherwise'],
            'is_malicious': False,
        }

    # Extract domain
    m = re.match(r'https?://([^/]+)', payload)
    domain = m.group(1).lower() if m else None

    if domain:
        # Typosquat check (reuse same logic pattern as validate.js)
        normalized = re.sub(r'[0-9]', lambda x: {'0':'o','1':'l','3':'e','5':'s','7':'t'}.get(x.group(),x.group()), domain)
        for brand in KNOWN_BRANDS:
            if brand in normalized and brand not in domain:
                findings.append(f"QR destination domain resembles '{brand}' — likely typosquat")
                risk += 60
                break
            if brand in domain and not domain.endswith(f'{brand}.com'):
                findings.append(f"QR destination contains '{brand}' but isn't the official domain")
                risk += 55
                break

        # Suspicious TLDs commonly used in QR phishing campaigns
        if re.search(r'\.(xyz|top|club|online|site|zip|shop)$', domain):
            findings.append(f"QR points to a commonly-abused TLD ({domain.split('.')[-1]})")
            risk += 25

        # URL shorteners hide the real destination — inherently suspicious in QR context
        if any(short in domain for short in ['bit.ly','tinyurl','t.co','goo.gl','ow.ly','is.gd']):
            findings.append("QR uses a URL shortener — destination is hidden from the recipient")
            risk += 30

        # Login/verify keywords in the URL path itself
        if re.search(r'(login|verify|account|secure|update|confirm)', payload, re.IGNORECASE):
            findings.append("URL path contains credential-harvesting keywords (login/verify/account)")
            risk += 20

    return {
        'payload': payload[:300],
        'is_url': True,
        'domain': domain,
        'risk_score': min(100, risk),
        'findings': findings,
        'is_malicious': risk >= 50,
    }


def scan_email_for_qr(attachments: list, inline_images: list = None) -> dict:
    """
    Main entry point. Pass a list of attachment dicts
    ({'filename': str, 'data': bytes}) plus optional inline
    images extracted from HTML body (cid: references).

    Returns a summary of all QR codes found and their risk.
    """
    if not QR_AVAILABLE:
        return {'scanned': False, 'reason': 'pyzbar not installed', 'qr_codes': []}

    all_images = list(attachments) + list(inline_images or [])
    qr_results = []

    for img in all_images:
        filename = img.get('filename', 'inline_image')
        if not is_image_attachment(filename) and 'data' not in img:
            continue
        data = img.get('data', b'')
        if not data:
            continue

        payloads = extract_qr_urls(data)
        for payload in payloads:
            analysis = analyze_qr_payload(payload)
            analysis['source_image'] = filename
            qr_results.append(analysis)

    malicious_count = sum(1 for r in qr_results if r['is_malicious'])

    return {
        'scanned': True,
        'images_checked': len(all_images),
        'qr_codes_found': len(qr_results),
        'malicious_qr_count': malicious_count,
        'qr_codes': qr_results,
        'has_threat': malicious_count > 0,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'rb') as f:
            data = f.read()
        payloads = extract_qr_urls(data)
        for p in payloads:
            print(f"Decoded: {p}")
            print(analyze_qr_payload(p))
    else:
        print(f"pyzbar available: {QR_AVAILABLE}")
