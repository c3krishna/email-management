#!/usr/bin/env python3
"""
============================================================
Worktual VirusTotal Sandbox Integration
File: /opt/virus-rescuers/detection/virustotal_check.py

Closes the Attachment Sandboxing (Zero-Day) gap WITHOUT building
a self-hosted VM detonation farm. VirusTotal already runs
submitted files through multiple real dynamic sandboxes
(behavioral analysis: network calls, process spawning, registry
changes, file drops) and aggregates verdicts from 70+ AV engines.

Two-tier approach:
  1. HASH LOOKUP (instant, free, no upload) — checks if this
     exact file has EVER been seen/analyzed before by anyone.
     Covers the vast majority of real-world attachments.
  2. FILE UPLOAD (for genuinely novel files with no hash match)
     — submits the file for fresh dynamic analysis. Free tier:
     4 requests/min, 500/day. Results available in ~1-3 minutes.

Requires: VT_API_KEY environment variable (free signup at
virustotal.com/gui/join-us)
============================================================
"""

import os, time, logging, requests

log = logging.getLogger("virustotal-check")

VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Free tier rate limiting — track last request time
_last_request_time = 0
_MIN_REQUEST_INTERVAL = 16  # ~4/min = 1 every 15s, add buffer


def _rate_limit():
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < _MIN_REQUEST_INTERVAL:
        time.sleep(_MIN_REQUEST_INTERVAL - elapsed)
    _last_request_time = time.time()


def is_configured() -> bool:
    return bool(VT_API_KEY)


def lookup_hash(sha256: str) -> dict:
    """
    Tier 1: Instant hash lookup — no rate limit concern, this is
    the primary path for the vast majority of attachments (most
    files, even legitimate ones, have been seen by VT before).
    """
    if not VT_API_KEY:
        return {'checked': False, 'reason': 'VT_API_KEY not configured'}

    try:
        r = requests.get(
            f"{VT_BASE_URL}/files/{sha256}",
            headers={'x-apikey': VT_API_KEY},
            timeout=15
        )

        if r.status_code == 404:
            return {'checked': True, 'found': False, 'reason': 'File never seen by VirusTotal — genuinely novel'}

        if r.status_code != 200:
            return {'checked': False, 'reason': f'VT API error: {r.status_code}'}

        data = r.json().get('data', {}).get('attributes', {})
        stats = data.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total_engines = sum(stats.values()) or 1

        # Dynamic/behavioral analysis results (sandbox verdicts) if available
        sandbox_verdicts = data.get('sandbox_verdicts', {})
        behavior_summary = []
        for sandbox_name, verdict in sandbox_verdicts.items():
            category = verdict.get('category', 'unknown')
            if category in ('malicious', 'suspicious'):
                behavior_summary.append(f"{sandbox_name}: {category}")

        return {
            'checked': True,
            'found': True,
            'malicious_count': malicious,
            'suspicious_count': suspicious,
            'total_engines': total_engines,
            'detection_ratio': f"{malicious}/{total_engines}",
            'is_malicious': malicious >= 3,  # conservative threshold — 3+ AV engines agree
            'sandbox_behavior': behavior_summary,
            'first_seen': data.get('first_submission_date'),
            'popular_threat_name': (data.get('popular_threat_classification', {})
                                     .get('suggested_threat_label')),
        }

    except Exception as e:
        log.error(f"VT hash lookup error: {e}")
        return {'checked': False, 'reason': str(e)}


def submit_file(filename: str, file_data: bytes) -> dict:
    """
    Tier 2: Upload a genuinely novel file (no hash match) for
    fresh dynamic sandbox analysis. Rate-limited to respect free
    tier. Returns an analysis_id to poll for results.

    NOTE: Only call this for files that already showed elevated
    risk in static analysis AND had no VT hash match — don't
    upload every attachment (wastes quota, and uploads customer
    file content to a third party, which should be a deliberate
    choice, not automatic for every clean-looking file).
    """
    if not VT_API_KEY:
        return {'submitted': False, 'reason': 'VT_API_KEY not configured'}

    if len(file_data) > 32 * 1024 * 1024:  # 32MB free tier limit
        return {'submitted': False, 'reason': 'File exceeds VT free tier size limit (32MB)'}

    _rate_limit()

    try:
        r = requests.post(
            f"{VT_BASE_URL}/files",
            headers={'x-apikey': VT_API_KEY},
            files={'file': (filename, file_data)},
            timeout=60
        )
        if r.status_code != 200:
            return {'submitted': False, 'reason': f'Upload failed: {r.status_code}'}

        analysis_id = r.json().get('data', {}).get('id')
        return {'submitted': True, 'analysis_id': analysis_id}

    except Exception as e:
        log.error(f"VT file submit error: {e}")
        return {'submitted': False, 'reason': str(e)}


def poll_analysis(analysis_id: str, max_wait_seconds: int = 180) -> dict:
    """
    Poll for dynamic analysis completion. Sandbox detonation
    takes 1-3 minutes typically. Call this AFTER submit_file()
    if you need the fresh result synchronously (e.g. holding an
    email for review); otherwise poll asynchronously later.
    """
    if not VT_API_KEY:
        return {'complete': False, 'reason': 'VT_API_KEY not configured'}

    start = time.time()
    while time.time() - start < max_wait_seconds:
        _rate_limit()
        try:
            r = requests.get(
                f"{VT_BASE_URL}/analyses/{analysis_id}",
                headers={'x-apikey': VT_API_KEY},
                timeout=15
            )
            if r.status_code != 200:
                return {'complete': False, 'reason': f'Poll error: {r.status_code}'}

            data = r.json().get('data', {}).get('attributes', {})
            status = data.get('status')

            if status == 'completed':
                stats = data.get('stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values()) or 1
                return {
                    'complete': True,
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'total_engines': total,
                    'detection_ratio': f"{malicious}/{total}",
                    'is_malicious': malicious >= 3,
                }

            time.sleep(10)

        except Exception as e:
            log.error(f"VT poll error: {e}")
            return {'complete': False, 'reason': str(e)}

    return {'complete': False, 'reason': 'Timed out waiting for sandbox analysis'}


def check_attachment(filename: str, sha256: str, file_data: bytes = None,
                       static_risk_score: int = 0) -> dict:
    """
    Main entry point — combines hash lookup with conditional
    upload. This is what mailbox_monitor.py / attachment_analyzer
    should call.

    Strategy:
      1. Always try hash lookup first (instant, free)
      2. If hash unknown AND static analysis already flagged
         elevated risk (>=40) AND file_data provided AND upload
         is explicitly enabled, submit for fresh dynamic analysis
      3. Otherwise, rely on hash lookup result alone
    """
    if not is_configured():
        return {
            'source': 'virustotal',
            'checked': False,
            'reason': 'VT_API_KEY not set — attachment sandboxing running in static-only mode',
        }

    hash_result = lookup_hash(sha256)

    result = {
        'source': 'virustotal',
        'method': 'hash_lookup',
        **hash_result,
    }

    # If genuinely novel AND already suspicious from static analysis,
    # this is exactly the case worth spending upload quota on
    should_upload = (
        hash_result.get('checked') and
        not hash_result.get('found') and
        static_risk_score >= 40 and
        file_data is not None and
        os.getenv('VT_AUTO_UPLOAD', 'false').lower() == 'true'
    )

    if should_upload:
        submit_result = submit_file(filename, file_data)
        if submit_result.get('submitted'):
            log.info(f"  Submitted novel high-risk file '{filename}' to VT for dynamic analysis...")
            poll_result = poll_analysis(submit_result['analysis_id'])
            result['method'] = 'dynamic_sandbox'
            result.update(poll_result)

    return result


if __name__ == "__main__":
    import sys
    print(f"VT_API_KEY configured: {is_configured()}")
    if len(sys.argv) > 1:
        result = lookup_hash(sys.argv[1])
        print(result)
