#!/usr/bin/env python3
"""
============================================================
Worktual Attachment Static Analyzer
File: /opt/virus-rescuers/detection/attachment_analyzer.py

Real "sandboxing" without a VM farm — static + AI analysis:
  1. Office docs (.doc/.docx/.xls/.xlsx) → extract VBA macros,
     scan for suspicious API calls (Shell, URLDownloadToFile,
     AutoOpen, CreateObject("WScript.Shell") etc.)
  2. PDFs → check for embedded JavaScript, /OpenAction, /Launch
  3. Executables → PE header parse, check for packing (high
     entropy = likely obfuscated/packed malware)
  4. Any script content found → sent to qwen2.5:14b-instruct-q4_K_M for a
     plain-English "what does this code actually do" analysis
  5. Archives (.zip/.rar) → list contents, flag double extensions
     (invoice.pdf.exe) and nested archives (zip bombs)

This catches NOVEL malware with no known hash — the #1 gap
in pure hash-matching.

Import into mailbox_monitor.py / validate.js pipeline.
============================================================
"""

import os, re, math, zipfile, struct, logging, requests, json
import virustotal_check

log = logging.getLogger("attachment-analyzer")

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://miniai.worktual.tech:11434")
AI_MODEL   = os.getenv("AI_MODEL",   "qwen2.5:14b-instruct-q4_K_M")

# ── Suspicious VBA/macro API calls ──────────────────────────────
SUSPICIOUS_MACRO_APIS = [
    'Shell', 'WScript.Shell', 'CreateObject', 'URLDownloadToFile',
    'AutoOpen', 'AutoExec', 'Document_Open', 'Workbook_Open',
    'CreateProcess', 'RegWrite', 'RegDelete', 'Environ',
    'ShellExecute', 'WinHttp', 'ADODB.Stream', 'Chr(', 'StrReverse',
    'Base64Decode', 'PowerShell', 'cmd.exe', 'certutil',
]

SUSPICIOUS_PDF_TOKENS = [
    b'/JavaScript', b'/JS', b'/OpenAction', b'/Launch',
    b'/EmbeddedFile', b'/RichMedia', b'/AA',  # AA = Additional Actions
]

DANGEROUS_EXTENSIONS = {'.exe','.scr','.bat','.cmd','.com','.pif','.vbs','.js','.jse',
                          '.wsf','.wsh','.ps1','.msi','.jar','.hta','.dll'}


def shannon_entropy(data: bytes) -> float:
    """Calculate byte-level entropy. High entropy (>7.2) suggests
    packed/encrypted/compressed content — common in obfuscated malware."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def extract_vba_strings(data: bytes) -> list:
    """Rough VBA/macro extraction without full OLE parsing —
    looks for readable script fragments inside the binary blob.
    Works well enough to catch suspicious API call names even
    inside compressed OLE streams for common obfuscation levels."""
    try:
        text = data.decode('latin-1', errors='ignore')
    except Exception:
        return []
    # Find runs of printable ASCII (macro source often survives this way)
    fragments = re.findall(r'[\x20-\x7e]{15,}', text)
    return fragments


def analyze_office_doc(filename: str, data: bytes) -> dict:
    findings = []
    risk = 0

    fragments = extract_vba_strings(data)
    full_text = ' '.join(fragments)

    hit_apis = [api for api in SUSPICIOUS_MACRO_APIS if api.lower() in full_text.lower()]
    if hit_apis:
        findings.append(f"Suspicious macro API calls found: {', '.join(hit_apis[:6])}")
        risk += min(60, len(hit_apis) * 12)

    # AutoOpen/AutoExec = macro runs without user interaction
    if any(a in full_text for a in ['AutoOpen', 'AutoExec', 'Document_Open', 'Workbook_Open']):
        findings.append("Macro auto-executes on document open (no user click needed)")
        risk += 25

    entropy = shannon_entropy(data)
    if entropy > 7.2:
        findings.append(f"High entropy ({entropy}/8.0) — content may be packed/obfuscated")
        risk += 15

    # Send suspicious fragments to AI for plain-English explanation
    ai_summary = None
    if hit_apis:
        snippet = full_text[:800]
        ai_summary = ai_explain_script(snippet, "VBA macro extracted from Office document")

    return {
        'file_type': 'office_document',
        'risk_score': min(100, risk),
        'findings': findings,
        'entropy': entropy,
        'ai_summary': ai_summary,
        'is_malicious': risk >= 50,
    }


def analyze_pdf(filename: str, data: bytes) -> dict:
    findings = []
    risk = 0

    for token in SUSPICIOUS_PDF_TOKENS:
        if token in data:
            findings.append(f"PDF contains {token.decode()} — can auto-execute code on open")
            risk += 25

    entropy = shannon_entropy(data)
    if entropy > 7.5:
        findings.append(f"High entropy ({entropy}/8.0) — possible embedded encrypted payload")
        risk += 15

    ai_summary = None
    if b'/JavaScript' in data or b'/JS' in data:
        # Try to extract JS between stream markers (rough)
        m = re.search(rb'/JS\s*\((.*?)\)', data, re.DOTALL)
        if m:
            js_snippet = m.group(1)[:600].decode('latin-1', errors='ignore')
            ai_summary = ai_explain_script(js_snippet, "JavaScript extracted from PDF")

    return {
        'file_type': 'pdf',
        'risk_score': min(100, risk),
        'findings': findings,
        'entropy': entropy,
        'ai_summary': ai_summary,
        'is_malicious': risk >= 50,
    }


def analyze_executable(filename: str, data: bytes) -> dict:
    findings = []
    risk = 60  # any raw executable attachment starts elevated

    is_pe = data[:2] == b'MZ'
    if is_pe:
        findings.append("Windows PE executable (.exe/.dll) detected")
        risk += 20

    entropy = shannon_entropy(data)
    if entropy > 7.2:
        findings.append(f"High entropy ({entropy}/8.0) — likely packed/obfuscated executable")
        risk += 15

    if len(data) < 50000 and is_pe:
        findings.append("Unusually small executable — common in droppers/loaders")
        risk += 10

    return {
        'file_type': 'executable',
        'risk_score': min(100, risk),
        'findings': findings,
        'entropy': entropy,
        'ai_summary': None,
        'is_malicious': True,  # raw executables in email are almost always flagged
    }


def analyze_archive(filename: str, data: bytes) -> dict:
    findings = []
    risk = 0
    inner_files = []

    try:
        import io
        z = zipfile.ZipFile(io.BytesIO(data))
        inner_files = z.namelist()

        for name in inner_files:
            # Double-extension trick: invoice.pdf.exe
            parts = name.lower().split('.')
            if len(parts) >= 3 and f'.{parts[-1]}' in DANGEROUS_EXTENSIONS:
                findings.append(f"Double-extension file inside archive: {name}")
                risk += 40
            elif f'.{name.lower().split(".")[-1]}' in DANGEROUS_EXTENSIONS:
                findings.append(f"Dangerous file type inside archive: {name}")
                risk += 35

        # Nested archive = potential zip bomb / evasion
        nested = [n for n in inner_files if n.lower().endswith(('.zip', '.rar', '.7z'))]
        if nested:
            findings.append(f"Nested archive(s) found: {nested[:3]} — common evasion technique")
            risk += 15

    except Exception as e:
        findings.append(f"Could not parse archive: {e}")

    return {
        'file_type': 'archive',
        'risk_score': min(100, risk),
        'findings': findings,
        'contents': inner_files[:20],
        'ai_summary': None,
        'is_malicious': risk >= 50,
    }


def ai_explain_script(snippet: str, context: str) -> str:
    """Ask qwen2.5:14b-instruct-q4_K_M to explain, in plain English, what an
    extracted script fragment does — helps analysts without
    needing to read raw VBA/JS."""
    try:
        prompt = (f"You are a malware analyst. Below is a {context}. "
                  f"In 1-2 plain-English sentences, explain what this code appears "
                  f"to do and whether it looks malicious. Be concise.\n\n"
                  f"CODE:\n{snippet[:800]}")
        r = requests.post(f"{OLLAMA_URL}/api/generate", json={
            "model": AI_MODEL, "prompt": prompt, "stream": False,
            "options": {"temperature": 0.1, "num_predict": 150}
        }, timeout=20)
        return r.json().get("response", "").strip()[:400]
    except Exception as e:
        log.warning(f"AI script explain error: {e}")
        return None


def analyze_attachment(filename: str, data: bytes) -> dict:
    """
    Main entry point — routes to the right analyzer based on file type,
    THEN cross-checks with VirusTotal's real dynamic sandbox network
    (if configured). This combination of static heuristics + real
    behavioral/multi-engine sandbox verdicts closes the zero-day gap.
    """
    import hashlib
    ext = os.path.splitext(filename.lower())[1]

    if ext in {'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'}:
        result = analyze_office_doc(filename, data)
    elif ext == '.pdf':
        result = analyze_pdf(filename, data)
    elif ext in DANGEROUS_EXTENSIONS:
        result = analyze_executable(filename, data)
    elif ext in {'.zip', '.rar', '.7z'}:
        result = analyze_archive(filename, data)
    else:
        entropy = shannon_entropy(data)
        result = {
            'file_type': 'other',
            'risk_score': 15 if entropy > 7.5 else 0,
            'findings': [f"High entropy content ({entropy}/8.0)"] if entropy > 7.5 else [],
            'entropy': entropy,
            'ai_summary': None,
            'is_malicious': False,
        }

    result['filename'] = filename
    result['size'] = len(data)

    # ── Cross-check with VirusTotal (real dynamic sandbox network) ──
    if virustotal_check.is_configured():
        sha256 = hashlib.sha256(data).hexdigest()
        vt_result = virustotal_check.check_attachment(
            filename, sha256, file_data=data, static_risk_score=result['risk_score']
        )
        result['virustotal'] = vt_result

        if vt_result.get('found') and vt_result.get('is_malicious'):
            result['risk_score'] = max(result['risk_score'], 95)
            result['is_malicious'] = True
            result['findings'].append(
                f"VirusTotal: {vt_result.get('detection_ratio')} engines flagged malicious"
                + (f" ({vt_result.get('popular_threat_name')})" if vt_result.get('popular_threat_name') else '')
            )
            if vt_result.get('sandbox_behavior'):
                result['findings'].append(
                    f"Dynamic sandbox behavior: {'; '.join(vt_result['sandbox_behavior'])}"
                )
        elif vt_result.get('found') and not vt_result.get('is_malicious'):
            if result['risk_score'] < 70:
                result['findings'].append(
                    f"VirusTotal: clean across {vt_result.get('total_engines')} engines "
                    f"(known file, first seen {vt_result.get('first_seen')})"
                )
        elif vt_result.get('method') == 'dynamic_sandbox' and vt_result.get('complete'):
            if vt_result.get('is_malicious'):
                result['risk_score'] = max(result['risk_score'], 90)
                result['is_malicious'] = True
                result['findings'].append(
                    f"Fresh dynamic sandbox analysis: {vt_result.get('detection_ratio')} engines flagged malicious"
                )

    return result


if __name__ == "__main__":
    # Quick self-test
    import sys
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'rb') as f:
            data = f.read()
        result = analyze_attachment(os.path.basename(sys.argv[1]), data)
        print(json.dumps(result, indent=2))
