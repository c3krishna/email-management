// ============================================================
// Customer Email Validation API
// /var/www/email-management/backend/routes/validate.js
//
// Public-facing API for customers to submit email content for
// spam/phishing/malware/BEC validation using Worktual AI Engine.
// Automatically triggers notifications on threat detection.
//
// Auth: X-API-Key header (customer's api_keys.key_value)
// ============================================================

const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');
const crypto  = require('crypto');
const dns     = require('dns').promises;

let pool = null;
function getPool() {
  if (!pool) pool = mysql.createPool({
    host:     process.env.DB_HOST || '10.180.0.84',
    user:     process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'threat_platform',
    waitForConnections: true, connectionLimit: 10,
  });
  return pool;
}

const OLLAMA_URL = process.env.OLLAMA_URL || 'http://miniai.worktual.tech:11434';
const AI_MODEL   = process.env.AI_MODEL   || 'llama3.1:8b';

// ── Pattern rules (JS-valid regex, case-insensitive flag) ──────
const PATTERNS = [
  { re:/(urgent|immediately).{0,30}(verify|confirm|update).{0,30}(account|password|login)/i, type:'phishing', conf:88 },
  { re:/(suspend|block|limit).{0,20}(account|access|card)/i,                                   type:'phishing', conf:85 },
  { re:/(paypal|amazon|apple|microsoft|google).{0,30}(verify|confirm|suspended)/i,             type:'phishing', conf:87 },
  { re:/click.{0,20}(here|below|link).{0,20}(verify|confirm|restore)/i,                        type:'phishing', conf:82 },
  { re:/(million|billion).{0,20}(dollar|usd|euro).{0,20}(transfer|beneficiar)/i,                type:'scam',     conf:92 },
  { re:/(lottery|winner|prize|won).{0,30}(claim|collect|contact)/i,                             type:'scam',     conf:88 },
  { re:/(wire|bank).{0,10}transfer.{0,30}(urgent|today|immediately)/i,                          type:'bec',      conf:85 },
  { re:/(ceo|president|director|boss).{0,20}(requesting|asking|need|wire)/i,                    type:'bec',      conf:78 },
  { re:/\.(exe|js|vbs|bat|cmd|scr)(\b|$)/i,                                                     type:'malware',  conf:90 },
  { re:/(invoice|receipt|document|delivery).{0,10}(attached|enclosed|below)/i,                  type:'malware',  conf:55 },
  { re:/(buy|order|purchase).{0,20}(cheap|discount|sale).{0,20}(now|today|online)/i,             type:'spam',     conf:72 },
  { re:/(weight loss|diet pill|slim|fat burn).{0,20}(fast|quick|easy)/i,                        type:'spam',     conf:75 },
  { re:/(pharmacy|medication|prescription).{0,20}(cheap|online|no prescription)/i,               type:'spam',     conf:80 },
  { re:/(bitcoin|ethereum|crypto).{0,20}(double|earn|profit|investment)/i,                       type:'crypto_scam', conf:85 },
];

function scanText(text) {
  if (!text) return null;
  let best = null;
  for (const p of PATTERNS) {
    if (p.re.test(text)) {
      if (!best || p.conf > best.conf) best = { type: p.type, conf: p.conf };
    }
  }
  return best;
}

function extractUrls(text) {
  if (!text) return [];
  return [...new Set((text.match(/https?:\/\/[^\s<>"']+/g) || []))].slice(0, 20);
}

function extractDomain(email) {
  if (!email || !email.includes('@')) return null;
  return email.split('@').pop().toLowerCase().replace(/[>\s]/g, '');
}

function detectTyposquat(domain) {
  if (!domain) return null;
  const brands = ['microsoft','google','paypal','amazon','apple','facebook','netflix',
                   'bankofamerica','chase','wellsfargo','office365','outlook'];
  const normalized = domain.replace(/[0-9]/g, m => ({0:'o',1:'l',3:'e',5:'s',7:'t'}[m] || m));
  for (const brand of brands) {
    if (normalized.includes(brand) && !domain.includes(brand)) {
      return { brand, reason: `Domain resembles "${brand}" using character substitution (typosquat)` };
    }
    if (domain.includes(brand) && !domain.endsWith(`${brand}.com`)) {
      return { brand, reason: `Contains "${brand}" but is not the official domain` };
    }
  }
  return null;
}

async function checkDomainResolves(domain) {
  try {
    await dns.resolveNs(domain);
    return true;
  } catch (e) {
    return false;
  }
}

async function aiClassify(subject, mailFrom, body) {
  const prompt = `You are an email security analyst. Classify this email strictly and conservatively.

FROM: ${mailFrom || ''}
SUBJECT: ${subject || ''}
BODY:
${(body || '').slice(0, 1000)}

Respond with JSON only, no other text:
{"is_spam": true/false, "spam_type": "phishing/scam/malware/bec/spam/legitimate", "confidence": 0-100, "reason": "one sentence explanation"}`;

  try {
    const r = await fetch(`${OLLAMA_URL}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify({
        model: AI_MODEL, prompt, stream: false,
        options: { temperature: 0.05, num_predict: 180 },
      }),
      signal: AbortSignal.timeout(20000),
    });
    if (!r.ok) return null;
    const data = await r.json();
    const match = (data.response || '').match(/\{[^}]+\}/s);
    if (!match) return null;
    const parsed = JSON.parse(match[0]);
    return {
      is_spam:    !!parsed.is_spam,
      spam_type:  parsed.spam_type || 'unknown',
      confidence: Math.min(100, Math.max(0, parseInt(parsed.confidence) || 0)),
      reason:     (parsed.reason || '').slice(0, 300),
    };
  } catch (e) {
    return null;
  }
}

// ── API Key auth middleware ─────────────────────────────────────
async function apiKeyAuth(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  if (!apiKey) {
    return res.status(401).json({ error: 'Missing X-API-Key header' });
  }
  try {
    const p = getPool();
    const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

    const [rows] = await p.query(`
      SELECT ak.*, c.name AS customer_name, c.domain AS customer_domain
      FROM api_keys ak
      JOIN customers c ON c.id = ak.customer_id
      WHERE ak.key_hash = ? AND ak.active = 1
        AND (ak.expires_at IS NULL OR ak.expires_at > NOW())
      LIMIT 1
    `, [keyHash]);

    if (!rows.length) {
      return res.status(401).json({ error: 'Invalid or inactive API key' });
    }
    req.apiCustomer = rows[0];

    // Update last_used_at + log request (fire and forget)
    p.query('UPDATE api_keys SET last_used_at = NOW() WHERE id = ?', [rows[0].id]).catch(() => {});
    p.query(
      'INSERT INTO api_request_log (api_key_id, endpoint, ip_address) VALUES (?,?,?)',
      [rows[0].id, req.path, req.ip]
    ).catch(() => {});

    next();
  } catch (e) {
    console.error('[validate] auth error:', e.message);
    res.status(500).json({ error: 'Authentication check failed' });
  }
}

// ── Send notification (reuses notification_settings + SMTP) ────
async function sendThreatNotification(customer, emailData, verdict) {
  try {
    const p = getPool();
    const [[settings]] = await p.query(
      'SELECT * FROM notification_settings WHERE customer_id=?',
      [customer.id]
    ).catch(() => [[null]]);

    if (!settings || !settings.active) return { sent: false, reason: 'notifications disabled' };
    if (verdict.confidence < (settings.min_confidence || 70)) {
      return { sent: false, reason: 'below confidence threshold' };
    }

    let adminEmails = [];
    try {
      adminEmails = JSON.parse(settings.admin_emails || '[]');
    } catch (e) {}

    if (!adminEmails.length) return { sent: false, reason: 'no admin emails configured' };

    const nodemailer = require('nodemailer');
    const transport = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'mail.worktual.tech',
      port: parseInt(process.env.SMTP_PORT || '587'),
      auth: {
        user: process.env.SMTP_USER || 'security@worktual.tech',
        pass: process.env.SMTP_PASS || '',
      }
    });

    const severityColor = verdict.confidence >= 85 ? '#ef4444' : verdict.confidence >= 70 ? '#f97316' : '#eab308';

    const html = `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;
                  background:#f9fafb;border-radius:10px;overflow:hidden;border:1px solid #e5e7eb">
        <div style="background:${severityColor};padding:20px 24px">
          <h2 style="margin:0;color:#fff;font-size:18px">🚨 ${verdict.spam_type.toUpperCase()} Detected</h2>
          <p style="margin:4px 0 0;color:rgba(255,255,255,0.85);font-size:12px">
            ${customer.customer_name} · Confidence: ${verdict.confidence}% · ${new Date().toISOString()}
          </p>
        </div>
        <div style="padding:20px 24px">
          <table style="width:100%;font-size:13px;border-collapse:collapse">
            <tr><td style="color:#6b7280;padding:6px 0;width:100px">From:</td>
                <td style="font-weight:600">${emailData.mail_from || '—'}</td></tr>
            <tr><td style="color:#6b7280;padding:6px 0">To:</td>
                <td>${emailData.mail_to || '—'}</td></tr>
            <tr><td style="color:#6b7280;padding:6px 0">Subject:</td>
                <td style="font-weight:600">${emailData.subject || '—'}</td></tr>
            <tr><td style="color:#6b7280;padding:6px 0">Reason:</td>
                <td>${verdict.reason || 'Pattern-based detection'}</td></tr>
          </table>
        </div>
        <div style="padding:12px 24px;background:#f3f4f6;font-size:11px;color:#9ca3af">
          Worktual AI Email Validation API · Automated Security Alert
        </div>
      </div>`;

    for (const email of adminEmails.slice(0, 5)) {
      await transport.sendMail({
        from: `"Worktual Security API" <${process.env.SMTP_USER || 'security@worktual.tech'}>`,
        to: email,
        subject: `🚨 [${verdict.spam_type.toUpperCase()}] Threat detected via API — ${customer.customer_name}`,
        html,
      });
    }

    return { sent: true, recipients: adminEmails.length };
  } catch (e) {
    console.error('[validate] notification error:', e.message);
    return { sent: false, reason: e.message };
  }
}

// ============================================================
// POST /api/v1/validate-email
// Customer-facing endpoint: validate email content for threats
//
// Headers: X-API-Key: <customer_api_key>
// Body: {
//   mail_from: string,
//   mail_to: string,
//   subject: string,
//   body: string,
//   notify: boolean (default true)
// }
// ============================================================
router.post('/validate-email', apiKeyAuth, async (req, res) => {
  const { mail_from, mail_to, subject, body, notify = true } = req.body;
  const customer = req.apiCustomer;

  if (!subject && !body && !mail_from) {
    return res.status(400).json({ error: 'At least one of mail_from, subject, or body is required' });
  }

  const startTime = Date.now();

  try {
    const senderDomain = extractDomain(mail_from);
    const urls = extractUrls(body);

    // Step 1: Pattern scan
    const patternMatch = scanText(`${subject || ''} ${body || ''}`);

    // Step 2: Typosquat check
    const typosquat = detectTyposquat(senderDomain);

    // Step 3: Domain resolution check
    const domainResolves = senderDomain ? await checkDomainResolves(senderDomain) : null;

    // Step 4: AI classification (always run for API — customers expect thorough check)
    const aiResult = await aiClassify(subject, mail_from, body);

    // Step 5: Determine final verdict
    let finalType = 'legitimate', finalConfidence = 0, method = 'clean';

    if (patternMatch) {
      finalType = patternMatch.type;
      finalConfidence = patternMatch.conf;
      method = 'pattern';
    }
    if (aiResult && aiResult.is_spam && aiResult.confidence > finalConfidence) {
      finalType = aiResult.spam_type;
      finalConfidence = aiResult.confidence;
      method = patternMatch ? 'pattern+ai' : 'ai';
    }
    if (typosquat && finalConfidence < 85) {
      finalConfidence = Math.max(finalConfidence, 85);
      finalType = finalType === 'legitimate' ? 'phishing' : finalType;
      method += '+typosquat';
    }

    const isThreat = finalConfidence >= 60;
    const verdict = {
      is_threat:  isThreat,
      spam_type:  isThreat ? finalType : 'legitimate',
      confidence: finalConfidence,
      method,
      reason:     aiResult?.reason || (patternMatch ? `Matched ${patternMatch.type} pattern` : 'No threat indicators found'),
      indicators: {
        pattern_match:      !!patternMatch,
        ai_flagged:         !!(aiResult && aiResult.is_spam),
        typosquat_detected: !!typosquat,
        typosquat_detail:   typosquat?.reason || null,
        domain_resolves:    domainResolves,
        urls_found:         urls.length,
      },
    };

    // Save to DB
    const dedupHash = crypto.createHash('md5')
      .update(`${mail_from}${mail_to}${subject}${Date.now()}`).digest('hex');

    let eventId = null;
    try {
      const [result] = await getPool().query(`
        INSERT INTO security_events
          (customer_id, platform, event_type, mail_from, mail_to, subject,
           event_datetime, threat_category, threat_score, sender_domain,
           urls, ai_processed, ai_threat_type, ai_confidence, ai_explanation, dedup_hash)
        VALUES (?,?,?,?,?,?,NOW(),?,?,?,?,1,?,?,?,?)
      `, [
        customer.customer_id, 'api', isThreat ? 'blocked' : 'delivered',
        mail_from, mail_to, subject,
        isThreat ? finalType : null, finalConfidence, senderDomain, JSON.stringify(urls),
        finalType, finalConfidence, verdict.reason, dedupHash,
      ]);
      eventId = result.insertId;
    } catch (e) {
      console.error('[validate] save error:', e.message);
    }

    // Trigger notification if threat + notify=true
    let notificationResult = { sent: false, reason: 'not requested' };
    if (isThreat && notify) {
      notificationResult = await sendThreatNotification(customer, { mail_from, mail_to, subject }, verdict);
    }

    res.json({
      success: true,
      event_id: eventId,
      verdict,
      notification: notificationResult,
      processing_time_ms: Date.now() - startTime,
      customer: customer.customer_name,
    });

  } catch (e) {
    console.error('[validate] error:', e);
    res.status(500).json({ error: 'Validation failed', detail: e.message });
  }
});

// ============================================================
// POST /api/v1/validate-batch
// Validate multiple emails in one call (max 50)
// ============================================================
router.post('/validate-batch', apiKeyAuth, async (req, res) => {
  const { emails, notify = true } = req.body;
  if (!Array.isArray(emails) || !emails.length) {
    return res.status(400).json({ error: 'emails array required' });
  }
  if (emails.length > 50) {
    return res.status(400).json({ error: 'Maximum 50 emails per batch' });
  }

  const results = [];
  for (const email of emails) {
    try {
      const senderDomain = extractDomain(email.mail_from);
      const patternMatch = scanText(`${email.subject || ''} ${email.body || ''}`);
      const typosquat = detectTyposquat(senderDomain);

      let finalType = 'legitimate', finalConfidence = 0;
      if (patternMatch) { finalType = patternMatch.type; finalConfidence = patternMatch.conf; }
      if (typosquat && finalConfidence < 85) { finalConfidence = 85; finalType = finalType === 'legitimate' ? 'phishing' : finalType; }

      results.push({
        mail_from:  email.mail_from,
        subject:    email.subject,
        is_threat:  finalConfidence >= 60,
        spam_type:  finalConfidence >= 60 ? finalType : 'legitimate',
        confidence: finalConfidence,
      });
    } catch (e) {
      results.push({ mail_from: email.mail_from, error: e.message });
    }
  }

  const threatCount = results.filter(r => r.is_threat).length;
  res.json({
    success: true,
    total: results.length,
    threats_found: threatCount,
    results,
  });
});

// ============================================================
// GET /api/v1/validate-status
// Check API key validity and usage stats
// ============================================================
router.get('/validate-status', apiKeyAuth, async (req, res) => {
  try {
    const p = getPool();
    const [[stats]] = await p.query(`
      SELECT COUNT(*) AS total_validated,
             SUM(CASE WHEN threat_category IS NOT NULL THEN 1 ELSE 0 END) AS threats_found
      FROM security_events
      WHERE customer_id = ? AND platform = 'api'
        AND event_datetime >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    `, [req.apiCustomer.customer_id]);

    res.json({
      success: true,
      customer: req.apiCustomer.customer_name,
      api_key_active: true,
      last_30_days: stats,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
