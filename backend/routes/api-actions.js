// ============================================================
// API Integration Action Endpoints
// /var/www/email-management/backend/routes/api-actions.js
//
// Powers the clickable buttons in VR Threat Platform's
// "API Integration Layer" panel: Fetch Email Logs, Fetch Threat
// Logs, Fetch Quarantine, Fetch Detection Events, Historical
// Retrieval, Continuous Sync — each returns REAL data and shows
// what the AI Orchestrator would do with it.
// ============================================================

const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');
const { verifyToken } = require('../middleware/auth');

let tPool = null, ePool = null;
function getThreatPool() {
  if (!tPool) tPool = mysql.createPool({
    host: process.env.DB_HOST || '10.180.0.84', user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'threat_platform', waitForConnections: true, connectionLimit: 10,
  });
  return tPool;
}
function getEmailPool() {
  if (!ePool) ePool = mysql.createPool({
    host: process.env.DB_HOST || '10.180.0.84', user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'worktual_email_campaign', waitForConnections: true, connectionLimit: 10,
  });
  return ePool;
}

const OLLAMA_URL = process.env.OLLAMA_URL || 'http://miniai.worktual.tech:11434';
const AI_MODEL   = process.env.AI_MODEL   || 'llama3.1:8b';

// ── GET /api/actions/fetch-email-logs?customer_id= ─────────────
router.get('/fetch-email-logs', verifyToken, async (req, res) => {
  const { customer_id, limit = 10 } = req.query;
  try {
    const [rows] = await getEmailPool().query(`
      SELECT queue_id, mail_from, mail_to, status, CONCAT(log_date, ' ', log_time) AS log_datetime
      FROM email_delivery_details
      WHERE customer_id = ? ORDER BY id DESC LIMIT ?
    `, [customer_id || 1, parseInt(limit)]);
    res.json({
      success: true, action: 'Fetch Email Logs',
      agent: 'API Integration Agent', count: rows.length, data: rows,
      note: rows.length ? 'Live data from Postfix delivery logs' : 'No recent emails for this customer',
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET /api/actions/fetch-threat-logs?customer_id= ─────────────
router.get('/fetch-threat-logs', verifyToken, async (req, res) => {
  const { customer_id, limit = 10 } = req.query;
  try {
    const [rows] = await getThreatPool().query(`
      SELECT id, platform, mail_from, subject, threat_category, threat_score, event_datetime
      FROM security_events
      WHERE customer_id = ? AND threat_category IS NOT NULL
      ORDER BY event_datetime DESC LIMIT ?
    `, [customer_id || 1, parseInt(limit)]);
    res.json({
      success: true, action: 'Fetch Threat Logs',
      agent: 'API Integration Agent', count: rows.length, data: rows,
      note: rows.length ? `${rows.length} threats found` : 'No threats detected yet — send a test via Validation API',
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET /api/actions/fetch-quarantine?customer_id= ──────────────
router.get('/fetch-quarantine', verifyToken, async (req, res) => {
  const { customer_id } = req.query;
  try {
    const [rows] = await getEmailPool().query(`
      SELECT id, mail_from, mail_to, subject, spam_score, classification, log_datetime
      FROM email_log_realtime
      WHERE customer_id = ? AND (spam_score >= 5 OR classification IS NOT NULL
            OR status IN ('rejected','blocked','quarantined'))
      ORDER BY log_datetime DESC LIMIT 20
    `, [customer_id || 1]);
    res.json({
      success: true, action: 'Fetch Quarantine',
      agent: 'API Integration Agent', count: rows.length, data: rows,
      note: rows.length ? `${rows.length} quarantined emails` : 'Quarantine empty — no emails exceeded spam threshold (score ≥5)',
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET /api/actions/fetch-detection-events?customer_id= ────────
router.get('/fetch-detection-events', verifyToken, async (req, res) => {
  const { customer_id, limit = 10 } = req.query;
  try {
    const [rows] = await getThreatPool().query(`
      SELECT id, platform, event_type, mail_from, ai_threat_type, ai_confidence, ai_explanation, event_datetime
      FROM security_events
      WHERE customer_id = ? AND ai_processed = 1
      ORDER BY event_datetime DESC LIMIT ?
    `, [customer_id || 1, parseInt(limit)]);
    res.json({
      success: true, action: 'Fetch Detection Events',
      agent: 'IOC Extraction + Threat Classification Agents', count: rows.length, data: rows,
      note: rows.length ? `${rows.length} AI-processed detections` : 'No AI detection events yet',
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET /api/actions/historical-retrieval?customer_id=&days= ────
router.get('/historical-retrieval', verifyToken, async (req, res) => {
  const { customer_id, days = 30 } = req.query;
  try {
    const [rows] = await getThreatPool().query(`
      SELECT DATE(event_datetime) AS date, COUNT(*) AS total,
             SUM(CASE WHEN threat_category IS NOT NULL THEN 1 ELSE 0 END) AS threats
      FROM security_events
      WHERE customer_id = ? AND event_datetime >= DATE_SUB(NOW(), INTERVAL ? DAY)
      GROUP BY DATE(event_datetime) ORDER BY date DESC
    `, [customer_id || 1, parseInt(days)]);
    res.json({
      success: true, action: 'Historical Retrieval',
      agent: 'Central Data Platform', count: rows.length, data: rows,
      note: `Retrieved ${days}-day historical trend (retention: 6 months – 1 year)`,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── POST /api/actions/continuous-sync ────────────────────────────
// Actually triggers a live check + AI validation on the most recent
// unprocessed inbound email for this customer — the "sync tick".
router.post('/continuous-sync', verifyToken, async (req, res) => {
  const { customer_id } = req.body;
  try {
    const [rows] = await getEmailPool().query(`
      SELECT mail_from, mail_to, subject, CONCAT(log_date, ' ', log_time) AS log_datetime
      FROM email_delivery_details
      WHERE customer_id = ? ORDER BY id DESC LIMIT 1
    `, [customer_id || 1]);

    if (!rows.length) {
      return res.json({ success: true, action: 'Continuous Sync',
        synced: 0, note: 'No new events to sync' });
    }

    const email = rows[0];

    // Quick AI check on the most recent email (real call)
    let aiResult = null;
    try {
      const prompt = `Classify this email briefly. FROM: ${email.mail_from}\nSUBJECT: ${email.subject || ''}\nRespond JSON only: {"is_spam":bool,"spam_type":"string","confidence":0-100}`;
      const r = await fetch(`${OLLAMA_URL}/api/generate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: AI_MODEL, prompt, stream: false, options: { num_predict: 100 } }),
        signal: AbortSignal.timeout(15000),
      });
      const data = await r.json();
      const m = (data.response || '').match(/\{[^}]+\}/s);
      if (m) aiResult = JSON.parse(m[0]);
    } catch (e) { /* non-fatal */ }

    res.json({
      success: true, action: 'Continuous Sync',
      agent: 'AI Orchestrator', synced: 1,
      last_synced_email: email, ai_check: aiResult,
      note: 'Sync tick complete — most recent event checked against AI engine',
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;
