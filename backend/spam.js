// ============================================================
// Spam Detection API
// /var/www/email-management/backend/routes/spam.js
// ============================================================

const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');
const { verifyToken, requireRole } = require('../middleware/auth');

let spamPool = null;
function getSpamPool() {
  if (!spamPool) {
    spamPool = mysql.createPool({
      host:     process.env.DB_HOST || '10.180.0.84',
      user:     process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: 'threat_platform',
      waitForConnections: true,
      connectionLimit: 10,
    });
  }
  return spamPool;
}

// Agent secret auth
function agentAuth(req, res, next) {
  if (req.headers['x-agent-secret'] !== (process.env.AGENT_SECRET)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// POST /api/spam/notification — from spam_detector.py
router.post('/notification', agentAuth, async (req, res) => {
  try {
    const pool = getSpamPool();
    // Store as alert for dashboard notification bell
    await pool.query(`
      INSERT IGNORE INTO spam_detections
        (log_id, server, mail_from, mail_to, subject, spam_type,
         confidence, detection_method, ai_explanation, pattern_matched)
      VALUES (?,?,?,?,?,?,?,?,?,?)
      ON DUPLICATE KEY UPDATE confidence=VALUES(confidence)
    `, [
      req.body.log_id, req.body.server,
      req.body.mail_from, req.body.mail_to,
      req.body.subject, req.body.spam_type,
      req.body.confidence, req.body.detection_method,
      req.body.ai_explanation, req.body.pattern_matched,
    ]);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/spam/summary
router.get('/summary', verifyToken, async (req, res) => {
  try {
    const { hours = 24 } = req.query;
    const pool = getSpamPool();

    const [[stats]] = await pool.query(`
      SELECT
        COUNT(*)                                                             AS total,
        SUM(CASE WHEN spam_type='phishing'  THEN 1 ELSE 0 END)             AS phishing,
        SUM(CASE WHEN spam_type='spam'      THEN 1 ELSE 0 END)             AS spam,
        SUM(CASE WHEN spam_type='malware'   THEN 1 ELSE 0 END)             AS malware,
        SUM(CASE WHEN spam_type='bec'       THEN 1 ELSE 0 END)             AS bec,
        SUM(CASE WHEN spam_type='scam'      THEN 1 ELSE 0 END)             AS scam,
        SUM(CASE WHEN alert_sent=1          THEN 1 ELSE 0 END)             AS alerts_sent,
        SUM(CASE WHEN false_positive=1      THEN 1 ELSE 0 END)             AS false_positives,
        SUM(CASE WHEN reviewed=0            THEN 1 ELSE 0 END)             AS unreviewed,
        AVG(confidence)                                                      AS avg_confidence
      FROM spam_detections
      WHERE detected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
    `, [parseInt(hours)]);

    const [trend] = await pool.query(`
      SELECT
        DATE(detected_at)                                       AS date,
        COUNT(*)                                                AS total,
        SUM(CASE WHEN spam_type='phishing' THEN 1 ELSE 0 END)  AS phishing,
        SUM(CASE WHEN spam_type='spam'     THEN 1 ELSE 0 END)  AS spam,
        SUM(CASE WHEN spam_type='malware'  THEN 1 ELSE 0 END)  AS malware,
        SUM(CASE WHEN spam_type='bec'      THEN 1 ELSE 0 END)  AS bec
      FROM spam_detections
      WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
      GROUP BY DATE(detected_at)
      ORDER BY date ASC
    `);

    const [topSenders] = await pool.query(`
      SELECT mail_from, COUNT(*) AS count, MAX(spam_type) AS type
      FROM spam_detections
      WHERE detected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
        AND mail_from IS NOT NULL
      GROUP BY mail_from
      ORDER BY count DESC LIMIT 10
    `, [parseInt(hours)]);

    res.json({ success: true, data: { stats, trend, topSenders } });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/spam/detections
router.get('/detections', verifyToken, async (req, res) => {
  try {
    const { page=1, limit=50, spam_type, reviewed, hours=24 } = req.query;
    const pool   = getSpamPool();
    const where  = ['detected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)'];
    const params = [parseInt(hours)];

    if (spam_type) { where.push('spam_type=?');  params.push(spam_type);  }
    if (reviewed !== undefined) { where.push('reviewed=?'); params.push(reviewed==='1'?1:0); }

    const whereStr = where.join(' AND ');
    const offset   = (parseInt(page)-1) * parseInt(limit);

    const [[{total}]] = await pool.query(
      `SELECT COUNT(*) AS total FROM spam_detections WHERE ${whereStr}`, params
    );

    const [rows] = await pool.query(`
      SELECT id, log_id, server, detected_at, mail_from, mail_to,
             subject, spam_type, confidence, detection_method,
             ai_explanation, pattern_matched, action_taken,
             alert_sent, reviewed, false_positive
      FROM spam_detections
      WHERE ${whereStr}
      ORDER BY detected_at DESC
      LIMIT ? OFFSET ?
    `, [...params, parseInt(limit), offset]);

    res.json({ success: true, data: rows, total, page: parseInt(page) });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// PUT /api/spam/detections/:id — mark reviewed / false positive
router.put('/detections/:id', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  const { reviewed, false_positive } = req.body;
  try {
    const pool = getSpamPool();
    await pool.query(
      `UPDATE spam_detections
       SET reviewed=?, false_positive=?
       WHERE id=?`,
      [reviewed?1:0, false_positive?1:0, req.params.id]
    );
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/spam/rules — custom rules
router.get('/rules', verifyToken, async (req, res) => {
  try {
    const [rows] = await getSpamPool().query(
      'SELECT * FROM spam_rules ORDER BY hit_count DESC'
    );
    res.json({ success: true, data: rows });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/spam/rules — add custom rule
router.post('/rules', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  const { rule_name, rule_type, pattern, spam_type, confidence } = req.body;
  if (!rule_name || !pattern) return res.status(400).json({ error: 'rule_name and pattern required' });
  try {
    const [r] = await getSpamPool().query(
      `INSERT INTO spam_rules (rule_name,rule_type,pattern,spam_type,confidence)
       VALUES (?,?,?,?,?)`,
      [rule_name, rule_type||'subject', pattern, spam_type||'spam', confidence||70]
    );
    res.json({ success: true, id: r.insertId });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/spam/test — test a message against rules
router.post('/test', verifyToken, async (req, res) => {
  const { subject, body, mail_from } = req.body;
  if (!subject && !body) return res.status(400).json({ error: 'subject or body required' });

  const SUBJECT_PATTERNS = [
    [/(?i)(urgent|action required).{0,20}(bank|account|payment)/i, 'phishing',  90],
    [/(?i)you.{0,10}(won|winner|prize|lottery)/i,                   'scam',      85],
    [/(?i)(bitcoin|crypto).{0,20}(profit|return|earn)/i,            'scam',      80],
    [/(?i)(verify|confirm|update).{0,20}(account|password)/i,       'phishing',  88],
    [/(?i)your.{0,10}account.{0,10}(suspended|blocked)/i,           'phishing',  87],
    [/(?i)(free|gift|reward).{0,20}(claim|click)/i,                 'spam',      75],
  ];

  const matches = [];
  const text = (subject + ' ' + body).toLowerCase();

  for (const [pattern, type, conf] of SUBJECT_PATTERNS) {
    if (pattern.test(text)) {
      matches.push({ pattern: pattern.toString(), type, confidence: conf });
    }
  }

  res.json({
    success:  true,
    input:    { subject, mail_from },
    matches,
    verdict:  matches.length > 0 ? 'SPAM' : 'CLEAN',
    max_confidence: matches.length > 0 ? Math.max(...matches.map(m=>m.confidence)) : 0,
  });
});

module.exports = router;
