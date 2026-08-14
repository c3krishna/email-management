// ============================================================
// Spam Detection API
// /var/www/email-management/backend/routes/spam.js
// ============================================================

const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');
const { verifyToken, requireRole } = require('../middleware/auth');
const {
  normalizeServer,
  serverFilter,
  ensureSpamWhitelistMailServer,
} = require('../mailServers');

let spamPool = null;
function getSpamPool() {
  if (!spamPool) {
    spamPool = mysql.createPool({
      host:     process.env.DB_HOST || '10.180.0.84',
      user:     process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.PLATFORM_DB || 'threat_platform',
      waitForConnections: true,
      connectionLimit: 10,
    });
  }
  return spamPool;
}

// Agent secret auth
function agentAuth(req, res, next) {
  if (!process.env.AGENT_SECRET) {
    return res.status(500).json({ error: 'Server misconfigured: AGENT_SECRET is not set' });
  }
  if (req.headers['x-agent-secret'] !== process.env.AGENT_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// POST /api/spam/notification — from spam_milter.py / spam_detector / mailbox_monitor
router.post('/notification', agentAuth, async (req, res) => {
  try {
    const pool = getSpamPool();
    const server = normalizeServer(
      req.body.server || req.headers['x-agent-server'] || 'app',
      'app'
    );
    const detectionMethod = req.body.detection_method || req.body.method || 'pattern';
    const explanation = req.body.ai_explanation || req.body.reason || req.body.explanation || null;
    const [insertResult] = await pool.query(`
      INSERT INTO spam_detections
        (log_id, server, mail_from, mail_to, subject, spam_type,
         confidence, detection_method, ai_explanation, pattern_matched, action_taken)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)
      ON DUPLICATE KEY UPDATE confidence=VALUES(confidence), action_taken=VALUES(action_taken)
    `, [
      req.body.log_id || null,
      server === 'all' ? 'app' : server,
      req.body.mail_from, req.body.mail_to,
      req.body.subject, req.body.spam_type || 'spam',
      req.body.confidence || 0, detectionMethod,
      explanation, req.body.pattern_matched || null,
      req.body.action_taken || req.body.action || null,
    ]);

    // Optional: notify additional emails (mailbox monitor / customer IT)
    let notified = [];
    const conf = Number(req.body.confidence || 0);
    let recipients = [];
    if (Array.isArray(req.body.notify_emails)) {
      recipients = req.body.notify_emails.filter(e => e && String(e).includes('@'));
    } else if (typeof req.body.notify_emails === 'string' && req.body.notify_emails.includes('@')) {
      recipients = req.body.notify_emails.split(/[,;\s]+/).filter(e => e.includes('@'));
    }
    if (req.body.customer_id) {
      try {
        const [[settings]] = await pool.query(
          'SELECT admin_emails, notify_admin, active, min_confidence FROM notification_settings WHERE customer_id=?',
          [req.body.customer_id]
        );
        if (settings && settings.active && settings.notify_admin) {
          if (conf >= (settings.min_confidence || 70)) {
            let admins = [];
            try { admins = JSON.parse(settings.admin_emails || '[]'); } catch (_) {}
            recipients = [...new Set([...recipients, ...admins.filter(Boolean)])];
          }
        }
      } catch (_) { /* notification_settings may be empty */ }
    }

    if (recipients.length && process.env.SMTP_PASS) {
      try {
        const nodemailer = require('nodemailer');
        const transport = nodemailer.createTransport({
          host: process.env.SMTP_HOST || 'mail.worktual.tech',
          port: parseInt(process.env.SMTP_PORT || '587'),
          auth: {
            user: process.env.SMTP_USER || 'security@worktual.tech',
            pass: process.env.SMTP_PASS,
          },
        });
        const subject = `[Security Alert] ${req.body.spam_type || 'threat'} · ${(req.body.subject || '').slice(0, 60)}`;
        const html = `
          <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
            <h2 style="color:#dc2626">🚨 ${(req.body.spam_type || 'Threat').toUpperCase()} detected</h2>
            <p><b>From:</b> ${req.body.mail_from || '—'}<br>
               <b>To:</b> ${req.body.mail_to || '—'}<br>
               <b>Subject:</b> ${req.body.subject || '—'}<br>
               <b>Confidence:</b> ${conf}%<br>
               <b>Reason:</b> ${explanation || detectionMethod}</p>
          </div>`;
        for (const to of recipients) {
          await transport.sendMail({
            from: `"Worktual Security" <${process.env.SMTP_USER || 'security@worktual.tech'}>`,
            to, subject, html,
          });
          notified.push(to);
        }
        if (insertResult.insertId) {
          await pool.query('UPDATE spam_detections SET alert_sent=1 WHERE id=?', [insertResult.insertId]).catch(() => {});
        }
      } catch (mailErr) {
        console.warn('[spam/notification] email failed:', mailErr.message);
      }
    }

    res.json({ success: true, server, notified });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/spam/summary?server=app|campaign|all
router.get('/summary', verifyToken, async (req, res) => {
  try {
    const { hours = 24, server = 'all' } = req.query;
    const pool = getSpamPool();
    const sf = serverFilter('server', server, [parseInt(hours)]);
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
      WHERE detected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR) AND ${sf.sql}
    `, sf.params);

    const trendParams = [];
    const trendSf = serverFilter('server', server, trendParams);
    const [trend] = await pool.query(`
      SELECT DATE(detected_at) AS date, COUNT(*) AS total,
        SUM(CASE WHEN spam_type='phishing' THEN 1 ELSE 0 END) AS phishing,
        SUM(CASE WHEN spam_type='spam'     THEN 1 ELSE 0 END) AS spam,
        SUM(CASE WHEN spam_type='malware'  THEN 1 ELSE 0 END) AS malware,
        SUM(CASE WHEN spam_type='bec'      THEN 1 ELSE 0 END) AS bec
      FROM spam_detections
      WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) AND ${trendSf.sql}
      GROUP BY DATE(detected_at) ORDER BY date ASC
    `, trendSf.params);

    const topParams = [parseInt(hours)];
    const topSf = serverFilter('server', server, topParams);
    const [topSenders] = await pool.query(`
      SELECT mail_from, COUNT(*) AS count, MAX(spam_type) AS type, MAX(server) AS server
      FROM spam_detections
      WHERE detected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
        AND mail_from IS NOT NULL AND ${topSf.sql}
      GROUP BY mail_from ORDER BY count DESC LIMIT 10
    `, topSf.params);

    // Per-server split for Security panel
    const [byServer] = await pool.query(`
      SELECT server, COUNT(*) AS total
      FROM spam_detections
      WHERE detected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
      GROUP BY server
    `, [parseInt(hours)]);

    res.json({ success: true, data: { stats, trend, topSenders, byServer }, filter: { server, hours } });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/spam/detections
router.get('/detections', verifyToken, async (req, res) => {
  try {
    const { page=1, limit=50, spam_type, reviewed, hours=24, server='all' } = req.query;
    const pool   = getSpamPool();
    const where  = ['detected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)'];
    const params = [parseInt(hours)];
    const sf = serverFilter('server', server, params);
    where.push(sf.sql);
    if (spam_type) { where.push('spam_type=?');  params.push(spam_type); }
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
      FROM spam_detections WHERE ${whereStr}
      ORDER BY detected_at DESC LIMIT ? OFFSET ?
    `, [...params, parseInt(limit), offset]);
    res.json({ success: true, data: rows, total, page: parseInt(page), filter: { server } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PUT /api/spam/detections/:id
router.put('/detections/:id', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  const { reviewed, false_positive } = req.body;
  try {
    await getSpamPool().query(
      'UPDATE spam_detections SET reviewed=?, false_positive=? WHERE id=?',
      [reviewed?1:0, false_positive?1:0, req.params.id]
    );
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/spam/rules
router.get('/rules', verifyToken, async (req, res) => {
  try {
    const [rows] = await getSpamPool().query(
      'SELECT * FROM spam_rules ORDER BY hit_count DESC'
    );
    res.json({ success: true, data: rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/spam/rules
router.post('/rules', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  const { rule_name, rule_type, pattern, spam_type, confidence } = req.body;
  if (!rule_name || !pattern) return res.status(400).json({ error: 'rule_name and pattern required' });
  try {
    const [r] = await getSpamPool().query(
      'INSERT INTO spam_rules (rule_name,rule_type,pattern,spam_type,confidence) VALUES (?,?,?,?,?)',
      [rule_name, rule_type||'subject', pattern, spam_type||'spam', confidence||70]
    );
    res.json({ success: true, id: r.insertId });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/spam/test
router.post('/test', verifyToken, async (req, res) => {
  const { subject, body, mail_from } = req.body;
  if (!subject && !body) return res.status(400).json({ error: 'subject or body required' });
  const PATTERNS = [
   // [/(?i)(urgent|action required).{0,20}(bank|account|payment)/i, 'phishing',  90],
    [/you.{0,10}(won|winner|prize|lottery)/i,                       'scam',      85],
    [/(bitcoin|crypto).{0,20}(profit|return|earn)/i,                'scam',      80],
    [/(verify|confirm|update).{0,20}(account|password|login)/i,     'phishing',  88],
    [/your.{0,10}account.{0,10}(suspended|blocked)/i,               'phishing',  87],
    [/(free|gift|reward).{0,20}(claim|click|limited)/i,             'spam',      75],
    [/(wire|bank).{0,10}transfer.{0,30}(urgent|immediately)/i,      'bec',       85],
    [/(million|billion).{0,20}(dollar|usd).{0,20}transfer/i,        'scam',      92],
    [/(invoice|receipt).{0,10}(attached|enclosed)/i,                'malware',   65],
    [/credit card.{0,20}(number|cvv)/i,                             'phishing',  88],
  ];
  const text    = ((subject||'') + ' ' + (body||'')).toLowerCase();
  const matches = [];
  for (const [pattern, type, conf] of PATTERNS) {
    if (pattern.test(text)) matches.push({ pattern: pattern.toString(), type, confidence: conf });
  }
  res.json({
    success: true, input: { subject, mail_from },
    matches, verdict: matches.length > 0 ? 'SPAM' : 'CLEAN',
    max_confidence: matches.length > 0 ? Math.max(...matches.map(m=>m.confidence)) : 0,
  });
});


// GET /api/spam/whitelist?server=app|campaign|all
router.get('/whitelist', verifyToken, async (req, res) => {
  try {
    const pool = getSpamPool();
    await ensureSpamWhitelistMailServer(pool);
    const server = normalizeServer(req.query.server, 'all');
    let sql = 'SELECT * FROM spam_whitelist WHERE active=1';
    const params = [];
    if (server !== 'all') {
      sql += ` AND mail_server IN (?, 'both')`;
      params.push(server);
    }
    sql += ' ORDER BY type, value';
    const [rows] = await pool.query(sql, params);
    res.json({ success:true, data:rows });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// POST /api/spam/whitelist
router.post('/whitelist', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  const { type='domain', value, description, mail_server='both' } = req.body;
  if (!value) return res.status(400).json({ error:'value required' });
  try {
    const pool = getSpamPool();
    await ensureSpamWhitelistMailServer(pool);
    const ms = normalizeServer(mail_server, 'both');
    await pool.query(
      `INSERT INTO spam_whitelist (type,value,mail_server,description,added_by)
       VALUES (?,?,?,?,?)
       ON DUPLICATE KEY UPDATE active=1, description=VALUES(description), mail_server=VALUES(mail_server)`,
      [type, value.toLowerCase(), ms === 'all' ? 'both' : ms, description||null,
       req.user?.email||'admin']
    );
    res.json({ success:true, message:`${value} added to whitelist`, mail_server: ms });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// Agent: milter pulls whitelist for its AGENT_SERVER
router.get('/whitelist/for-agent', agentAuth, async (req, res) => {
  try {
    const pool = getSpamPool();
    await ensureSpamWhitelistMailServer(pool);
    const server = normalizeServer(req.query.server || req.headers['x-agent-server'], 'app');
    const [rows] = await pool.query(
      `SELECT type, value FROM spam_whitelist
       WHERE active=1 AND type IN ('domain','email')
         AND mail_server IN (?, 'both')`,
      [server === 'all' ? 'app' : server]
    );
    res.json({ success: true, server, data: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/spam/whitelist/:id
router.delete('/whitelist/:id', verifyToken, requireRole('super_admin','admin'), async (req,res) => {
  try {
    await getSpamPool().query(
      'UPDATE spam_whitelist SET active=0 WHERE id=?', [req.params.id]
    );
    res.json({ success:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

module.exports = router;
