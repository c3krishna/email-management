// ============================================================
// Phase 2 Threat Intelligence API
// /var/www/email-management/backend/routes/threats.js
// ============================================================

const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');
const { verifyToken, requireRole } = require('../middleware/auth');
const { normalizeServer, serverFilter } = require('../mailServers');

let threatPool = null;
function getThreatPool() {
  if (!threatPool) {
    threatPool = mysql.createPool({
      host:     process.env.DB_HOST || '10.180.0.84',
      port:     parseInt(process.env.DB_PORT) || 3306,
      user:     process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.PLATFORM_DB || 'threat_platform',
      waitForConnections: true,
      connectionLimit: 10,
    });
  }
  return threatPool;
}

async function ensureThreatServerColumn(pool) {
  try {
    await pool.query(`
      ALTER TABLE threat_indicators
        ADD COLUMN mail_server ENUM('app','campaign','both') NOT NULL DEFAULT 'both'
    `);
  } catch { /* exists */ }
}

// ---- Auth: allow both dashboard JWT and platform API key ----
async function flexAuth(req, res, next) {
  const jwt     = req.headers['authorization'];
  const apiKey  = req.headers['x-api-key'];

  if (jwt && jwt.startsWith('Bearer ')) {
    return verifyToken(req, res, next);
  }

  if (apiKey) {
    const crypto = require('crypto');
    const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
    try {
      const pool = getThreatPool();
      const [rows] = await pool.query(
        `SELECT ak.customer_id, c.name, c.domain
         FROM api_keys ak JOIN customers c ON c.id = ak.customer_id
         WHERE ak.key_hash = ? AND ak.active = 1
           AND (ak.expires_at IS NULL OR ak.expires_at > NOW())`,
        [keyHash]
      );
      if (rows.length === 0) return res.status(401).json({ error: 'Invalid API key' });
      req.customer = rows[0];
      req.user     = { role: 'api', id: rows[0].customer_id };
      return next();
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(401).json({ error: 'Authentication required' });
}

// ============================================================
// DASHBOARD: Threat Overview
// ============================================================

// GET /api/threats/summary
router.get('/summary', verifyToken, async (req, res) => {
  try {
    const pool = getThreatPool();
    await ensureThreatServerColumn(pool);
    const server = normalizeServer(req.query.server, 'all');
    const params = [];
    const sf = serverFilter('mail_server', server, params);
    // When filtering a specific infra, also include 'both'
    let whereSql = sf.sql;
    if (server !== 'all') {
      whereSql = `(mail_server = ? OR mail_server = 'both')`;
      params.length = 0;
      params.push(server);
    }

    const [[counts]] = await pool.query(`
      SELECT
        COUNT(*)                                                             AS total,
        SUM(CASE WHEN status = 'active'    THEN 1 ELSE 0 END)               AS active,
        SUM(CASE WHEN threat_type = 'spam' THEN 1 ELSE 0 END)               AS spam,
        SUM(CASE WHEN threat_type = 'phishing'  THEN 1 ELSE 0 END)          AS phishing,
        SUM(CASE WHEN threat_type = 'malware'   THEN 1 ELSE 0 END)          AS malware,
        SUM(CASE WHEN threat_type = 'bec'       THEN 1 ELSE 0 END)          AS bec,
        SUM(CASE WHEN threat_type = 'url_threat' THEN 1 ELSE 0 END)         AS url_threat,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END)              AS critical,
        SUM(CASE WHEN severity = 'high'     THEN 1 ELSE 0 END)              AS high,
        SUM(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                 THEN 1 ELSE 0 END)                                          AS last_24h,
        SUM(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                 THEN 1 ELSE 0 END)                                          AS last_7d
      FROM threat_indicators
      WHERE ${whereSql}
    `, params);

    const [[blocklist]] = await pool.query(`
      SELECT COUNT(*) AS total FROM postfix_blocklist WHERE active = 1
    `);

    const [[queue]] = await pool.query(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN status = 'pending'    THEN 1 ELSE 0 END) AS pending,
        SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END) AS processing
      FROM ai_analysis_queue
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    `);

    const [lastRun] = await pool.query(`
      SELECT started_at, completed_at, logs_scanned, new_indicators, status
      FROM ai_engine_runs ORDER BY id DESC LIMIT 1
    `);

    res.json({
      success: true,
      data: {
        indicators: counts,
        blocklist:  blocklist,
        queue:      queue,
        last_run:   lastRun[0] || null,
      },
      filter: { server },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/threats/indicators?type=&threat_type=&severity=&page=&limit=&server=
router.get('/indicators', verifyToken, async (req, res) => {
  try {
    const { type, threat_type, severity, status = 'active',
            search, page = 1, limit = 50, server = 'all' } = req.query;
    const pool = getThreatPool();
    await ensureThreatServerColumn(pool);

    const conditions = ['1=1'];
    const params     = [];
    const s = normalizeServer(server, 'all');
    if (s !== 'all') {
      conditions.push(`(mail_server = ? OR mail_server = 'both')`);
      params.push(s);
    }

    if (type)        { conditions.push('indicator_type = ?'); params.push(type); }
    if (threat_type) { conditions.push('threat_type = ?');    params.push(threat_type); }
    if (severity)    { conditions.push('severity = ?');       params.push(severity); }
    if (status)      { conditions.push('status = ?');         params.push(status); }
    if (search)      { conditions.push('indicator_value LIKE ?'); params.push(`%${search}%`); }

    const where  = conditions.join(' AND ');
    const offset = (parseInt(page) - 1) * parseInt(limit);

    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) AS total FROM threat_indicators WHERE ${where}`, params
    );

    const [rows] = await pool.query(`
      SELECT id, indicator_type, indicator_value, threat_type,
             confidence, severity, status, occurrence_count, customer_count,
             ai_explanation, first_seen_at, last_seen_at
      FROM threat_indicators
      WHERE ${where}
      ORDER BY confidence DESC, last_seen_at DESC
      LIMIT ? OFFSET ?
    `, [...params, parseInt(limit), offset]);

    res.json({ success: true, data: rows, total, page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/threats/trend?days=30
router.get('/trend', verifyToken, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const pool = getThreatPool();

    const [rows] = await pool.query(`
      SELECT
        DATE(created_at)                                      AS date,
        COUNT(*)                                              AS total,
        SUM(CASE WHEN threat_type = 'spam'       THEN 1 ELSE 0 END) AS spam,
        SUM(CASE WHEN threat_type = 'phishing'   THEN 1 ELSE 0 END) AS phishing,
        SUM(CASE WHEN threat_type = 'malware'    THEN 1 ELSE 0 END) AS malware,
        SUM(CASE WHEN threat_type = 'bec'        THEN 1 ELSE 0 END) AS bec,
        SUM(CASE WHEN threat_type = 'url_threat' THEN 1 ELSE 0 END) AS url_threat
      FROM threat_indicators
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
      GROUP BY DATE(created_at)
      ORDER BY date ASC
    `, [parseInt(days)]);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/threats/top?limit=10
router.get('/top', verifyToken, async (req, res) => {
  try {
    const { limit = 10, threat_type } = req.query;
    const pool = getThreatPool();

    let where = "status = 'active'";
    const params = [];
    if (threat_type) { where += ' AND threat_type = ?'; params.push(threat_type); }

    const [rows] = await pool.query(`
      SELECT indicator_type, indicator_value, threat_type,
             confidence, severity, occurrence_count, last_seen_at, ai_explanation
      FROM threat_indicators
      WHERE ${where}
      ORDER BY confidence DESC, occurrence_count DESC
      LIMIT ?
    `, [...params, parseInt(limit)]);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/threats/engine-status
router.get('/engine-status', verifyToken, async (req, res) => {
  try {
    const pool = getThreatPool();
    const [runs] = await pool.query(`
      SELECT * FROM ai_engine_runs ORDER BY id DESC LIMIT 10
    `);
    const [[queueStats]] = await pool.query(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN status='pending'    THEN 1 ELSE 0 END) AS pending,
        SUM(CASE WHEN status='done'       THEN 1 ELSE 0 END) AS done,
        SUM(CASE WHEN status='failed'     THEN 1 ELSE 0 END) AS failed
      FROM ai_analysis_queue
    `);
    res.json({ success: true, recent_runs: runs, queue: queueStats });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// EXTERNAL API: Threat intelligence endpoints
// ============================================================

// GET /api/threats/v1/check?indicator=&type=
router.get('/v1/check', flexAuth, async (req, res) => {
  try {
    const { indicator, type = 'email' } = req.query;
    if (!indicator) return res.status(400).json({ error: 'indicator required' });

    const pool = getThreatPool();
    const [rows] = await pool.query(`
      SELECT id, indicator_type, threat_type, confidence, severity,
             occurrence_count, customer_count, ai_explanation,
             first_seen_at, last_seen_at
      FROM threat_indicators
      WHERE indicator_value = ?
        AND (indicator_type = ? OR %s)
        AND status = 'active'
      LIMIT 1
    `.replace('%s', type === 'any' ? '1=1' : 'indicator_type = ?'),
    type === 'any' ? [indicator, type] : [indicator, type, type]);

    if (rows.length > 0) {
      const t = rows[0];
      return res.json({
        success:     true,
        found:       true,
        blocked:     t.confidence >= 70,
        indicator,
        threat_type: t.threat_type,
        confidence:  t.confidence,
        severity:    t.severity,
        occurrences: t.occurrence_count,
        explanation: t.ai_explanation,
        first_seen:  t.first_seen_at,
        last_seen:   t.last_seen_at,
      });
    }

    res.json({ success: true, found: false, blocked: false, indicator });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/threats/v1/feed?since=&limit=
router.get('/v1/feed', flexAuth, async (req, res) => {
  try {
    const { since, limit = 100, threat_type } = req.query;
    const pool  = getThreatPool();
    const lim   = Math.min(parseInt(limit), 1000);
    const where = ['1=1'];
    const params = [];

    if (since)       { where.push('published_at > ?');  params.push(since); }
    if (threat_type) { where.push('threat_type = ?');   params.push(threat_type); }

    const [rows] = await pool.query(`
      SELECT id, indicator_type, indicator_value, threat_type,
             confidence, severity, published_at, expires_at
      FROM threat_feed
      WHERE ${where.join(' AND ')}
      ORDER BY published_at DESC
      LIMIT ?
    `, [...params, lim]);

    res.json({
      success: true, data: rows, count: rows.length,
      generated_at: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/threats/v1/blocklist?format=postfix
router.get('/v1/blocklist', flexAuth, async (req, res) => {
  try {
    const { format = 'json', type } = req.query;
    const pool = getThreatPool();
    const where = ['active = 1', '(expires_at IS NULL OR expires_at > NOW())'];
    const params = [];
    if (type) { where.push('block_type = ?'); params.push(type); }

    const [rows] = await pool.query(`
      SELECT block_type, block_value, threat_type, confidence
      FROM postfix_blocklist
      WHERE ${where.join(' AND ')}
      ORDER BY confidence DESC
    `, params);

    if (format === 'postfix') {
      const lines = rows.map(r =>
        `${r.block_value}\t\tREJECT [Threat Intelligence] ${r.threat_type} (${r.confidence}%)`
      );
      res.set('Content-Type', 'text/plain');
      return res.send(lines.join('\n'));
    }

    res.json({ success: true, data: rows, count: rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/threats/v1/report — customer reports a new threat
router.post('/v1/report', flexAuth, async (req, res) => {
  try {
    const { indicator_type, indicator_value, threat_type, subject, reason } = req.body;
    if (!indicator_type || !indicator_value) {
      return res.status(400).json({ error: 'indicator_type and indicator_value required' });
    }

    const pool = getThreatPool();
    const customerId = req.customer?.id || req.user?.id || 1;

    // Queue for AI analysis
    await pool.query(`
      INSERT INTO ai_analysis_queue
        (log_id, customer_id, mail_from, subject, reason, status, priority)
      VALUES (0, ?, ?, ?, ?, 'pending', 1)
    `, [customerId, indicator_value, subject || null, reason || null]);

    // Optimistic insert with medium confidence (AI will refine)
    await pool.query(`
      INSERT INTO threat_indicators
        (indicator_type, indicator_value, threat_type, confidence, severity,
         source_customer_id, ai_analyzed)
      VALUES (?, ?, ?, 50, 'medium', ?, 0)
      ON DUPLICATE KEY UPDATE
        occurrence_count = occurrence_count + 1,
        last_seen_at = NOW(),
        confidence = LEAST(99, confidence + 3)
    `, [indicator_type, indicator_value, threat_type || 'unknown', customerId]);

    res.json({ success: true, message: 'Threat reported and queued for AI analysis' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/threats/indicators/:id — update status (false positive etc)
router.put('/indicators/:id', verifyToken, requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    const { status, notes } = req.body;
    const pool = getThreatPool();
    await pool.query(
      `UPDATE threat_indicators SET status = ?, ai_explanation = COALESCE(?, ai_explanation)
       WHERE id = ?`,
      [status, notes, req.params.id]
    );

    // If false positive, deactivate blocklist entry
    if (status === 'false_positive') {
      await pool.query(
        `UPDATE postfix_blocklist SET active = 0 WHERE indicator_id = ?`,
        [req.params.id]
      );
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
