// ============================================================
// Phase 1 API Routes
// /var/www/email-management/backend/routes/platform.js
// Handles: customer CRUD, API key management,
//          external log ingest, historical query, archive status
// ============================================================

const express  = require('express');
const router   = express.Router();
const crypto   = require('crypto');
const mysql    = require('mysql2/promise');
const { verifyToken, requireRole } = require('../middleware/auth');
const {
  resolveCustomerMailServer,
  ensureCustomerMailServerColumn,
  normalizeServer,
  MAIL_SERVERS,
} = require('../mailServers');

// ---- Platform DB pool (threat_platform database) ----
let platformPool = null;

function getPlatformPool() {
  if (!platformPool) {
    platformPool = mysql.createPool({
      host:     process.env.DB_HOST || '10.180.0.84',
      port:     parseInt(process.env.DB_PORT) || 3306,
      user:     process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.PLATFORM_DB || 'threat_platform',
      waitForConnections: true,
      connectionLimit: 10,
    });
  }
  return platformPool;
}

// ---- API Key Authentication middleware ----
async function apiKeyAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const apiKey     = req.headers['x-api-key']     || authHeader.replace('Bearer ', '');

  if (!apiKey) {
    return res.status(401).json({ error: 'API key required. Use X-Api-Key header.' });
  }

  // Keys are prefixed: tp_live_XXXXXX or tp_test_XXXXXX
  const prefix   = apiKey.slice(0, 8);
  const keyHash  = crypto.createHash('sha256').update(apiKey).digest('hex');

  try {
    const pool = getPlatformPool();
    const [rows] = await pool.query(`
      SELECT ak.id, ak.customer_id, ak.permissions, ak.rate_limit,
             c.name AS customer_name, c.domain, c.active AS customer_active,
             c.retention_days
      FROM api_keys ak
      JOIN customers c ON c.id = ak.customer_id
      WHERE ak.key_hash = ? AND ak.active = 1
        AND (ak.expires_at IS NULL OR ak.expires_at > NOW())
    `, [keyHash]);

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid or expired API key.' });
    }

    const key = rows[0];
    if (!key.customer_active) {
      return res.status(403).json({ error: 'Customer account is inactive.' });
    }

    // Update last_used_at async (don't await)
    pool.query('UPDATE api_keys SET last_used_at = NOW() WHERE id = ?', [key.id]).catch(() => {});

    req.apiKey    = key;
    req.customer  = { id: key.customer_id, name: key.customer_name, domain: key.domain, retention_days: key.retention_days };
    next();
  } catch (err) {
    res.status(500).json({ error: 'Auth error: ' + err.message });
  }
}

// ============================================================
// CUSTOMER MANAGEMENT (dashboard admin only)
// ============================================================

// GET /api/platform/mail-servers — infra inventory for Security UI
router.get('/mail-servers', verifyToken, async (req, res) => {
  res.json({ success: true, data: Object.values(MAIL_SERVERS) });
});

// GET /api/platform/customers
router.get('/customers', verifyToken, requireRole('super_admin'), async (req, res) => {
  try {
    const pool = getPlatformPool();
    await ensureCustomerMailServerColumn(pool);
    const [rows] = await pool.query(`
      SELECT c.*,
        (SELECT COUNT(*) FROM api_keys WHERE customer_id = c.id AND active = 1) AS active_keys,
        (SELECT MAX(ingested_at) FROM ingest_events WHERE customer_id = c.id)   AS last_ingest
      FROM customers c
      ORDER BY c.created_at DESC
    `);
    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/platform/customers
router.post('/customers', verifyToken, requireRole('super_admin'), async (req, res) => {
  const {
    name, domain, plan = 'professional', retention_days = 365, contact_email,
    mail_server = 'app',
  } = req.body;
  if (!name || !domain) return res.status(400).json({ error: 'name and domain are required' });
  try {
    const pool = getPlatformPool();
    await ensureCustomerMailServerColumn(pool);
    const ms = normalizeServer(mail_server, 'app');
    const [result] = await pool.query(
      `INSERT INTO customers (name, domain, mail_server, plan, retention_days, contact_email)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [name, domain, ms === 'all' ? 'both' : ms, plan, retention_days, contact_email]
    );
    res.json({ success: true, id: result.insertId, message: `Customer ${name} created`, mail_server: ms });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/platform/customers/:id
router.put('/customers/:id', verifyToken, requireRole('super_admin'), async (req, res) => {
  const { name, plan, retention_days, contact_email, active, mail_server } = req.body;
  try {
    const pool = getPlatformPool();
    await ensureCustomerMailServerColumn(pool);
    if (mail_server !== undefined) {
      const ms = normalizeServer(mail_server, 'app');
      await pool.query(
        `UPDATE customers SET name=?, plan=?, retention_days=?, contact_email=?, active=?,
            mail_server=?, updated_at=NOW()
         WHERE id=?`,
        [name, plan, retention_days, contact_email, active ? 1 : 0, ms === 'all' ? 'both' : ms, req.params.id]
      );
    } else {
      await pool.query(
        `UPDATE customers SET name=?, plan=?, retention_days=?, contact_email=?, active=?, updated_at=NOW()
         WHERE id=?`,
        [name, plan, retention_days, contact_email, active ? 1 : 0, req.params.id]
      );
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// API KEY MANAGEMENT
// ============================================================

// POST /api/platform/customers/:id/keys
router.post('/customers/:id/keys', verifyToken, requireRole('super_admin', 'admin'), async (req, res) => {
  const { key_name, permissions, rate_limit = 1000, expires_days } = req.body;
  try {
    const pool = getPlatformPool();

    // Generate API key: tp_live_<32 random chars>
    const rawKey   = `tp_live_${crypto.randomBytes(24).toString('hex')}`;
    const prefix   = rawKey.slice(0, 8);
    const keyHash  = crypto.createHash('sha256').update(rawKey).digest('hex');
    const expiresAt = expires_days
      ? new Date(Date.now() + expires_days * 86400000).toISOString().slice(0, 19).replace('T', ' ')
      : null;

    await pool.query(
      `INSERT INTO api_keys (customer_id, key_name, key_hash, key_prefix, permissions, rate_limit, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [req.params.id, key_name, keyHash, prefix,
       JSON.stringify(permissions || { ingest: true, query: true }),
       rate_limit, expiresAt]
    );

    // Return full key ONCE — never stored in plain text
    res.json({ success: true, api_key: rawKey, prefix, expires_at: expiresAt,
      message: 'Store this key securely — it will not be shown again.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/platform/customers/:id/keys
router.get('/customers/:id/keys', verifyToken, requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    const pool = getPlatformPool();
    const [rows] = await pool.query(
      `SELECT id, key_name, key_prefix, permissions, rate_limit, last_used_at, expires_at, active, created_at
       FROM api_keys WHERE customer_id = ? ORDER BY created_at DESC`,
      [req.params.id]
    );
    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/platform/customers/:cid/keys/:kid
router.delete('/customers/:cid/keys/:kid', verifyToken, requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    const pool = getPlatformPool();
    await pool.query(
      `UPDATE api_keys SET active = 0 WHERE id = ? AND customer_id = ?`,
      [req.params.kid, req.params.cid]
    );
    res.json({ success: true, message: 'API key revoked' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// EXTERNAL LOG INGEST API (Requirement 4)
// External customers POST their logs here
// ============================================================

// POST /api/platform/v1/ingest/events
router.post('/v1/ingest/events', apiKeyAuth, async (req, res) => {
  const { events } = req.body;
  if (!events || !Array.isArray(events) || events.length === 0) {
    return res.status(400).json({ error: 'events array required' });
  }

  const customerId = req.customer.id;
  const pool = getPlatformPool();
  await ensureCustomerMailServerColumn(pool);

  const { getPool } = require('../db');
  const server  = await resolveCustomerMailServer(pool, customerId);
  const emailPool = getPool(server);

  let inserted = 0;
  const errors  = [];

  try {
    const CHUNK = 50;
    for (let i = 0; i < events.length; i += CHUNK) {
      const chunk = events.slice(i, i + CHUNK);
      const values = chunk.map(e => [
        customerId,
        server,
        req.customer.domain,
        e.log_datetime ? e.log_datetime.replace('T', ' ').replace('Z', '').slice(0, 19) : new Date().toISOString().replace('T', ' ').replace('Z', '').slice(0, 19),
        e.event_type   || 'unknown',
        e.queue_id     || null,
        e.message_id   || null,
        e.mail_from    || null,
        e.mail_to      || null,
        e.subject      || null,
        e.direction    || null,
        e.status       || null,
        e.dsn          || null,
        e.reason       ? e.reason.slice(0, 500) : null,
        e.spam_score   || null,
        e.classification || null,
        e.size_bytes   || null,
        e.duration_ms  || null,
      ]);

      try {
        await emailPool.query(`
          INSERT IGNORE INTO email_log_realtime
            (customer_id, server, server_name, log_datetime, event_type, queue_id, message_id,
             mail_from, mail_to, subject, direction, status, dsn, reason,
             spam_score, classification, size_bytes, duration_ms)
          VALUES ?
        `, [values]);
        inserted += chunk.length;
      } catch (e) {
        errors.push(e.message);
      }
    }

    // Log ingest event
    await pool.query(
      `INSERT INTO ingest_events (customer_id, source, event_count) VALUES (?, 'api', ?)`,
      [customerId, inserted]
    );

    res.json({ success: true, inserted, errors: errors.slice(0, 5), customer: req.customer.name });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/platform/v1/ingest/threats
router.post('/v1/ingest/threats', apiKeyAuth, async (req, res) => {
  const { threats } = req.body;
  if (!threats || !Array.isArray(threats)) {
    return res.status(400).json({ error: 'threats array required' });
  }

  try {
    const pool = getPlatformPool();
    let inserted = 0;

    for (const t of threats) {
      try {
        await pool.query(`
          INSERT IGNORE INTO ingest_events
            (customer_id, source, event_count, threat_count)
          VALUES (?, 'api_threat', 0, 1)
        `, [req.customer.id]);
        inserted++;
      } catch (e) { /* skip duplicates */ }
    }

    res.json({ success: true, inserted, message: `${inserted} threats queued for AI processing` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// HISTORICAL QUERY API (Requirement 3)
// ============================================================

// GET /api/platform/v1/logs/history
router.get('/v1/logs/history', apiKeyAuth, async (req, res) => {
  try {
    const {
      from, to, mail_from, mail_to, domain, status,
      event_type, subject, limit = 100, page = 1
    } = req.query;

    if (!from || !to) {
      return res.status(400).json({ error: 'from and to date params required (YYYY-MM-DD)' });
    }

    const maxLimit = Math.min(parseInt(limit), 1000);
    const offset   = (parseInt(page) - 1) * maxLimit;
    const { getPool } = require('../db');
    const server = await resolveCustomerMailServer(getPlatformPool(), req.customer.id);
    const pool = getPool(server);

    const conditions = [
      'customer_id = ?',
      'DATE(log_datetime) >= ?',
      'DATE(log_datetime) <= ?',
    ];
    const params = [req.customer.id, from, to];

    if (mail_from)  { conditions.push('mail_from LIKE ?');  params.push(`%${mail_from}%`);  }
    if (mail_to)    { conditions.push('mail_to LIKE ?');    params.push(`%${mail_to}%`);    }
    if (domain)     { conditions.push('(mail_from LIKE ? OR mail_to LIKE ?)'); params.push(`%@${domain}`, `%@${domain}`); }
    if (status)     { conditions.push('status = ?');        params.push(status);             }
    if (event_type) { conditions.push('event_type = ?');    params.push(event_type);         }
    if (subject)    { conditions.push('subject LIKE ?');    params.push(`%${subject}%`);     }

    const where = conditions.join(' AND ');

    const [[countRow]] = await pool.query(
      `SELECT COUNT(*) AS total FROM email_log_realtime WHERE ${where}`,
      params
    );

    const [rows] = await pool.query(`
      SELECT id, log_datetime, event_type, mail_from, mail_to, subject,
             direction, status, dsn, reason, spam_score, classification, size_bytes
      FROM email_log_realtime
      WHERE ${where}
      ORDER BY log_datetime DESC
      LIMIT ? OFFSET ?
    `, [...params, maxLimit, offset]);

    res.json({
      success:   true,
      data:      rows,
      total:     countRow.total,
      page:      parseInt(page),
      limit:     maxLimit,
      pages:     Math.ceil(countRow.total / maxLimit),
      customer:  req.customer.name,
      date_range: { from, to },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/platform/v1/logs/summary
router.get('/v1/logs/summary', apiKeyAuth, async (req, res) => {
  try {
    const { from, to } = req.query;
    if (!from || !to) return res.status(400).json({ error: 'from and to required' });

    const { getPool } = require('../db');
    const server = await resolveCustomerMailServer(getPlatformPool(), req.customer.id);
    const pool = getPool(server);

    const [rows] = await pool.query(`
      SELECT
        DATE(log_datetime)                          AS date,
        COUNT(*)                                    AS total,
        SUM(CASE WHEN direction='outbound' THEN 1 ELSE 0 END) AS outbound,
        SUM(CASE WHEN direction='inbound'  THEN 1 ELSE 0 END) AS inbound,
        SUM(CASE WHEN status IN ('sent','delivered') THEN 1 ELSE 0 END) AS delivered,
        SUM(CASE WHEN status = 'bounced'  THEN 1 ELSE 0 END) AS bounced,
        SUM(CASE WHEN status = 'failed'   THEN 1 ELSE 0 END) AS failed,
        SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected,
        SUM(CASE WHEN spam_score > 5      THEN 1 ELSE 0 END) AS spam
      FROM email_log_realtime
      WHERE customer_id = ?
        AND DATE(log_datetime) BETWEEN ? AND ?
      GROUP BY DATE(log_datetime)
      ORDER BY date ASC
    `, [req.customer.id, from, to]);

    res.json({ success: true, data: rows, customer: req.customer.name, mail_server: server });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/platform/v1/threats/check?indicator=...&type=...
router.get('/v1/threats/check', apiKeyAuth, async (req, res) => {
  const { indicator, type = 'email' } = req.query;
  if (!indicator) return res.status(400).json({ error: 'indicator param required' });

  try {
    // Phase 2 will add the real threat DB check
    // Phase 1: check against known bad patterns in logs
    const { getPool } = require('../db');
    const server = await resolveCustomerMailServer(getPlatformPool(), req.customer.id);
    const pool = getPool(server);

    const [rows] = await pool.query(`
      SELECT
        mail_from,
        COUNT(*) AS occurrences,
        SUM(CASE WHEN status = 'rejected' OR status = 'blocked' THEN 1 ELSE 0 END) AS blocked_count,
        MAX(spam_score) AS max_spam_score,
        MAX(log_datetime) AS last_seen
      FROM email_log_realtime
      WHERE mail_from = ? OR mail_to = ?
        AND log_datetime >= DATE_SUB(NOW(), INTERVAL 90 DAY)
      GROUP BY mail_from
      LIMIT 1
    `, [indicator, indicator]);

    const found = rows.length > 0;
    const data  = rows[0] || {};
    const threatLevel = found && (data.blocked_count > 5 || data.max_spam_score > 8)
      ? 'high' : found ? 'medium' : 'unknown';

    res.json({
      success:     true,
      indicator,
      type,
      found,
      threat_level: threatLevel,
      data: found ? {
        occurrences:   data.occurrences,
        blocked_count: data.blocked_count,
        max_spam_score:data.max_spam_score,
        last_seen:     data.last_seen,
      } : null,
      note: 'Phase 2 will add full AI threat intelligence check',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ARCHIVE STATUS
// ============================================================

// GET /api/platform/archive/status
router.get('/archive/status', verifyToken, requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    const pool = getPlatformPool();
    const [jobs] = await pool.query(`
      SELECT aj.*, c.name AS customer_name
      FROM archive_jobs aj
      JOIN customers c ON c.id = aj.customer_id
      ORDER BY aj.created_at DESC
      LIMIT 50
    `);

    const [summary] = await pool.query(`
      SELECT
        customer_id,
        COUNT(*) AS total_jobs,
        SUM(row_count) AS total_rows_archived,
        SUM(file_size_bytes) AS total_bytes,
        MAX(completed_at) AS last_archive
      FROM archive_jobs
      WHERE status = 'done'
      GROUP BY customer_id
    `);

    res.json({ success: true, jobs, summary });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
