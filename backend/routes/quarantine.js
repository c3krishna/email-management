const express = require('express');
const router = express.Router();
const { getPool } = require('../db');
const { requireRole } = require('../middleware/auth');
const { normalizeServer } = require('../mailServers');

const QUARANTINE_STATUSES = new Set(['quarantined', 'released', 'deleted', 'allowed']);

async function ensureQuarantineTable(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS email_quarantine (
      id              BIGINT AUTO_INCREMENT PRIMARY KEY,
      server          VARCHAR(20)  NOT NULL DEFAULT 'app',
      source_log_id   BIGINT NULL,
      queue_id        VARCHAR(128) NULL,
      mail_from       VARCHAR(255) NULL,
      mail_to         VARCHAR(255) NULL,
      subject         VARCHAR(500) NULL,
      classification  VARCHAR(64)  NULL,
      spam_score      DECIMAL(8,2) NULL,
      status          VARCHAR(32)  NOT NULL DEFAULT 'quarantined',
      reason          TEXT NULL,
      direction       VARCHAR(32)  NULL,
      relay_ip        VARCHAR(64)  NULL,
      dkim_result     VARCHAR(32)  NULL,
      spf_result      VARCHAR(32)  NULL,
      body_preview    TEXT NULL,
      action_by       VARCHAR(128) NULL,
      action_at       DATETIME NULL,
      action_note     VARCHAR(500) NULL,
      created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_q_status (status),
      INDEX idx_q_created (created_at),
      INDEX idx_q_from (mail_from),
      INDEX idx_q_source (source_log_id),
      INDEX idx_q_server (server)
    )
  `);
  try {
    await pool.query(`ALTER TABLE email_quarantine ADD COLUMN server VARCHAR(20) NOT NULL DEFAULT 'app' AFTER id`);
  } catch { /* already exists */ }
}

function classifyFromLog(row) {
  if (row.classification) return row.classification;
  const score = parseFloat(row.spam_score || 0);
  if (score > 10) return 'Spam';
  if (row.status === 'blocked' || row.status === 'rejected') return 'Policy';
  return 'Other';
}

function shouldQuarantine(row, thresholds) {
  const qThresh = parseFloat(thresholds.quarantine_threshold || 10);
  const score = parseFloat(row.spam_score || 0);
  return (
    row.status === 'rejected' ||
    row.status === 'blocked' ||
    ['Spam', 'Phishing', 'Malware'].includes(row.classification) ||
    score >= qThresh
  );
}

async function loadThresholds(pool) {
  try {
    const [rows] = await pool.query(
      `SELECT setting_key, setting_value FROM app_settings
       WHERE setting_key IN ('quarantine_threshold','spam_threshold','block_threshold')`
    );
    const map = {};
    for (const r of rows) map[r.setting_key] = r.setting_value;
    return map;
  } catch {
    return {};
  }
}

// GET /api/quarantine — list quarantine items
router.get('/', async (req, res) => {
  try {
    const server = req.query.server || 'app';
    const pool = getPool(server);
    await ensureQuarantineTable(pool);

    const status = req.query.status || 'quarantined';
    const search = (req.query.search || '').trim();
    const limit = Math.min(parseInt(req.query.limit, 10) || 200, 500);
    const offset = parseInt(req.query.offset, 10) || 0;

    const where = [];
    const params = [];
    if (status !== 'all') {
      where.push('status = ?');
      params.push(status);
    }
    if (search) {
      where.push('(mail_from LIKE ? OR mail_to LIKE ? OR subject LIKE ? OR reason LIKE ?)');
      const q = `%${search}%`;
      params.push(q, q, q, q);
    }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) AS total FROM email_quarantine ${whereSql}`,
      params
    );
    const [rows] = await pool.query(
      `SELECT * FROM email_quarantine ${whereSql}
       ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    const [statsRows] = await pool.query(`
      SELECT
        SUM(CASE WHEN status='quarantined' THEN 1 ELSE 0 END) AS quarantined,
        SUM(CASE WHEN status='released' THEN 1 ELSE 0 END) AS released,
        SUM(CASE WHEN status='deleted' THEN 1 ELSE 0 END) AS deleted,
        SUM(CASE WHEN status='allowed' THEN 1 ELSE 0 END) AS allowed,
        SUM(CASE WHEN classification='Spam' OR (spam_score IS NOT NULL AND spam_score >= 8) THEN 1 ELSE 0 END) AS spam,
        SUM(CASE WHEN classification='Phishing' THEN 1 ELSE 0 END) AS phishing,
        SUM(CASE WHEN classification='Malware' THEN 1 ELSE 0 END) AS malware
      FROM email_quarantine
      WHERE status='quarantined' OR created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    `);

    res.json({
      success: true,
      data: rows,
      total,
      stats: {
        total: Number(statsRows[0]?.quarantined || 0),
        spam: Number(statsRows[0]?.spam || 0),
        phishing: Number(statsRows[0]?.phishing || 0),
        malware: Number(statsRows[0]?.malware || 0),
        blocked: Number(statsRows[0]?.quarantined || 0),
        released: Number(statsRows[0]?.released || 0),
        deleted: Number(statsRows[0]?.deleted || 0),
        allowed: Number(statsRows[0]?.allowed || 0),
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/quarantine/sync — import matching realtime logs into quarantine
router.post('/sync', requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    const server = req.query.server || req.body.server || 'app';
    const pool = getPool(server);
    await ensureQuarantineTable(pool);
    const thresholds = await loadThresholds(pool);

    const [logs] = await pool.query(`
      SELECT id, queue_id, mail_from, mail_to, subject, classification, spam_score,
             status, reason, direction, relay_ip, dkim_result, spf_result, log_datetime
      FROM email_log_realtime
      ORDER BY id DESC
      LIMIT 500
    `).catch(() => [[]]);

    let imported = 0;
    for (const row of logs) {
      if (!shouldQuarantine(row, thresholds)) continue;
      const [existing] = await pool.query(
        `SELECT id FROM email_quarantine
         WHERE (source_log_id = ?) OR (queue_id IS NOT NULL AND queue_id = ? AND mail_from = ?)
         LIMIT 1`,
        [row.id, row.queue_id || '', row.mail_from || '']
      );
      if (existing.length) continue;

      await pool.query(
        `INSERT INTO email_quarantine
          (server, source_log_id, queue_id, mail_from, mail_to, subject, classification, spam_score,
           status, reason, direction, relay_ip, dkim_result, spf_result, created_at)
         VALUES (?,?,?,?,?,?,?,?,'quarantined',?,?,?,?,?, COALESCE(?, NOW()))`,
        [
          normalizeServer(server, 'app') === 'all' ? 'app' : normalizeServer(server, 'app'),
          row.id,
          row.queue_id || null,
          row.mail_from || null,
          row.mail_to || null,
          row.subject || null,
          classifyFromLog(row),
          row.spam_score != null ? row.spam_score : null,
          row.reason || null,
          row.direction || null,
          row.relay_ip || null,
          row.dkim_result || null,
          row.spf_result || null,
          row.log_datetime || null,
        ]
      );
      imported += 1;
    }

    res.json({ success: true, imported, scanned: logs.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/quarantine — manual / agent ingest of one or more items
router.post('/', async (req, res) => {
  try {
    const server = req.query.server || req.body.server || 'app';
    const pool = getPool(server);
    await ensureQuarantineTable(pool);

    const items = Array.isArray(req.body.items) ? req.body.items : [req.body];
    let inserted = 0;
    for (const item of items) {
      if (!item.mail_from && !item.mail_to && !item.subject) continue;
      await pool.query(
        `INSERT INTO email_quarantine
          (source_log_id, queue_id, mail_from, mail_to, subject, classification, spam_score,
           status, reason, direction, relay_ip, dkim_result, spf_result, body_preview)
         VALUES (?,?,?,?,?,?,?,'quarantined',?,?,?,?,?,?)`,
        [
          item.source_log_id || null,
          item.queue_id || null,
          item.mail_from || null,
          item.mail_to || null,
          item.subject || null,
          item.classification || 'Other',
          item.spam_score != null ? item.spam_score : null,
          item.reason || null,
          item.direction || null,
          item.relay_ip || null,
          item.dkim_result || null,
          item.spf_result || null,
          item.body_preview || null,
        ]
      );
      inserted += 1;
    }
    res.json({ success: true, inserted });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function applyAction(req, res, nextStatus) {
  try {
    const server = req.query.server || req.body.server || 'app';
    const pool = getPool(server);
    await ensureQuarantineTable(pool);

    const ids = req.body.ids || (req.params.id ? [req.params.id] : []);
    if (!ids.length) return res.status(400).json({ error: 'ids required' });
    if (!QUARANTINE_STATUSES.has(nextStatus)) {
      return res.status(400).json({ error: 'invalid status' });
    }

    const note = req.body.note || null;
    const actor = req.user?.email || req.user?.username || req.user?.id || 'system';

    const [result] = await pool.query(
      `UPDATE email_quarantine
       SET status=?, action_by=?, action_at=NOW(), action_note=?
       WHERE id IN (?) AND status='quarantined'`,
      [nextStatus, String(actor), note, ids]
    );

    // Allow-list sender when allowing
    if (nextStatus === 'allowed') {
      const [rows] = await pool.query(
        `SELECT DISTINCT mail_from, COALESCE(server, ?) AS server FROM email_quarantine WHERE id IN (?)`,
        [server === 'campaign' ? 'campaign' : 'app', ids]
      ).catch(async () => {
        const [r2] = await pool.query(
          `SELECT DISTINCT mail_from FROM email_quarantine WHERE id IN (?)`,
          [ids]
        );
        return [r2.map(x => ({ ...x, server }))];
      });
      for (const row of rows) {
        const from = row.mail_from;
        if (!from) continue;
        const value = from.includes('@') ? from.toLowerCase() : from;
        const type = from.includes('@') ? 'email' : 'domain';
        const ms = normalizeServer(row.server || server, 'app');
        try {
          const { getThreatPool } = require('../threatDb');
          const { ensureSpamWhitelistMailServer } = require('../mailServers');
          const tp = getThreatPool();
          await ensureSpamWhitelistMailServer(tp);
          await tp.query(
            `INSERT INTO spam_whitelist (type, value, mail_server, description, added_by, active)
             VALUES (?, ?, ?, 'Allowed from quarantine', ?, 1)
             ON DUPLICATE KEY UPDATE active=1, mail_server=VALUES(mail_server), description=VALUES(description)`,
            [type, value, ms === 'all' ? 'both' : ms, String(actor)]
          );
        } catch {
          // whitelist table may differ — non-fatal
        }
      }
    }

    res.json({
      success: true,
      status: nextStatus,
      affected: result.affectedRows,
      message: `${result.affectedRows} item(s) marked ${nextStatus}`,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

router.post('/release', requireRole('super_admin', 'admin'), (req, res) => applyAction(req, res, 'released'));
router.post('/delete', requireRole('super_admin', 'admin'), (req, res) => applyAction(req, res, 'deleted'));
router.post('/allow', requireRole('super_admin', 'admin'), (req, res) => applyAction(req, res, 'allowed'));

router.get('/:id', async (req, res) => {
  try {
    const server = req.query.server || 'app';
    const pool = getPool(server);
    await ensureQuarantineTable(pool);
    const [rows] = await pool.query(`SELECT * FROM email_quarantine WHERE id=?`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true, data: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
