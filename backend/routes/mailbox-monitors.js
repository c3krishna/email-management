// ============================================================
// Mailbox Monitor Configuration API
// Supports customer mailbox IMAP scan + notify_emails for alerts
// ============================================================

const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');
const { verifyToken, requireRole } = require('../middleware/auth');

let pool = null;
function getPool() {
  if (!pool) pool = mysql.createPool({
    host: process.env.DB_HOST || '10.180.0.84', user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'threat_platform', waitForConnections: true, connectionLimit: 10,
  });
  return pool;
}

async function ensureSchema() {
  const p = getPool();
  await p.query(`
    CREATE TABLE IF NOT EXISTS mailbox_monitors (
      id            INT AUTO_INCREMENT PRIMARY KEY,
      customer_id   INT NOT NULL,
      mail_server   ENUM('app','campaign','both') NOT NULL DEFAULT 'app',
      display_name  VARCHAR(255) DEFAULT NULL,
      imap_host     VARCHAR(255) NOT NULL,
      imap_port     INT DEFAULT 993,
      imap_user     VARCHAR(255) NOT NULL,
      imap_pass     TEXT NOT NULL,
      folder        VARCHAR(128) DEFAULT 'INBOX',
      use_ssl       TINYINT(1) DEFAULT 1,
      poll_interval INT DEFAULT 120,
      last_uid      VARCHAR(64) DEFAULT NULL,
      last_checked  DATETIME DEFAULT NULL,
      total_scanned INT DEFAULT 0,
      total_threats INT DEFAULT 0,
      notify_emails TEXT DEFAULT NULL COMMENT 'JSON array of alert recipient emails',
      active        TINYINT(1) DEFAULT 1,
      created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
      KEY idx_customer (customer_id),
      KEY idx_active (active)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);
  try {
    await p.query(`ALTER TABLE mailbox_monitors ADD COLUMN notify_emails TEXT DEFAULT NULL`);
  } catch (_) { /* column may already exist */ }
  try {
    await p.query(`
      ALTER TABLE mailbox_monitors
        ADD COLUMN mail_server ENUM('app','campaign','both') NOT NULL DEFAULT 'app'
        AFTER customer_id
    `);
  } catch (_) { /* may already exist */ }
}

ensureSchema().catch(e => console.warn('[mailbox-monitors] schema:', e.message));

function parseEmails(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw.map(e => String(e).trim()).filter(Boolean);
  if (typeof raw === 'string') {
    try {
      const j = JSON.parse(raw);
      if (Array.isArray(j)) return j.map(e => String(e).trim()).filter(Boolean);
    } catch (_) {}
    return raw.split(/[,;\s]+/).map(e => e.trim()).filter(e => e.includes('@'));
  }
  return [];
}

// GET /api/mailbox-monitors?customer_id=
router.get('/', verifyToken, async (req, res) => {
  try {
    const { customer_id } = req.query;
    const p = getPool();
    let sql = `SELECT mm.id, mm.customer_id, mm.mail_server, mm.display_name, mm.imap_host, mm.imap_port,
                      mm.imap_user, mm.folder, mm.poll_interval, mm.last_checked,
                      mm.total_scanned, mm.total_threats, mm.notify_emails, mm.active, mm.created_at,
                      c.name AS customer_name
               FROM mailbox_monitors mm
               JOIN customers c ON c.id = mm.customer_id`;
    const params = [];
    if (customer_id) { sql += ' WHERE mm.customer_id = ?'; params.push(customer_id); }
    if (req.query.server && req.query.server !== 'all') {
      sql += (params.length ? ' AND' : ' WHERE') + ` (mm.mail_server = ? OR mm.mail_server = 'both')`;
      params.push(req.query.server);
    }
    sql += ' ORDER BY mm.created_at DESC';
    const [rows] = await p.query(sql, params);
    rows.forEach(r => { r.notify_emails = parseEmails(r.notify_emails); });
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/mailbox-monitors — add new mailbox to monitor
router.post('/', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  const { customer_id, display_name, imap_host, imap_port = 993, imap_user,
          imap_pass, folder = 'INBOX', use_ssl = true, poll_interval = 120,
          notify_emails, mail_server = 'app' } = req.body;

  if (!customer_id || !imap_host || !imap_user || !imap_pass) {
    return res.status(400).json({ error: 'customer_id, imap_host, imap_user, imap_pass required' });
  }

  try {
    const p = getPool();
    const emails = parseEmails(notify_emails);
    const ms = ['app', 'campaign', 'both'].includes(mail_server) ? mail_server : 'app';
    const [r] = await p.query(`
      INSERT INTO mailbox_monitors
        (customer_id, mail_server, display_name, imap_host, imap_port, imap_user, imap_pass,
         folder, use_ssl, poll_interval, notify_emails)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)
    `, [
      customer_id, ms, display_name || imap_user, imap_host, imap_port, imap_user, imap_pass,
      folder, use_ssl ? 1 : 0, poll_interval, JSON.stringify(emails),
    ]);
    res.json({
      success: true,
      id: r.insertId,
      message: `Mailbox monitor configured — polling begins within ${poll_interval}s` +
        (emails.length ? `; alerts → ${emails.join(', ')}` : ''),
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/mailbox-monitors/:id/test — test IMAP connection
router.post('/:id/test', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  try {
    const p = getPool();
    const [[row]] = await p.query('SELECT * FROM mailbox_monitors WHERE id=?', [req.params.id]);
    if (!row) return res.status(404).json({ error: 'Not found' });

    const Imap = require('imap');
    const imap = new Imap({
      user: row.imap_user, password: row.imap_pass,
      host: row.imap_host, port: row.imap_port, tls: !!row.use_ssl,
      tlsOptions: { rejectUnauthorized: false },
      connTimeout: 10000,
    });

    const result = await new Promise((resolve) => {
      imap.once('ready', () => {
        imap.openBox(row.folder || 'INBOX', true, (err, box) => {
          imap.end();
          if (err) resolve({ success: false, message: err.message });
          else resolve({ success: true, message: `Connected — ${box.messages.total} messages in inbox` });
        });
      });
      imap.once('error', (err) => resolve({ success: false, message: err.message }));
      imap.connect();
    });

    res.json(result);
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// PUT /api/mailbox-monitors/:id — update / toggle active / notify emails
router.put('/:id', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  try {
    const { active, poll_interval, display_name, notify_emails } = req.body;
    const emailsJson = notify_emails !== undefined
      ? JSON.stringify(parseEmails(notify_emails))
      : null;
    await getPool().query(`
      UPDATE mailbox_monitors
      SET active=COALESCE(?,active), poll_interval=COALESCE(?,poll_interval),
          display_name=COALESCE(?,display_name),
          notify_emails=COALESCE(?,notify_emails)
      WHERE id=?
    `, [
      active !== undefined ? (active ? 1 : 0) : null,
      poll_interval || null,
      display_name || null,
      emailsJson,
      req.params.id,
    ]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/mailbox-monitors/:id
router.delete('/:id', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  try {
    await getPool().query('UPDATE mailbox_monitors SET active=0 WHERE id=?', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;
