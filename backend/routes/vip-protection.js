// ============================================================
// VIP Contacts + Anomaly/Impersonation Alerts API
// ============================================================

const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');
const { verifyToken, requireRole } = require('../middleware/auth');
const {
  ensureVipTables,
  detectVipImpersonation,
  detectSenderAnomaly,
} = require('../vipDetect');

let pool = null;
function getPool() {
  if (!pool) pool = mysql.createPool({
    host: process.env.DB_HOST || '10.180.0.84', user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'threat_platform', waitForConnections: true, connectionLimit: 10,
  });
  return pool;
}

ensureVipTables(getPool()).catch(e => console.warn('[vip] schema:', e.message));

router.get('/vip-contacts', verifyToken, async (req, res) => {
  try {
    const { customer_id } = req.query;
    const p = getPool();
    await ensureVipTables(p);
    const [rows] = await p.query(
      'SELECT * FROM vip_contacts WHERE customer_id=? ORDER BY display_name', [customer_id]
    );
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/vip-contacts', verifyToken, requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    const { customer_id, display_name, real_email, title } = req.body;
    if (!customer_id || !display_name || !real_email) {
      return res.status(400).json({ error: 'customer_id, display_name, real_email required' });
    }
    await ensureVipTables(getPool());
    const [r] = await getPool().query(
      'INSERT INTO vip_contacts (customer_id, display_name, real_email, title) VALUES (?,?,?,?)',
      [customer_id, display_name, real_email, title || null]
    );
    res.json({ success: true, id: r.insertId });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete('/vip-contacts/:id', verifyToken, requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    await getPool().query('UPDATE vip_contacts SET active=0 WHERE id=?', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/impersonation-alerts', verifyToken, async (req, res) => {
  try {
    const { customer_id, hours = 168, limit = 100 } = req.query;
    const p = getPool();
    await ensureVipTables(p);
    const [rows] = await p.query(`
      SELECT * FROM impersonation_alerts
      WHERE customer_id=? AND detected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
      ORDER BY detected_at DESC LIMIT ?
    `, [customer_id, parseInt(hours), parseInt(limit)]);
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/anomaly-alerts', verifyToken, async (req, res) => {
  try {
    const { customer_id, hours = 168, limit = 100 } = req.query;
    const p = getPool();
    await ensureVipTables(p);
    const [rows] = await p.query(`
      SELECT * FROM sender_anomaly_alerts
      WHERE customer_id=? AND detected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
      ORDER BY detected_at DESC LIMIT ?
    `, [customer_id, parseInt(hours), parseInt(limit)]);
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/protection-summary', verifyToken, async (req, res) => {
  try {
    const { customer_id, hours = 168 } = req.query;
    const p = getPool();
    await ensureVipTables(p);

    const [[vipCount]] = await p.query(
      'SELECT COUNT(*) AS total FROM vip_contacts WHERE customer_id=? AND active=1', [customer_id]
    ).catch(() => [[{ total: 0 }]]);

    const [[impersonation]] = await p.query(`
      SELECT COUNT(*) AS total FROM impersonation_alerts
      WHERE customer_id=? AND detected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
    `, [customer_id, parseInt(hours)]).catch(() => [[{ total: 0 }]]);

    const [[anomalies]] = await p.query(`
      SELECT COUNT(*) AS total FROM sender_anomaly_alerts
      WHERE customer_id=? AND detected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
    `, [customer_id, parseInt(hours)]).catch(() => [[{ total: 0 }]]);

    res.json({
      success: true,
      data: {
        vip_contacts_registered: vipCount?.total || 0,
        impersonation_attempts: impersonation?.total || 0,
        behavioral_anomalies: anomalies?.total || 0,
      }
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/**
 * POST /api/protection/detect
 * Body: { customer_id?, mail_from, mail_to?, subject?, display_name?, mail_server? }
 * Auth: JWT (via parent middleware) OR X-Agent-Secret
 */
router.post('/detect', async (req, res) => {
  const agentSecret = req.headers['x-agent-secret'];
  const expected = process.env.AGENT_SECRET;
  const isAgent = expected && agentSecret === expected;
  if (!isAgent && !req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const {
      customer_id, mail_from, mail_to, subject, display_name, mail_server = 'app',
    } = req.body || {};
    if (!mail_from) return res.status(400).json({ error: 'mail_from required' });

    const p = getPool();
    const vip = await detectVipImpersonation(p, {
      customer_id: customer_id || null,
      mail_from, mail_to, subject, display_name, mail_server,
    });
    let anomaly = { alerts: [] };
    if (customer_id) {
      anomaly = await detectSenderAnomaly(p, {
        customer_id, mail_from, mail_to, subject, mail_server,
      });
    }
    res.json({
      success: true,
      impersonation: vip.alerts,
      anomalies: anomaly.alerts,
      matched: vip.alerts.length > 0 || anomaly.alerts.length > 0,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.patch('/impersonation-alerts/:id/review', verifyToken, requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    try {
      await getPool().query('UPDATE impersonation_alerts SET reviewed=1 WHERE id=?', [req.params.id]);
    } catch {
      await getPool().query(
        'UPDATE impersonation_alerts SET status=? WHERE id=?',
        [req.body.status || 'reviewed', req.params.id]
      );
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.patch('/anomaly-alerts/:id/review', verifyToken, requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    try {
      await getPool().query('UPDATE sender_anomaly_alerts SET reviewed=1 WHERE id=?', [req.params.id]);
    } catch {
      await getPool().query(
        'UPDATE sender_anomaly_alerts SET status=? WHERE id=?',
        [req.body.status || 'reviewed', req.params.id]
      );
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;
