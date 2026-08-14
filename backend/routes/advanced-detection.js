// ============================================================
// Advanced Detection API — surfaces attachment/QR/thread-hijack results
// /var/www/email-management/backend/routes/advanced-detection.js
// ============================================================

const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');
const { verifyToken } = require('../middleware/auth');

let pool = null;
function getPool() {
  if (!pool) pool = mysql.createPool({
    host: process.env.DB_HOST || '10.180.0.84', user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'threat_platform', waitForConnections: true, connectionLimit: 10,
  });
  return pool;
}

// GET /api/advanced-detection/thread-hijacks?customer_id=&hours=
router.get('/thread-hijacks', verifyToken, async (req, res) => {
  try {
    const { customer_id, hours = 168 } = req.query;
    const p = getPool();
    const where = ['detected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)'];
    const params = [parseInt(hours)];
    if (customer_id) { where.push('customer_id = ?'); params.push(customer_id); }

    const [rows] = await p.query(`
      SELECT * FROM thread_hijack_alerts
      WHERE ${where.join(' AND ')}
      ORDER BY detected_at DESC LIMIT 100
    `, params);
    res.json({ success: true, data: rows, count: rows.length });
  } catch (e) { res.json({ success: true, data: [], count: 0, note: 'thread_hijack_alerts table not yet created — run thread_tracker.py once' }); }
});

// PUT /api/advanced-detection/thread-hijacks/:id/review
router.put('/thread-hijacks/:id/review', verifyToken, async (req, res) => {
  try {
    await getPool().query('UPDATE thread_hijack_alerts SET reviewed=1 WHERE id=?', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/advanced-detection/summary?customer_id=&hours=
router.get('/summary', verifyToken, async (req, res) => {
  try {
    const { customer_id, hours = 168 } = req.query;
    const p = getPool();
    const custClause = customer_id ? 'AND customer_id = ?' : '';
    const custParam = customer_id ? [customer_id] : [];

    const [[hijacks]] = await p.query(`
      SELECT COUNT(*) AS total, SUM(CASE WHEN reviewed=0 THEN 1 ELSE 0 END) AS unreviewed
      FROM thread_hijack_alerts
      WHERE detected_at >= DATE_SUB(NOW(), INTERVAL ? HOUR) ${custClause}
    `, [parseInt(hours), ...custParam]).catch(() => [[{ total: 0, unreviewed: 0 }]]);

    // Attachment/QR threats surface via security_events with method containing markers
    const [[advDetections]] = await p.query(`
      SELECT
        SUM(CASE WHEN ai_explanation LIKE '%static_attachment_analysis%' OR ai_threat_type='malware' THEN 1 ELSE 0 END) AS attachment_threats,
        SUM(CASE WHEN ai_explanation LIKE '%qr%' OR ai_explanation LIKE '%QR%' THEN 1 ELSE 0 END) AS qr_threats
      FROM security_events
      WHERE platform='mailbox_monitor' AND event_datetime >= DATE_SUB(NOW(), INTERVAL ? HOUR) ${custClause}
    `, [parseInt(hours), ...custParam]).catch(() => [[{ attachment_threats: 0, qr_threats: 0 }]]);

    res.json({
      success: true,
      data: {
        thread_hijacks_total: hijacks?.total || 0,
        thread_hijacks_unreviewed: hijacks?.unreviewed || 0,
        attachment_threats: advDetections?.attachment_threats || 0,
        qr_threats: advDetections?.qr_threats || 0,
      }
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;
