// ============================================================
// Notification Settings API
// /var/www/email-management/backend/routes/notifications.js
// ============================================================

const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');
const { verifyToken, requireRole } = require('../middleware/auth');

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

// GET /api/notifications/settings/:customer_id
router.get('/settings/:customer_id', verifyToken, async (req, res) => {
  try {
    const [rows] = await getPool().query(
      'SELECT * FROM notification_settings WHERE customer_id=?',
      [req.params.customer_id]
    );
    if (!rows.length) {
      // Return defaults
      return res.json({ success:true, data:{
        customer_id:     parseInt(req.params.customer_id),
        notify_admin:    1,
        notify_end_user: 1,
        notify_ops_team: 0,
        admin_emails:    [],
        webhook_url:     null,
        slack_webhook:   null,
        teams_webhook:   null,
        min_severity:    'medium',
        min_confidence:  70,
        rate_limit_hour: 20,
        notify_blocked:  1,
        notify_spam:     1,
        active:          1,
      }});
    }
    const row = rows[0];
    if (typeof row.admin_emails === 'string') {
      try { row.admin_emails = JSON.parse(row.admin_emails); } catch(e) {}
    }
    res.json({ success:true, data:row });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// POST /api/notifications/settings — save settings
router.post('/settings', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  const {
    customer_id, notify_admin, notify_end_user, notify_ops_team,
    admin_emails, webhook_url, slack_webhook, teams_webhook,
    min_severity, min_confidence, rate_limit_hour,
    notify_blocked, notify_spam, active,
  } = req.body;

  if (!customer_id) return res.status(400).json({ error:'customer_id required' });

  try {
    await getPool().query(`
      INSERT INTO notification_settings
        (customer_id, notify_admin, notify_end_user, notify_ops_team,
         admin_emails, webhook_url, slack_webhook, teams_webhook,
         min_severity, min_confidence, rate_limit_hour,
         notify_blocked, notify_spam, active)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON DUPLICATE KEY UPDATE
        notify_admin     = VALUES(notify_admin),
        notify_end_user  = VALUES(notify_end_user),
        notify_ops_team  = VALUES(notify_ops_team),
        admin_emails     = VALUES(admin_emails),
        webhook_url      = VALUES(webhook_url),
        slack_webhook    = VALUES(slack_webhook),
        teams_webhook    = VALUES(teams_webhook),
        min_severity     = VALUES(min_severity),
        min_confidence   = VALUES(min_confidence),
        rate_limit_hour  = VALUES(rate_limit_hour),
        notify_blocked   = VALUES(notify_blocked),
        notify_spam      = VALUES(notify_spam),
        active           = VALUES(active)
    `, [
      customer_id,
      notify_admin    ? 1 : 0,
      notify_end_user ? 1 : 0,
      notify_ops_team ? 1 : 0,
      JSON.stringify(Array.isArray(admin_emails) ? admin_emails : [admin_emails].filter(Boolean)),
      webhook_url     || null,
      slack_webhook   || null,
      teams_webhook   || null,
      min_severity    || 'medium',
      min_confidence  || 70,
      rate_limit_hour || 20,
      notify_blocked  ? 1 : 0,
      notify_spam     ? 1 : 0,
      active !== false ? 1 : 0,
    ]);
    res.json({ success:true, message:'Notification settings saved' });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// GET /api/notifications/log
router.get('/log', verifyToken, async (req, res) => {
  try {
    const { customer_id, hours=24, page=1, limit=50 } = req.query;
    const p = getPool();
    const where  = ['nl.sent_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)'];
    const params = [parseInt(hours)];
    if (customer_id) { where.push('nl.customer_id=?'); params.push(customer_id); }

    const whereStr = where.join(' AND ');
    const offset   = (parseInt(page)-1) * parseInt(limit);

    const [[{total}]] = await p.query(
      `SELECT COUNT(*) AS total FROM notification_log nl WHERE ${whereStr}`, params
    );
    const [rows] = await p.query(`
      SELECT nl.*, c.name AS customer_name
      FROM notification_log nl
      JOIN customers c ON c.id = nl.customer_id
      WHERE ${whereStr}
      ORDER BY nl.sent_at DESC
      LIMIT ? OFFSET ?
    `, [...params, parseInt(limit), offset]);

    res.json({ success:true, data:rows, total, page:parseInt(page) });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// GET /api/notifications/stats
router.get('/stats', verifyToken, async (req, res) => {
  try {
    const { hours=24 } = req.query;
    const [[stats]] = await getPool().query(`
      SELECT
        COUNT(*)                                                             AS total,
        SUM(CASE WHEN status='sent'    THEN 1 ELSE 0 END)                   AS sent,
        SUM(CASE WHEN status='failed'  THEN 1 ELSE 0 END)                   AS failed,
        SUM(CASE WHEN notification_type='admin'    THEN 1 ELSE 0 END)       AS admin_notifs,
        SUM(CASE WHEN notification_type='end_user' THEN 1 ELSE 0 END)       AS user_notifs,
        SUM(CASE WHEN notification_type='ops_team' THEN 1 ELSE 0 END)       AS ops_notifs,
        SUM(CASE WHEN notification_type='webhook'  THEN 1 ELSE 0 END)       AS webhook_notifs,
        SUM(CASE WHEN notification_type='slack'    THEN 1 ELSE 0 END)       AS slack_notifs,
        SUM(CASE WHEN notification_type='teams'    THEN 1 ELSE 0 END)       AS teams_notifs,
        COUNT(DISTINCT customer_id)                                          AS customers
      FROM notification_log
      WHERE sent_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
    `, [parseInt(hours)]);
    res.json({ success:true, data:stats });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// POST /api/notifications/test — send test notification
router.post('/test', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  const { customer_id, email } = req.body;
  if (!email) return res.status(400).json({ error:'email required' });
  try {
    const nodemailer = require('nodemailer');
    const transport  = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'mail.worktual.tech',
      port: parseInt(process.env.SMTP_PORT || '587'),
      auth: {
        user: process.env.SMTP_USER || 'security@worktual.tech',
        pass: process.env.SMTP_PASS || '',
      }
    });

    await transport.sendMail({
      from:    `"Worktual Security" <${process.env.SMTP_USER}>`,
      to:      email,
      subject: '✅ [TEST] Worktual Security Notification Test',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;
                    background:#f9fafb;padding:24px;border-radius:10px">
          <h2 style="color:#16a34a">✅ Notification Test Successful</h2>
          <p>This is a test notification from the Worktual Email Security Platform.</p>
          <p>Your notification settings are working correctly.</p>
          <hr style="border:none;border-top:1px solid #e5e7eb;margin:16px 0">
          <p style="font-size:12px;color:#9ca3af">
            Sent at: ${new Date().toISOString()}<br>
            Dashboard: <a href="${process.env.DASHBOARD_URL}">
            ${process.env.DASHBOARD_URL}</a>
          </p>
        </div>
      `,
    });

    res.json({ success:true, message:`Test email sent to ${email}` });
  } catch(e) {
    res.status(500).json({ success:false, error:e.message });
  }
});

module.exports = router;
