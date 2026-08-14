const express = require('express');
const router = express.Router();
const { getPool } = require('../db');

// GET /api/stats/summary?date=YYYY-MM-DD&range=today|7d|30d|custom&from=&to=
router.get('/summary', async (req, res) => {
  try {
    const { date, range = 'today', from, to } = req.query;
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    const [rows] = await getPool(req.query.server).query(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS success,
        SUM(CASE WHEN status = 'failed' OR delivery_status = 'failed' THEN 1 ELSE 0 END) AS failed,
        SUM(CASE WHEN status = 'bounced' OR delivery_status = 'bounced' OR dsn LIKE '5%' THEN 1 ELSE 0 END) AS bounced,
        SUM(CASE WHEN status = 'deferred' OR delivery_status = 'deferred' OR dsn LIKE '4%' THEN 1 ELSE 0 END) AS deferred,
        SUM(CASE WHEN status = 'timeout' OR delivery_status = 'timeout' OR reason LIKE '%timeout%' OR reason LIKE '%timed out%' THEN 1 ELSE 0 END) AS timedout,
        SUM(CASE WHEN status = 'invalid' OR delivery_status = 'invalid' OR dsn = '5.1.1' OR reason LIKE '%User unknown%' OR reason LIKE '%does not exist%' THEN 1 ELSE 0 END) AS invalid_addr,
        SUM(CASE WHEN status = 'processing' OR delivery_status = 'processing' THEN 1 ELSE 0 END) AS processing,
        SUM(CASE WHEN status = 'spam' OR reason LIKE '%spam%' OR reason LIKE '%blocked%' OR reason LIKE '%blacklist%' OR reason LIKE '%spamhaus%' THEN 1 ELSE 0 END) AS spam_blocked,
        AVG(duration) AS avg_duration,
        COUNT(DISTINCT mail_from) AS unique_senders,
        COUNT(DISTINCT campaign_id) AS total_campaigns,
        COUNT(DISTINCT domain_id) AS total_domains
      FROM email_delivery_details
      WHERE ${dateFilter}
    `, params);

    res.json({ success: true, data: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});




// GET /api/stats/trend?range=7d|30d&campaign_id=5865
router.get('/trend', async (req, res) => {
  try {
    const { range = '7d', campaign_id } = req.query;
    const days = range === '30d' ? 30 : 7;
    const pool = getPool(req.query.server);

    let whereExtra = '';
    const params = [days];

    if (campaign_id) {
      whereExtra = 'AND campaign_id = ?';
      params.push(campaign_id);
    }

    const [rows] = await pool.query(`
      SELECT
        log_date,
        COUNT(*) AS total,
        CAST(SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS SIGNED) AS success,
        CAST(SUM(CASE WHEN status = 'failed' OR delivery_status = 'failed' THEN 1 ELSE 0 END) AS SIGNED) AS failed,
        CAST(SUM(CASE WHEN status = 'bounced' OR delivery_status = 'bounced' OR dsn LIKE '5%' THEN 1 ELSE 0 END) AS SIGNED) AS bounced,
        CAST(SUM(CASE WHEN status = 'deferred' OR delivery_status = 'deferred' OR dsn LIKE '4%' THEN 1 ELSE 0 END) AS SIGNED) AS deferred,
        CAST(SUM(CASE WHEN reason LIKE '%spam%' OR reason LIKE '%blocked%' OR reason LIKE '%blacklist%' THEN 1 ELSE 0 END) AS SIGNED) AS spam_blocked
      FROM email_delivery_details
      WHERE log_date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
      ${whereExtra}
      GROUP BY log_date
      ORDER BY log_date ASC
    `, params);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});






// GET /api/stats/hourly?date=YYYY-MM-DD
router.get('/hourly', async (req, res) => {
  try {
    const { date } = req.query;
    const targetDate = date || new Date().toISOString().slice(0, 10);

    const [rows] = await getPool(req.query.server).query(`
      SELECT
        HOUR(log_time) AS hour,
        COUNT(*) AS total,
        SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS success,
        SUM(CASE WHEN status = 'failed' OR delivery_status = 'failed' THEN 1 ELSE 0 END) AS failed,
        SUM(CASE WHEN status = 'bounced' OR delivery_status = 'bounced' OR dsn LIKE '5%' THEN 1 ELSE 0 END) AS bounced,
        SUM(CASE WHEN status = 'deferred' OR delivery_status = 'deferred' THEN 1 ELSE 0 END) AS deferred
      FROM email_delivery_details
      WHERE log_date = ?
      GROUP BY HOUR(log_time)
      ORDER BY hour ASC
    `, [targetDate]);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/by-campaign?range=7d&limit=20
router.get('/by-campaign', async (req, res) => {
  try {
    const { range = '7d', limit = 20 } = req.query;
    const days = range === '30d' ? 30 : range === '1d' ? 1 : 7;

    const [rows] = await getPool(req.query.server).query(`
      SELECT
        campaign_id,
        COUNT(*) AS total,
        SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS success,
        SUM(CASE WHEN status = 'failed' OR delivery_status = 'failed' THEN 1 ELSE 0 END) AS failed,
        SUM(CASE WHEN status = 'bounced' OR delivery_status = 'bounced' OR dsn LIKE '5%' THEN 1 ELSE 0 END) AS bounced,
        SUM(CASE WHEN status = 'deferred' OR delivery_status = 'deferred' THEN 1 ELSE 0 END) AS deferred,
        ROUND(SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) AS success_rate,
        MIN(log_date) AS first_seen,
        MAX(log_date) AS last_seen
      FROM email_delivery_details
      WHERE log_date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
        AND campaign_id IS NOT NULL
      GROUP BY campaign_id
      ORDER BY total DESC
      LIMIT ?
    `, [days, parseInt(limit)]);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/failure-reasons?range=7d&limit=20
router.get('/failure-reasons', async (req, res) => {
  try {
    const { range = '7d', limit = 20 } = req.query;
    const days = range === '30d' ? 30 : 7;

    const [rows] = await getPool(req.query.server).query(`
      SELECT
        COALESCE(reason, 'Unknown') AS reason,
        dsn,
        status,
        delivery_status,
        COUNT(*) AS count,
        COUNT(DISTINCT mail_from) AS affected_senders,
        COUNT(DISTINCT campaign_id) AS affected_campaigns
      FROM email_delivery_details
      WHERE log_date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
        AND (status IN ('failed','bounced','deferred','invalid','timeout')
          OR delivery_status IN ('failed','bounced','deferred','invalid','timeout'))
      GROUP BY reason, dsn, status, delivery_status
      ORDER BY count DESC
      LIMIT ?
    `, [days, parseInt(limit)]);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/by-sender?range=7d
router.get('/by-sender', async (req, res) => {
  try {
    const { range = '7d', limit = 15 } = req.query;
    const days = range === '30d' ? 30 : 7;

    const [rows] = await getPool(req.query.server).query(`
      SELECT
        mail_from,
        COUNT(*) AS total,
        SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS success,
        SUM(CASE WHEN status = 'failed' OR delivery_status = 'failed' THEN 1 ELSE 0 END) AS failed,
        SUM(CASE WHEN status = 'bounced' OR delivery_status = 'bounced' OR dsn LIKE '5%' THEN 1 ELSE 0 END) AS bounced,
        ROUND(SUM(CASE WHEN status = 'failed' OR delivery_status = 'failed' OR status = 'bounced' OR delivery_status = 'bounced' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) AS failure_rate
      FROM email_delivery_details
      WHERE log_date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
        AND mail_from IS NOT NULL
      GROUP BY mail_from
      ORDER BY total DESC
      LIMIT ?
    `, [days, parseInt(limit)]);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/dsn-breakdown?range=7d
router.get('/dsn-breakdown', async (req, res) => {
  try {
    const { range = '7d' } = req.query;
    const days = range === '30d' ? 30 : 7;

    const [rows] = await getPool(req.query.server).query(`
      SELECT
        dsn,
        COUNT(*) AS count,
        CASE
          WHEN dsn LIKE '2%' THEN 'Success'
          WHEN dsn LIKE '4%' THEN 'Temporary Failure'
          WHEN dsn LIKE '5%' THEN 'Permanent Failure'
          ELSE 'Unknown'
        END AS category
      FROM email_delivery_details
      WHERE log_date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
        AND dsn IS NOT NULL
      GROUP BY dsn
      ORDER BY count DESC
      LIMIT 30
    `, [days]);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Helper: build WHERE clause for date range
function buildDateFilter(range, date, from, to) {
  if (range === 'custom' && from && to) {
    return { dateFilter: 'log_date BETWEEN ? AND ?', params: [from, to] };
  }
  if (range === 'today' || date) {
    const d = date || new Date().toISOString().slice(0, 10);
    return { dateFilter: 'log_date = ?', params: [d] };
  }
  if (range === '7d') return { dateFilter: 'log_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)', params: [] };
  if (range === '30d') return { dateFilter: 'log_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)', params: [] };
  return { dateFilter: 'log_date = CURDATE()', params: [] };
}
// ============================================================
// ADD THESE NEW ROUTES to /etc/postfix/routes/stats.js
// Enhanced dashboard: inbound/outbound, threats, top senders/recipients
// wrong hits (rejected attempts), vs-yesterday comparison
// ============================================================

// GET /api/stats/enhanced-summary?range=today&date=&server=app
// Returns full dashboard data including vs-yesterday comparison
router.get('/enhanced-summary', async (req, res) => {
  try {
    const { range = 'today', date, from, to } = req.query;
    const pool = getPool(req.query.server);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    // Today's stats
    const [today] = await pool.query(`
      SELECT
        COUNT(*)                                                                                   AS total,
        SUM(CASE WHEN mail_from LIKE '%@worktual%' OR mail_from LIKE '%@${process.env.MAIL_DOMAIN || 'worktual.tech'}%' THEN 1 ELSE 0 END) AS outbound,
        SUM(CASE WHEN mail_to   LIKE '%@worktual%' OR mail_to   LIKE '%@${process.env.MAIL_DOMAIN || 'worktual.tech'}%' THEN 1 ELSE 0 END) AS inbound,
        SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered')   THEN 1 ELSE 0 END) AS success,
        SUM(CASE WHEN status = 'failed'   OR delivery_status = 'failed'                          THEN 1 ELSE 0 END) AS failed,
        SUM(CASE WHEN status = 'bounced'  OR delivery_status = 'bounced'  OR dsn LIKE '5%'       THEN 1 ELSE 0 END) AS bounced,
        SUM(CASE WHEN status = 'deferred' OR delivery_status = 'deferred' OR dsn LIKE '4%'       THEN 1 ELSE 0 END) AS deferred,
        SUM(CASE WHEN status = 'timeout'  OR delivery_status = 'timeout'                         THEN 1 ELSE 0 END) AS timedout,
        SUM(CASE WHEN reason LIKE '%spam%'     OR reason LIKE '%blocked%'
                  OR reason LIKE '%blacklist%' OR reason LIKE '%spamhaus%'
                  OR reason LIKE '%DNSBL%'     OR reason LIKE '%RBL%'                            THEN 1 ELSE 0 END) AS spam_blocked,
        SUM(CASE WHEN reason LIKE '%phish%'    OR reason LIKE '%malware%'
                  OR reason LIKE '%virus%'     OR reason LIKE '%malicious%'                      THEN 1 ELSE 0 END) AS threats,
        SUM(CASE WHEN status = 'invalid'  OR delivery_status = 'invalid'
                  OR dsn = '5.1.1' OR reason LIKE '%User unknown%'
                  OR reason LIKE '%does not exist%'                                               THEN 1 ELSE 0 END) AS invalid_addr,
        SUM(CASE WHEN status = 'processing' OR delivery_status = 'processing'                    THEN 1 ELSE 0 END) AS processing,
        -- Wrong hits / rejected attempts
        SUM(CASE WHEN status IN ('failed','bounced','invalid','spam')
                  OR delivery_status IN ('failed','bounced','invalid')
                  OR dsn LIKE '5%'                                                                THEN 1 ELSE 0 END) AS wrong_hits,
        -- Quarantined (spam score high)
        SUM(CASE WHEN reason LIKE '%quarantine%' OR reason LIKE '%Quarantine%'                   THEN 1 ELSE 0 END) AS quarantined,
        AVG(duration)                                                                              AS avg_duration,
        COUNT(DISTINCT campaign_id)                                                                AS total_campaigns,
        COUNT(DISTINCT mail_from)                                                                  AS unique_senders
      FROM email_delivery_details
      WHERE ${dateFilter}
    `, params);

    // Yesterday's stats for comparison
    const [yesterday] = await pool.query(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS success,
        SUM(CASE WHEN status = 'failed'   OR delivery_status = 'failed'   THEN 1 ELSE 0 END) AS failed,
        SUM(CASE WHEN status = 'bounced'  OR delivery_status = 'bounced'  THEN 1 ELSE 0 END) AS bounced,
        SUM(CASE WHEN reason LIKE '%spam%' OR reason LIKE '%blocked%'      THEN 1 ELSE 0 END) AS spam_blocked,
        SUM(CASE WHEN status IN ('failed','bounced','invalid')
                  OR dsn LIKE '5%'                                         THEN 1 ELSE 0 END) AS wrong_hits
      FROM email_delivery_details
      WHERE log_date = DATE_SUB(CURDATE(), INTERVAL 1 DAY)
    `);

    // Compute vs-yesterday percentage change
    const pct = (curr, prev) => {
      if (!prev || prev === 0) return curr > 0 ? 100 : 0;
      return Math.round(((curr - prev) / prev) * 100);
    };

    const t = today[0];
    const y = yesterday[0];

    res.json({
      success: true,
      data: {
        ...t,
        vs_yesterday: {
          total:       pct(t.total,       y.total),
          success:     pct(t.success,     y.success),
          failed:      pct(t.failed,      y.failed),
          bounced:     pct(t.bounced,     y.bounced),
          spam_blocked:pct(t.spam_blocked,y.spam_blocked),
          wrong_hits:  pct(t.wrong_hits,  y.wrong_hits),
        }
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/top-senders?range=today&limit=10
router.get('/top-senders', async (req, res) => {
  try {
    const { range = 'today', date, from, to, limit = 10 } = req.query;
    const pool = getPool(req.query.server);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    const [rows] = await pool.query(`
      SELECT
        mail_from AS email,
        COUNT(*) AS total,
        SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS success,
        SUM(CASE WHEN status IN ('failed','bounced') OR delivery_status IN ('failed','bounced') THEN 1 ELSE 0 END) AS failed
      FROM email_delivery_details
      WHERE ${dateFilter} AND mail_from IS NOT NULL AND mail_from != ''
      GROUP BY mail_from
      ORDER BY total DESC
      LIMIT ?
    `, [...params, parseInt(limit)]);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/top-recipients?range=today&limit=10
router.get('/top-recipients', async (req, res) => {
  try {
    const { range = 'today', date, from, to, limit = 10 } = req.query;
    const pool = getPool(req.query.server);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    const [rows] = await pool.query(`
      SELECT
        mail_to AS email,
        COUNT(*) AS total,
        SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS success,
        SUM(CASE WHEN status = 'bounced' OR delivery_status = 'bounced' OR dsn LIKE '5.1%'     THEN 1 ELSE 0 END) AS bounced
      FROM email_delivery_details
      WHERE ${dateFilter} AND mail_to IS NOT NULL AND mail_to != ''
      GROUP BY mail_to
      ORDER BY total DESC
      LIMIT ?
    `, [...params, parseInt(limit)]);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/wrong-hits-trend?range=7d
// Wrong hits = rejected, blocked, bounced, spam attempts over time
router.get('/wrong-hits-trend', async (req, res) => {
  try {
    const { range = '7d' } = req.query;
    const pool = getPool(req.query.server);
    const days = range === '30d' ? 30 : 7;

    const [rows] = await pool.query(`
      SELECT
        log_date,
        COUNT(*) AS total,
        CAST(SUM(CASE WHEN status = 'failed'   OR delivery_status = 'failed'   THEN 1 ELSE 0 END) AS SIGNED) AS failed,
        CAST(SUM(CASE WHEN status = 'bounced'  OR delivery_status = 'bounced'
                       OR dsn LIKE '5%'                                         THEN 1 ELSE 0 END) AS SIGNED) AS bounced,
        CAST(SUM(CASE WHEN reason LIKE '%spam%' OR reason LIKE '%blocked%'
                       OR reason LIKE '%DNSBL%'                                 THEN 1 ELSE 0 END) AS SIGNED) AS spam,
        CAST(SUM(CASE WHEN status = 'invalid'  OR dsn = '5.1.1'
                       OR reason LIKE '%User unknown%'                           THEN 1 ELSE 0 END) AS SIGNED) AS invalid,
        CAST(SUM(CASE WHEN status = 'timeout'  OR delivery_status = 'timeout'  THEN 1 ELSE 0 END) AS SIGNED) AS timeout,
        CAST(SUM(CASE WHEN status IN ('failed','bounced','invalid','spam')
                       OR delivery_status IN ('failed','bounced','invalid')
                       OR dsn LIKE '5%'                                          THEN 1 ELSE 0 END) AS SIGNED) AS total_wrong
      FROM email_delivery_details
      WHERE log_date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
      GROUP BY log_date
      ORDER BY log_date ASC
    `, [days]);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/threat-breakdown?range=today
router.get('/threat-breakdown', async (req, res) => {
  try {
    const { range = 'today', date, from, to } = req.query;
    const pool = getPool(req.query.server);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    const [rows] = await pool.query(`
      SELECT
        CAST(SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS SIGNED) AS clean,
        CAST(SUM(CASE WHEN reason LIKE '%spam%' OR reason LIKE '%DNSBL%' OR reason LIKE '%RBL%'     THEN 1 ELSE 0 END) AS SIGNED) AS spam,
        CAST(SUM(CASE WHEN reason LIKE '%phish%' OR reason LIKE '%phishing%'                        THEN 1 ELSE 0 END) AS SIGNED) AS phishing,
        CAST(SUM(CASE WHEN reason LIKE '%virus%' OR reason LIKE '%malware%' OR reason LIKE '%malicious%' THEN 1 ELSE 0 END) AS SIGNED) AS malware,
        CAST(SUM(CASE WHEN reason LIKE '%reject%' OR reason LIKE '%blocked%' OR reason LIKE '%blacklist%' THEN 1 ELSE 0 END) AS SIGNED) AS blocked,
        CAST(SUM(CASE WHEN status = 'bounced' OR delivery_status = 'bounced' OR dsn LIKE '5%'       THEN 1 ELSE 0 END) AS SIGNED) AS bounced,
        CAST(SUM(CASE WHEN status = 'failed'  OR delivery_status = 'failed'                         THEN 1 ELSE 0 END) AS SIGNED) AS failed,
        CAST(SUM(CASE WHEN status = 'deferred' OR delivery_status = 'deferred' OR dsn LIKE '4%'     THEN 1 ELSE 0 END) AS SIGNED) AS deferred
      FROM email_delivery_details
      WHERE ${dateFilter}
    `, params);

    res.json({ success: true, data: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/recent-logs?limit=20
router.get('/recent-logs', async (req, res) => {
  try {
    const { range = 'today', date, from, to, limit = 20 } = req.query;
    const pool = getPool(req.query.server);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    const [rows] = await pool.query(`
      SELECT
        id, log_date, log_time, mail_from, mail_to,
        campaign_id, status, delivery_status, dsn, reason, duration,
        CASE
          WHEN mail_from LIKE '%@worktual.tech%' OR mail_from LIKE '%@worktual.com%' THEN 'Outbound'
          ELSE 'Inbound'
        END AS direction,
        CASE
          WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 'Delivered'
          WHEN status = 'bounced'  OR delivery_status = 'bounced'  OR dsn LIKE '5%'    THEN 'Bounced'
          WHEN status = 'failed'   OR delivery_status = 'failed'                        THEN 'Failed'
          WHEN status = 'deferred' OR delivery_status = 'deferred'                      THEN 'Deferred'
          WHEN reason LIKE '%spam%' OR reason LIKE '%blocked%'                          THEN 'Blocked'
          ELSE 'Processing'
        END AS action,
        CASE
          WHEN reason LIKE '%spam%' OR reason LIKE '%DNSBL%'    THEN 'Spam'
          WHEN reason LIKE '%phish%'                             THEN 'Phishing'
          WHEN reason LIKE '%virus%' OR reason LIKE '%malware%' THEN 'Malware'
          WHEN reason LIKE '%blacklist%' OR reason LIKE '%RBL%' THEN 'Blacklisted'
          WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 'Clean'
          ELSE 'Other'
        END AS threat_type
      FROM email_delivery_details
      WHERE ${dateFilter}
      ORDER BY log_date DESC, log_time DESC
      LIMIT ?
    `, [...params, parseInt(limit)]);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
