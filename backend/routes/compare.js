const express = require('express');
const router  = express.Router();
const { getPool } = require('../db');
const { normalizeServer, buildDateFilter } = require('../mailServers');

function poolFor(req) {
  // Queue vs delivery is primarily a Campaign feature, but honor Topbar when set
  const s = normalizeServer(req.query.server, 'campaign');
  return getPool(s === 'all' ? 'campaign' : s);
}

function queueDateFilter(range, date, from, to) {
  return buildDateFilter(range, date, from, to, 'ecq.create_date');
}

const SUMMARY_SQL = `
  SELECT
    ecq.campaign_id,
    ecq.create_date,
    COUNT(DISTINCT ecq.id) AS queued,
    SUM(CASE WHEN ecq.status = 'sent'    THEN 1 ELSE 0 END) AS queue_sent,
    SUM(CASE WHEN ecq.status = 'pending' THEN 1 ELSE 0 END) AS queue_pending,
    SUM(CASE WHEN ecq.status = 'failed'  THEN 1 ELSE 0 END) AS queue_failed,
    COUNT(DISTINCT edd.id) AS delivered_records,
    SUM(CASE WHEN edd.status IN ('sent','delivered') OR edd.delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS delivery_success,
    SUM(CASE WHEN edd.status = 'failed'   OR edd.delivery_status = 'failed'   THEN 1 ELSE 0 END) AS delivery_failed,
    SUM(CASE WHEN edd.status = 'bounced'  OR edd.delivery_status = 'bounced'
      OR edd.dsn LIKE '5%' THEN 1 ELSE 0 END) AS delivery_bounced,
    SUM(CASE WHEN edd.status = 'deferred' OR edd.delivery_status = 'deferred' THEN 1 ELSE 0 END) AS delivery_deferred,
    SUM(CASE WHEN edd.id IS NULL THEN 1 ELSE 0 END) AS not_in_delivery,
    SUM(CASE WHEN ecq.status = 'sent' AND edd.id IS NULL THEN 1 ELSE 0 END) AS sent_but_missing,
    ROUND(AVG(edd.duration), 1) AS avg_duration
  FROM email_campaign_queue ecq
  LEFT JOIN email_delivery_details edd
    ON ecq.message_id = edd.message_id
  WHERE __DATE__
  __CAMP__
  GROUP BY ecq.campaign_id, ecq.create_date
  ORDER BY ecq.create_date DESC, queued DESC
  LIMIT 200
`;

// GET /api/compare/summary?campaign_id=&date=&range=today|7d|30d|custom&server=campaign
router.get('/summary', async (req, res) => {
  try {
    const { campaign_id, range = 'today', date, from, to } = req.query;
    const pool = poolFor(req);
    const { dateFilter, params } = queueDateFilter(range, date, from, to);

    let campaignFilter = '';
    if (campaign_id) {
      campaignFilter = 'AND ecq.campaign_id = ?';
      params.push(campaign_id);
    }

    const sql = SUMMARY_SQL
      .replace('__DATE__', dateFilter)
      .replace('__CAMP__', campaignFilter);

    const [rows] = await pool.query(sql, params);
    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/compare/missing
router.get('/missing', async (req, res) => {
  try {
    const { campaign_id, date, range = 'today', from, to, page = 1, limit = 100 } = req.query;
    const pool   = poolFor(req);
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const { dateFilter, params } = queueDateFilter(range, date, from, to);

    let campaignFilter = '';
    if (campaign_id) { campaignFilter = 'AND ecq.campaign_id = ?'; params.push(campaign_id); }

    const [countRows] = await pool.query(`
      SELECT COUNT(*) AS total
      FROM email_campaign_queue ecq
      LEFT JOIN email_delivery_details edd ON ecq.message_id = edd.message_id
      WHERE ${dateFilter} ${campaignFilter}
        AND edd.id IS NULL AND ecq.status = 'sent'
    `, params);

    const [rows] = await pool.query(`
      SELECT
        ecq.id, ecq.campaign_id, ecq.fromMail, ecq.contact_email,
        ecq.domain_id, ecq.subject, ecq.status AS queue_status,
        ecq.message_id, ecq.sent_at, ecq.create_date, ecq.template_type
      FROM email_campaign_queue ecq
      LEFT JOIN email_delivery_details edd ON ecq.message_id = edd.message_id
      WHERE ${dateFilter} ${campaignFilter}
        AND edd.id IS NULL AND ecq.status = 'sent'
      ORDER BY ecq.create_date DESC, ecq.sent_at DESC
      LIMIT ? OFFSET ?
    `, [...params, parseInt(limit), offset]);

    res.json({
      success: true, data: rows,
      total: countRows[0].total,
      page: parseInt(page), limit: parseInt(limit)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/compare/mismatch
router.get('/mismatch', async (req, res) => {
  try {
    const { campaign_id, date, range = 'today', from, to, limit = 200 } = req.query;
    const pool = poolFor(req);
    const { dateFilter, params } = queueDateFilter(range, date, from, to);

    let campaignFilter = '';
    if (campaign_id) { campaignFilter = 'AND ecq.campaign_id = ?'; params.push(campaign_id); }

    const [rows] = await pool.query(`
      SELECT
        ecq.id AS queue_id, ecq.campaign_id, ecq.contact_email,
        ecq.fromMail, ecq.subject, ecq.status AS queue_status,
        ecq.sent_at, ecq.create_date,
        edd.id AS delivery_id, edd.status AS delivery_status,
        edd.delivery_status AS final_status,
        edd.dsn, edd.reason, edd.duration, edd.log_date
      FROM email_campaign_queue ecq
      INNER JOIN email_delivery_details edd ON ecq.message_id = edd.message_id
      WHERE ${dateFilter} ${campaignFilter}
        AND ecq.status = 'sent'
        AND edd.status NOT IN ('sent','delivered')
        AND edd.delivery_status NOT IN ('sent','delivered')
      ORDER BY ecq.create_date DESC
      LIMIT ?
    `, [...params, parseInt(limit)]);

    res.json({ success: true, data: rows, count: rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/compare/campaigns?range=7d|today|30d|custom
router.get('/campaigns', async (req, res) => {
  try {
    const { range = '7d', date, from, to } = req.query;
    const pool = poolFor(req);
    const { dateFilter, params } = queueDateFilter(range, date, from, to);

    const [rows] = await pool.query(`
      SELECT
        ecq.campaign_id,
        COUNT(DISTINCT ecq.id) AS total_queued,
        SUM(CASE WHEN ecq.status = 'sent'    THEN 1 ELSE 0 END) AS queue_sent,
        SUM(CASE WHEN ecq.status = 'pending' THEN 1 ELSE 0 END) AS queue_pending,
        COUNT(DISTINCT edd.id) AS total_delivered,
        SUM(CASE WHEN edd.status IN ('sent','delivered')
          OR edd.delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS delivery_success,
        SUM(CASE WHEN edd.status = 'failed'
          OR edd.delivery_status = 'failed' THEN 1 ELSE 0 END) AS delivery_failed,
        SUM(CASE WHEN edd.status = 'bounced'
          OR edd.delivery_status = 'bounced'
          OR edd.dsn LIKE '5%' THEN 1 ELSE 0 END) AS delivery_bounced,
        SUM(CASE WHEN edd.id IS NULL AND ecq.status = 'sent' THEN 1 ELSE 0 END) AS sent_not_tracked,
        ROUND(
          SUM(CASE WHEN edd.id IS NOT NULL THEN 1 ELSE 0 END) * 100.0
          / NULLIF(COUNT(DISTINCT ecq.id), 0), 2
        ) AS tracking_rate,
        ROUND(
          SUM(CASE WHEN edd.status IN ('sent','delivered')
            OR edd.delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) * 100.0
          / NULLIF(COUNT(DISTINCT ecq.id), 0), 2
        ) AS overall_success_rate,
        MIN(ecq.create_date) AS first_date,
        MAX(ecq.create_date) AS last_date
      FROM email_campaign_queue ecq
      LEFT JOIN email_delivery_details edd ON ecq.message_id = edd.message_id
      WHERE ${dateFilter}
      GROUP BY ecq.campaign_id
      ORDER BY total_queued DESC
      LIMIT 100
    `, params);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
