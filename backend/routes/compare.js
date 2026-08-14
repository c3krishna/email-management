const express = require('express');
const router  = express.Router();
const { getPool } = require('../db');

// GET /api/compare/summary?campaign_id=5865&date=2026-07-07&range=today
// Summary: queue vs delivery counts per campaign
router.get('/summary', async (req, res) => {
  try {
    const { campaign_id, range = 'today', date, from, to } = req.query;
    const pool = getPool('campaign'); // always campaign server

    let dateFilter = 'ecq.create_date = CURDATE()';
    const params = [];

    if (range === 'today' && date) {
      dateFilter = 'ecq.create_date = ?';
      params.push(date);
    } else if (range === '7d') {
      dateFilter = 'ecq.create_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)';
    } else if (range === '30d') {
      dateFilter = 'ecq.create_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)';
    } else if (range === 'custom' && from && to) {
      dateFilter = 'ecq.create_date BETWEEN ? AND ?';
      params.push(from, to);
    }

    let campaignFilter = '';
    if (campaign_id) {
      campaignFilter = 'AND ecq.campaign_id = ?';
      params.push(campaign_id);
    }

    const [rows] = await pool.query(`
      SELECT
        ecq.campaign_id,
        ecq.create_date,
        COUNT(DISTINCT ecq.id)                                                        AS queued,
        COUNT(DISTINCT ecq.id) FILTER (WHERE ecq.status = 'sent')                    AS queue_sent,
        COUNT(DISTINCT ecq.id) FILTER (WHERE ecq.status = 'pending')                 AS queue_pending,
        COUNT(DISTINCT ecq.id) FILTER (WHERE ecq.status = 'failed')                  AS queue_failed,
        COUNT(DISTINCT edd.id)                                                        AS delivered_records,
        COUNT(DISTINCT edd.id) FILTER (WHERE edd.status IN ('sent','delivered')
          OR edd.delivery_status IN ('sent','delivered'))                              AS delivery_success,
        COUNT(DISTINCT edd.id) FILTER (WHERE edd.status = 'failed'
          OR edd.delivery_status = 'failed')                                           AS delivery_failed,
        COUNT(DISTINCT edd.id) FILTER (WHERE edd.status = 'bounced'
          OR edd.delivery_status = 'bounced' OR edd.dsn LIKE '5%')                    AS delivery_bounced,
        COUNT(DISTINCT edd.id) FILTER (WHERE edd.status = 'deferred'
          OR edd.delivery_status = 'deferred')                                         AS delivery_deferred,
        COUNT(DISTINCT CASE WHEN edd.id IS NULL THEN ecq.id END)                      AS not_in_delivery,
        COUNT(DISTINCT CASE WHEN ecq.status = 'sent' AND edd.id IS NULL
          THEN ecq.id END)                                                             AS sent_but_missing,
        ROUND(AVG(edd.duration), 1)                                                   AS avg_duration
      FROM email_campaign_queue ecq
      LEFT JOIN email_delivery_details edd
        ON ecq.message_id = edd.message_id
      WHERE ${dateFilter}
      ${campaignFilter}
      GROUP BY ecq.campaign_id, ecq.create_date
      ORDER BY ecq.create_date DESC, queued DESC
      LIMIT 200
    `, params);

    res.json({ success: true, data: rows });
  } catch (err) {
    // Fallback: MariaDB doesn't support FILTER(WHERE...) before 10.3
    // Use CASE WHEN instead
    try {
      const { campaign_id, range = 'today', date, from, to } = req.query;
      const pool = getPool('campaign');
      let dateFilter = 'ecq.create_date = CURDATE()';
      const params = [];

      if (range === 'today' && date) { dateFilter = 'ecq.create_date = ?'; params.push(date); }
      else if (range === '7d')  { dateFilter = 'ecq.create_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)'; }
      else if (range === '30d') { dateFilter = 'ecq.create_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)'; }
      else if (range === 'custom' && from && to) { dateFilter = 'ecq.create_date BETWEEN ? AND ?'; params.push(from, to); }

      let campaignFilter = '';
      if (campaign_id) { campaignFilter = 'AND ecq.campaign_id = ?'; params.push(campaign_id); }

      const [rows] = await pool.query(`
        SELECT
          ecq.campaign_id,
          ecq.create_date,
          COUNT(DISTINCT ecq.id)                                                                    AS queued,
          SUM(CASE WHEN ecq.status = 'sent'    THEN 1 ELSE 0 END)                                  AS queue_sent,
          SUM(CASE WHEN ecq.status = 'pending' THEN 1 ELSE 0 END)                                  AS queue_pending,
          SUM(CASE WHEN ecq.status = 'failed'  THEN 1 ELSE 0 END)                                  AS queue_failed,
          COUNT(DISTINCT edd.id)                                                                    AS delivered_records,
          SUM(CASE WHEN edd.status IN ('sent','delivered') OR edd.delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS delivery_success,
          SUM(CASE WHEN edd.status = 'failed'   OR edd.delivery_status = 'failed'   THEN 1 ELSE 0 END) AS delivery_failed,
          SUM(CASE WHEN edd.status = 'bounced'  OR edd.delivery_status = 'bounced'
            OR edd.dsn LIKE '5%'                                                     THEN 1 ELSE 0 END) AS delivery_bounced,
          SUM(CASE WHEN edd.status = 'deferred' OR edd.delivery_status = 'deferred' THEN 1 ELSE 0 END) AS delivery_deferred,
          SUM(CASE WHEN edd.id IS NULL THEN 1 ELSE 0 END)                                          AS not_in_delivery,
          SUM(CASE WHEN ecq.status = 'sent' AND edd.id IS NULL THEN 1 ELSE 0 END)                  AS sent_but_missing,
          ROUND(AVG(edd.duration), 1)                                                               AS avg_duration
        FROM email_campaign_queue ecq
        LEFT JOIN email_delivery_details edd
          ON ecq.message_id = edd.message_id
        WHERE ${dateFilter}
        ${campaignFilter}
        GROUP BY ecq.campaign_id, ecq.create_date
        ORDER BY ecq.create_date DESC, queued DESC
        LIMIT 200
      `, params);

      res.json({ success: true, data: rows });
    } catch (err2) {
      res.status(500).json({ error: err2.message });
    }
  }
});

// GET /api/compare/missing?campaign_id=5865&date=2026-07-07
// Mails in queue (sent) but NOT in delivery details
router.get('/missing', async (req, res) => {
  try {
    const { campaign_id, date, range = 'today', from, to, page = 1, limit = 100 } = req.query;
    const pool   = getPool('campaign');
    const offset = (parseInt(page) - 1) * parseInt(limit);

    let dateFilter = 'ecq.create_date = CURDATE()';
    const params   = [];

    if (range === 'today' && date) { dateFilter = 'ecq.create_date = ?'; params.push(date); }
    else if (range === '7d')  { dateFilter = 'ecq.create_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)'; }
    else if (range === '30d') { dateFilter = 'ecq.create_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)'; }
    else if (range === 'custom' && from && to) { dateFilter = 'ecq.create_date BETWEEN ? AND ?'; params.push(from, to); }

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

// GET /api/compare/mismatch?campaign_id=5865&date=2026-07-07
// Mails where queue.status != delivery outcome (e.g. queue=sent but delivery=failed)
router.get('/mismatch', async (req, res) => {
  try {
    const { campaign_id, date, range = 'today', from, to, limit = 200 } = req.query;
    const pool = getPool('campaign');

    let dateFilter = 'ecq.create_date = CURDATE()';
    const params   = [];

    if (range === 'today' && date) { dateFilter = 'ecq.create_date = ?'; params.push(date); }
    else if (range === '7d')  { dateFilter = 'ecq.create_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)'; }
    else if (range === '30d') { dateFilter = 'ecq.create_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)'; }
    else if (range === 'custom' && from && to) { dateFilter = 'ecq.create_date BETWEEN ? AND ?'; params.push(from, to); }

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

// GET /api/compare/campaigns?range=7d
// List all campaigns with queue vs delivery match rate
router.get('/campaigns', async (req, res) => {
  try {
    const { range = '7d' } = req.query;
    const pool = getPool('campaign');
    const days = range === '30d' ? 30 : range === 'today' ? 0 : 7;
    const dateFilter = days === 0
      ? 'ecq.create_date = CURDATE()'
      : `ecq.create_date >= DATE_SUB(CURDATE(), INTERVAL ${days} DAY)`;

    const [rows] = await pool.query(`
      SELECT
        ecq.campaign_id,
        COUNT(DISTINCT ecq.id)                                                       AS total_queued,
        SUM(CASE WHEN ecq.status = 'sent'    THEN 1 ELSE 0 END)                      AS queue_sent,
        SUM(CASE WHEN ecq.status = 'pending' THEN 1 ELSE 0 END)                      AS queue_pending,
        COUNT(DISTINCT edd.id)                                                       AS total_delivered,
        SUM(CASE WHEN edd.status IN ('sent','delivered')
          OR edd.delivery_status IN ('sent','delivered')    THEN 1 ELSE 0 END)       AS delivery_success,
        SUM(CASE WHEN edd.status = 'failed'
          OR edd.delivery_status = 'failed'                 THEN 1 ELSE 0 END)       AS delivery_failed,
        SUM(CASE WHEN edd.status = 'bounced'
          OR edd.delivery_status = 'bounced'
          OR edd.dsn LIKE '5%'                              THEN 1 ELSE 0 END)       AS delivery_bounced,
        SUM(CASE WHEN edd.id IS NULL AND ecq.status = 'sent' THEN 1 ELSE 0 END)      AS sent_not_tracked,
        ROUND(
          SUM(CASE WHEN edd.id IS NOT NULL THEN 1 ELSE 0 END) * 100.0
          / NULLIF(COUNT(DISTINCT ecq.id), 0), 2
        )                                                                            AS tracking_rate,
        ROUND(
          SUM(CASE WHEN edd.status IN ('sent','delivered')
            OR edd.delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) * 100.0
          / NULLIF(COUNT(DISTINCT ecq.id), 0), 2
        )                                                                            AS overall_success_rate,
        MIN(ecq.create_date) AS first_date,
        MAX(ecq.create_date) AS last_date
      FROM email_campaign_queue ecq
      LEFT JOIN email_delivery_details edd ON ecq.message_id = edd.message_id
      WHERE ${dateFilter}
      GROUP BY ecq.campaign_id
      ORDER BY total_queued DESC
      LIMIT 100
    `);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
