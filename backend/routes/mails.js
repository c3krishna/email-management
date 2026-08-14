const express = require('express');
const router = express.Router();
const { getPool } = require('../db');

// GET /api/mails?page=1&limit=50&status=failed&search=&date=&campaign_id=&range=today
router.get('/', async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      status,
      delivery_status,
      search,
      date,
      range = 'today',
      campaign_id,
      domain_id,
      mail_from,
      dsn,
      from: dateFrom,
      to: dateTo
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);
    const conditions = [];
    const params = [];

    // Date filter
    if (range === 'custom' && dateFrom && dateTo) {
      conditions.push('log_date BETWEEN ? AND ?');
      params.push(dateFrom, dateTo);
    } else if (date) {
      conditions.push('log_date = ?');
      params.push(date);
    } else if (range === '7d') {
      conditions.push('log_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)');
    } else if (range === '30d') {
      conditions.push('log_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)');
    } else {
      conditions.push('log_date = CURDATE()');
    }

    // Status filters
    if (status) {
      conditions.push('status = ?');
      params.push(status);
    }
    if (delivery_status) {
      conditions.push('delivery_status = ?');
      params.push(delivery_status);
    }
    if (campaign_id) {
      conditions.push('campaign_id = ?');
      params.push(campaign_id);
    }
    if (domain_id) {
      conditions.push('domain_id = ?');
      params.push(parseInt(domain_id));
    }
    if (mail_from) {
      conditions.push('mail_from LIKE ?');
      params.push(`%${mail_from}%`);
    }
    if (dsn) {
      conditions.push('dsn = ?');
      params.push(dsn);
    }
    if (search) {
      conditions.push('(mail_to LIKE ? OR mail_from LIKE ? OR message_id LIKE ? OR queue_id LIKE ? OR campaign_id LIKE ?)');
      const s = `%${search}%`;
      params.push(s, s, s, s, s);
    }

    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    // Count
    const [countRows] = await getPool(req.query.server).query(
      `SELECT COUNT(*) AS total FROM email_delivery_details ${whereClause}`,
      params
    );
    const total = countRows[0].total;

    // Data
    const [rows] = await getPool(req.query.server).query(
      `SELECT id, log_date, log_time, mail_from, mail_to, queue_id, message_id,
              campaign_id, domain_id, mail_id, queued_as, duration, status,
              delivery_status, dsn, reason
       FROM email_delivery_details
       ${whereClause}
       ORDER BY log_date DESC, log_time DESC
       LIMIT ? OFFSET ?`,
      [...params, parseInt(limit), offset]
    );

    res.json({
      success: true,
      data: rows,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/mails/problematic — mails with issues needing attention
router.get('/problematic', async (req, res) => {
  try {
    const { range = 'today', category } = req.query;
    const days = range === '7d' ? 7 : range === '30d' ? 30 : 0;
    const dateFilter = days === 0 ? 'log_date = CURDATE()' : `log_date >= DATE_SUB(CURDATE(), INTERVAL ${days} DAY)`;

    // Category map
    const categoryFilters = {
      spam: `(reason LIKE '%spam%' OR reason LIKE '%blocked%' OR reason LIKE '%blacklist%' OR reason LIKE '%spamhaus%' OR reason LIKE '%Spam%')`,
      bounced: `(status = 'bounced' OR delivery_status = 'bounced' OR dsn LIKE '5%')`,
      failed: `(status = 'failed' OR delivery_status = 'failed')`,
      deferred: `(status = 'deferred' OR delivery_status = 'deferred' OR dsn LIKE '4%')`,
      timedout: `(status = 'timeout' OR delivery_status = 'timeout' OR reason LIKE '%timeout%' OR reason LIKE '%timed out%')`,
      invalid: `(status = 'invalid' OR delivery_status = 'invalid' OR dsn = '5.1.1' OR reason LIKE '%User unknown%' OR reason LIKE '%does not exist%' OR reason LIKE '%No such user%')`,
      unformatted: `(reason LIKE '%format%' OR reason LIKE '%malformed%' OR reason LIKE '%invalid header%' OR reason LIKE '%encoding%' OR reason LIKE '%syntax%')`
    };

    const catFilter = category && categoryFilters[category]
      ? `AND ${categoryFilters[category]}`
      : `AND (status NOT IN ('sent','delivered','processing') OR delivery_status NOT IN ('sent','delivered','processing'))`;

    const [rows] = await getPool(req.query.server).query(`
      SELECT id, log_date, log_time, mail_from, mail_to, queue_id, message_id,
             campaign_id, domain_id, duration, status, delivery_status, dsn, reason
      FROM email_delivery_details
      WHERE ${dateFilter}
      ${catFilter}
      ORDER BY log_date DESC, log_time DESC
      LIMIT 500
    `);

    res.json({ success: true, data: rows, count: rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/mails/spam-analysis — deep spam pattern analysis
router.get('/spam-analysis', async (req, res) => {
  try {
    const [rows] = await getPool(req.query.server).query(`
      SELECT
        mail_from,
        COUNT(*) AS count,
        GROUP_CONCAT(DISTINCT SUBSTRING(reason, 1, 100) SEPARATOR ' | ') AS reasons,
        MIN(log_date) AS first_seen,
        MAX(log_date) AS last_seen,
        COUNT(DISTINCT log_date) AS days_active
      FROM email_delivery_details
      WHERE log_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        AND (reason LIKE '%spam%' OR reason LIKE '%blocked%' OR reason LIKE '%blacklist%'
             OR reason LIKE '%spamhaus%' OR reason LIKE '%reject%' OR reason LIKE '%reputation%'
             OR reason LIKE '%DNSBL%' OR reason LIKE '%RBL%')
      GROUP BY mail_from
      ORDER BY count DESC
      LIMIT 50
    `);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/mails/distinct-statuses — available filter values
router.get('/filter-values', async (req, res) => {
  try {
    const [statuses] = await getPool(req.query.server).query(`SELECT DISTINCT status FROM email_delivery_details WHERE status IS NOT NULL LIMIT 30`);
    const [deliveries] = await getPool(req.query.server).query(`SELECT DISTINCT delivery_status FROM email_delivery_details WHERE delivery_status IS NOT NULL LIMIT 30`);
    const [campaigns] = await getPool(req.query.server).query(`SELECT DISTINCT campaign_id FROM email_delivery_details WHERE campaign_id IS NOT NULL ORDER BY campaign_id LIMIT 100`);
    const [dsns] = await getPool(req.query.server).query(`SELECT DISTINCT dsn FROM email_delivery_details WHERE dsn IS NOT NULL ORDER BY dsn LIMIT 30`);

    res.json({
      success: true,
      statuses: statuses.map(r => r.status),
      delivery_statuses: deliveries.map(r => r.delivery_status),
      campaigns: campaigns.map(r => r.campaign_id),
      dsn_codes: dsns.map(r => r.dsn)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
