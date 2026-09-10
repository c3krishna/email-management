const express = require('express');
const router = express.Router();
const { getPool } = require('../db');
const {
  normalizeServer,
  buildDateFilter,
  buildDirectionSql,
  istToday,
} = require('../mailServers');

// ---- helpers ----

function poolFor(req) {
  return getPool(normalizeServer(req.query.server, 'app'));
}

/** Realtime date filter using DATE(log_datetime) */
function buildRealtimeDateFilter(range, date, from, to) {
  if (range === 'custom' && from && to) {
    return { dateFilter: 'DATE(log_datetime) BETWEEN ? AND ?', params: [from, to] };
  }
  if (range === 'today' || (date && range !== '7d' && range !== '30d')) {
    const d = date || istToday();
    return { dateFilter: 'DATE(log_datetime) = ?', params: [d] };
  }
  if (range === '7d') {
    return { dateFilter: 'DATE(log_datetime) >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)', params: [] };
  }
  if (range === '30d') {
    return { dateFilter: 'DATE(log_datetime) >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)', params: [] };
  }
  return { dateFilter: 'DATE(log_datetime) = CURDATE()', params: [] };
}

async function summarizeFromRealtime(pool, range, date, from, to, server) {
  const { dateFilter, params } = buildRealtimeDateFilter(range, date, from, to);
  const { outboundSql, inboundSql } = buildDirectionSql(server);

  const [rows] = await pool.query(`
    SELECT
      COUNT(*) AS total,
      ${outboundSql} AS outbound,
      ${inboundSql} AS inbound,
      SUM(CASE WHEN status IN ('sent','delivered','ok','2.0.0')
                 OR LOWER(COALESCE(status,'')) IN ('sent','delivered') THEN 1 ELSE 0 END) AS success,
      SUM(CASE WHEN status = 'failed' OR LOWER(COALESCE(status,'')) = 'failed' THEN 1 ELSE 0 END) AS failed,
      SUM(CASE WHEN status = 'bounced' OR COALESCE(dsn,'') LIKE '5%' THEN 1 ELSE 0 END) AS bounced,
      SUM(CASE WHEN status = 'deferred' OR COALESCE(dsn,'') LIKE '4%' THEN 1 ELSE 0 END) AS deferred,
      SUM(CASE WHEN status = 'timeout' OR COALESCE(reason,'') LIKE '%timeout%' THEN 1 ELSE 0 END) AS timedout,
      SUM(CASE WHEN COALESCE(reason,'') LIKE '%spam%' OR COALESCE(reason,'') LIKE '%blocked%'
                 OR COALESCE(classification,'') LIKE '%spam%' THEN 1 ELSE 0 END) AS spam_blocked,
      SUM(CASE WHEN COALESCE(reason,'') LIKE '%phish%' OR COALESCE(reason,'') LIKE '%malware%'
                 OR COALESCE(reason,'') LIKE '%virus%' THEN 1 ELSE 0 END) AS threats,
      SUM(CASE WHEN status = 'invalid' OR dsn = '5.1.1' THEN 1 ELSE 0 END) AS invalid_addr,
      0 AS processing,
      SUM(CASE WHEN status IN ('failed','bounced','invalid','spam')
                 OR COALESCE(dsn,'') LIKE '5%' THEN 1 ELSE 0 END) AS wrong_hits,
      0 AS quarantined,
      AVG(duration_ms) AS avg_duration,
      0 AS total_campaigns,
      COUNT(DISTINCT mail_from) AS unique_senders
    FROM email_log_realtime
    WHERE ${dateFilter}
  `, params);

  return rows[0] || null;
}

async function maybeRealtimeFallback(pool, deliveryRow, range, date, from, to, server) {
  const total = Number(deliveryRow?.total || 0);
  if (total > 0) {
    return { ...deliveryRow, data_source: 'email_delivery_details' };
  }
  try {
    const rt = await summarizeFromRealtime(pool, range, date, from, to, server);
    if (rt && Number(rt.total || 0) > 0) {
      return { ...rt, data_source: 'email_log_realtime', fallback: true };
    }
  } catch (e) {
    // realtime table may be missing on some hosts
    console.warn('[stats] realtime fallback failed:', e.message);
  }
  return { ...deliveryRow, data_source: 'email_delivery_details', fallback: false };
}

const pct = (curr, prev) => {
  if (!prev || prev === 0) return curr > 0 ? 100 : 0;
  return Math.round(((curr - prev) / prev) * 100);
};

// GET /api/stats/summary?date=YYYY-MM-DD&range=today|7d|30d|custom&from=&to=
router.get('/summary', async (req, res) => {
  try {
    const { date, range = 'today', from, to } = req.query;
    const server = normalizeServer(req.query.server, 'app');
    const pool = getPool(server);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    const [rows] = await pool.query(`
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

    const data = await maybeRealtimeFallback(pool, rows[0], range, date, from, to, server);
    res.json({ success: true, data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/trend?range=today|7d|30d|custom&date=&from=&to=&campaign_id=
router.get('/trend', async (req, res) => {
  try {
    const { range = '7d', campaign_id, date, from, to } = req.query;
    const pool = poolFor(req);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    let whereExtra = '';
    const qParams = [...params];
    if (campaign_id) {
      whereExtra = 'AND campaign_id = ?';
      qParams.push(campaign_id);
    }

    let [rows] = await pool.query(`
      SELECT
        log_date,
        COUNT(*) AS total,
        CAST(SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS SIGNED) AS success,
        CAST(SUM(CASE WHEN status = 'failed' OR delivery_status = 'failed' THEN 1 ELSE 0 END) AS SIGNED) AS failed,
        CAST(SUM(CASE WHEN status = 'bounced' OR delivery_status = 'bounced' OR dsn LIKE '5%' THEN 1 ELSE 0 END) AS SIGNED) AS bounced,
        CAST(SUM(CASE WHEN status = 'deferred' OR delivery_status = 'deferred' OR dsn LIKE '4%' THEN 1 ELSE 0 END) AS SIGNED) AS deferred,
        CAST(SUM(CASE WHEN reason LIKE '%spam%' OR reason LIKE '%blocked%' OR reason LIKE '%blacklist%' THEN 1 ELSE 0 END) AS SIGNED) AS spam_blocked
      FROM email_delivery_details
      WHERE ${dateFilter}
      ${whereExtra}
      GROUP BY log_date
      ORDER BY log_date ASC
    `, qParams);

    // Realtime fallback when delivery table empty for window
    if (!rows.length) {
      try {
        const rt = buildRealtimeDateFilter(range, date, from, to);
        const [rtRows] = await pool.query(`
          SELECT
            DATE(log_datetime) AS log_date,
            COUNT(*) AS total,
            CAST(SUM(CASE WHEN status IN ('sent','delivered','ok') THEN 1 ELSE 0 END) AS SIGNED) AS success,
            CAST(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS SIGNED) AS failed,
            CAST(SUM(CASE WHEN status = 'bounced' OR COALESCE(dsn,'') LIKE '5%' THEN 1 ELSE 0 END) AS SIGNED) AS bounced,
            CAST(SUM(CASE WHEN status = 'deferred' OR COALESCE(dsn,'') LIKE '4%' THEN 1 ELSE 0 END) AS SIGNED) AS deferred,
            CAST(SUM(CASE WHEN COALESCE(reason,'') LIKE '%spam%' OR COALESCE(reason,'') LIKE '%blocked%' THEN 1 ELSE 0 END) AS SIGNED) AS spam_blocked
          FROM email_log_realtime
          WHERE ${rt.dateFilter}
          GROUP BY DATE(log_datetime)
          ORDER BY log_date ASC
        `, rt.params);
        rows = rtRows;
      } catch { /* ignore */ }
    }

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/hourly?date=YYYY-MM-DD
router.get('/hourly', async (req, res) => {
  try {
    const { date, range = 'today' } = req.query;
    const targetDate = date || istToday();
    const pool = poolFor(req);

    let [rows] = await pool.query(`
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

    if (!rows.length && (range === 'today' || date)) {
      try {
        const [rtRows] = await pool.query(`
          SELECT
            HOUR(log_datetime) AS hour,
            COUNT(*) AS total,
            SUM(CASE WHEN status IN ('sent','delivered','ok') THEN 1 ELSE 0 END) AS success,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
            SUM(CASE WHEN status = 'bounced' OR COALESCE(dsn,'') LIKE '5%' THEN 1 ELSE 0 END) AS bounced,
            SUM(CASE WHEN status = 'deferred' THEN 1 ELSE 0 END) AS deferred
          FROM email_log_realtime
          WHERE DATE(log_datetime) = ?
          GROUP BY HOUR(log_datetime)
          ORDER BY hour ASC
        `, [targetDate]);
        rows = rtRows;
      } catch { /* ignore */ }
    }

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/by-campaign?range=today|7d|30d|custom&limit=20
router.get('/by-campaign', async (req, res) => {
  try {
    const { range = '7d', limit = 20, date, from, to } = req.query;
    const pool = poolFor(req);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    const [rows] = await pool.query(`
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
      WHERE ${dateFilter}
        AND campaign_id IS NOT NULL
      GROUP BY campaign_id
      ORDER BY total DESC
      LIMIT ?
    `, [...params, parseInt(limit)]);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/failure-reasons?range=today|7d|30d|custom&limit=20
router.get('/failure-reasons', async (req, res) => {
  try {
    const { range = '7d', limit = 20, date, from, to } = req.query;
    const pool = poolFor(req);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    const [rows] = await pool.query(`
      SELECT
        COALESCE(reason, 'Unknown') AS reason,
        dsn,
        status,
        delivery_status,
        COUNT(*) AS count,
        COUNT(DISTINCT mail_from) AS affected_senders,
        COUNT(DISTINCT campaign_id) AS affected_campaigns
      FROM email_delivery_details
      WHERE ${dateFilter}
        AND (status IN ('failed','bounced','deferred','invalid','timeout')
          OR delivery_status IN ('failed','bounced','deferred','invalid','timeout'))
      GROUP BY reason, dsn, status, delivery_status
      ORDER BY count DESC
      LIMIT ?
    `, [...params, parseInt(limit)]);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/by-sender?range=today|7d|30d|custom
router.get('/by-sender', async (req, res) => {
  try {
    const { range = '7d', limit = 15, date, from, to } = req.query;
    const pool = poolFor(req);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    const [rows] = await pool.query(`
      SELECT
        mail_from,
        COUNT(*) AS total,
        SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS success,
        SUM(CASE WHEN status = 'failed' OR delivery_status = 'failed' THEN 1 ELSE 0 END) AS failed,
        SUM(CASE WHEN status = 'bounced' OR delivery_status = 'bounced' OR dsn LIKE '5%' THEN 1 ELSE 0 END) AS bounced,
        ROUND(SUM(CASE WHEN status = 'failed' OR delivery_status = 'failed' OR status = 'bounced' OR delivery_status = 'bounced' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) AS failure_rate
      FROM email_delivery_details
      WHERE ${dateFilter}
        AND mail_from IS NOT NULL
      GROUP BY mail_from
      ORDER BY total DESC
      LIMIT ?
    `, [...params, parseInt(limit)]);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/dsn-breakdown?range=today|7d|30d|custom
router.get('/dsn-breakdown', async (req, res) => {
  try {
    const { range = '7d', date, from, to } = req.query;
    const pool = poolFor(req);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    const [rows] = await pool.query(`
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
      WHERE ${dateFilter}
        AND dsn IS NOT NULL
      GROUP BY dsn
      ORDER BY count DESC
      LIMIT 30
    `, params);

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/enhanced-summary?range=today&date=&server=app|campaign
router.get('/enhanced-summary', async (req, res) => {
  try {
    const { range = 'today', date, from, to } = req.query;
    const server = normalizeServer(req.query.server, 'app');
    const pool = getPool(server);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);
    const { outboundSql, inboundSql } = buildDirectionSql(server);

    const [today] = await pool.query(`
      SELECT
        COUNT(*) AS total,
        ${outboundSql} AS outbound,
        ${inboundSql} AS inbound,
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
        SUM(CASE WHEN status IN ('failed','bounced','invalid','spam')
                  OR delivery_status IN ('failed','bounced','invalid')
                  OR dsn LIKE '5%'                                                                THEN 1 ELSE 0 END) AS wrong_hits,
        SUM(CASE WHEN reason LIKE '%quarantine%' OR reason LIKE '%Quarantine%'                   THEN 1 ELSE 0 END) AS quarantined,
        AVG(duration)                                                                              AS avg_duration,
        COUNT(DISTINCT campaign_id)                                                                AS total_campaigns,
        COUNT(DISTINCT mail_from)                                                                  AS unique_senders
      FROM email_delivery_details
      WHERE ${dateFilter}
    `, params);

    const t = await maybeRealtimeFallback(pool, today[0], range, date, from, to, server);

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
    `).catch(() => [[{}]]);

    const y = yesterday[0] || {};

    res.json({
      success: true,
      data: {
        ...t,
        vs_yesterday: {
          total:        pct(Number(t.total || 0),        Number(y.total || 0)),
          success:      pct(Number(t.success || 0),      Number(y.success || 0)),
          failed:       pct(Number(t.failed || 0),       Number(y.failed || 0)),
          bounced:      pct(Number(t.bounced || 0),      Number(y.bounced || 0)),
          spam_blocked: pct(Number(t.spam_blocked || 0), Number(y.spam_blocked || 0)),
          wrong_hits:   pct(Number(t.wrong_hits || 0),   Number(y.wrong_hits || 0)),
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
    const pool = poolFor(req);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    let [rows] = await pool.query(`
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

    if (!rows.length) {
      try {
        const rt = buildRealtimeDateFilter(range, date, from, to);
        const [rtRows] = await pool.query(`
          SELECT
            mail_from AS email,
            COUNT(*) AS total,
            SUM(CASE WHEN status IN ('sent','delivered','ok') THEN 1 ELSE 0 END) AS success,
            SUM(CASE WHEN status IN ('failed','bounced') THEN 1 ELSE 0 END) AS failed
          FROM email_log_realtime
          WHERE ${rt.dateFilter} AND mail_from IS NOT NULL AND mail_from != ''
          GROUP BY mail_from
          ORDER BY total DESC
          LIMIT ?
        `, [...rt.params, parseInt(limit)]);
        rows = rtRows;
      } catch { /* ignore */ }
    }

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/top-recipients?range=today&limit=10
router.get('/top-recipients', async (req, res) => {
  try {
    const { range = 'today', date, from, to, limit = 10 } = req.query;
    const pool = poolFor(req);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    let [rows] = await pool.query(`
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

    if (!rows.length) {
      try {
        const rt = buildRealtimeDateFilter(range, date, from, to);
        const [rtRows] = await pool.query(`
          SELECT
            mail_to AS email,
            COUNT(*) AS total,
            SUM(CASE WHEN status IN ('sent','delivered','ok') THEN 1 ELSE 0 END) AS success,
            SUM(CASE WHEN status = 'bounced' OR COALESCE(dsn,'') LIKE '5.1%' THEN 1 ELSE 0 END) AS bounced
          FROM email_log_realtime
          WHERE ${rt.dateFilter} AND mail_to IS NOT NULL AND mail_to != ''
          GROUP BY mail_to
          ORDER BY total DESC
          LIMIT ?
        `, [...rt.params, parseInt(limit)]);
        rows = rtRows;
      } catch { /* ignore */ }
    }

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/wrong-hits-trend?range=today|7d|30d|custom
router.get('/wrong-hits-trend', async (req, res) => {
  try {
    const { range = '7d', date, from, to } = req.query;
    const pool = poolFor(req);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    let [rows] = await pool.query(`
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
      WHERE ${dateFilter}
      GROUP BY log_date
      ORDER BY log_date ASC
    `, params);

    if (!rows.length) {
      try {
        const rt = buildRealtimeDateFilter(range, date, from, to);
        const [rtRows] = await pool.query(`
          SELECT
            DATE(log_datetime) AS log_date,
            COUNT(*) AS total,
            CAST(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS SIGNED) AS failed,
            CAST(SUM(CASE WHEN status = 'bounced' OR COALESCE(dsn,'') LIKE '5%' THEN 1 ELSE 0 END) AS SIGNED) AS bounced,
            CAST(SUM(CASE WHEN COALESCE(reason,'') LIKE '%spam%' OR COALESCE(reason,'') LIKE '%blocked%' THEN 1 ELSE 0 END) AS SIGNED) AS spam,
            CAST(SUM(CASE WHEN status = 'invalid' OR dsn = '5.1.1' THEN 1 ELSE 0 END) AS SIGNED) AS invalid,
            CAST(SUM(CASE WHEN status = 'timeout' THEN 1 ELSE 0 END) AS SIGNED) AS timeout,
            CAST(SUM(CASE WHEN status IN ('failed','bounced','invalid','spam')
                           OR COALESCE(dsn,'') LIKE '5%' THEN 1 ELSE 0 END) AS SIGNED) AS total_wrong
          FROM email_log_realtime
          WHERE ${rt.dateFilter}
          GROUP BY DATE(log_datetime)
          ORDER BY log_date ASC
        `, rt.params);
        rows = rtRows;
      } catch { /* ignore */ }
    }

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/threat-breakdown?range=today
router.get('/threat-breakdown', async (req, res) => {
  try {
    const { range = 'today', date, from, to } = req.query;
    const pool = poolFor(req);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);

    let [rows] = await pool.query(`
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

    const row = rows[0] || {};
    const sum = Object.values(row).reduce((a, v) => a + Number(v || 0), 0);
    if (sum === 0) {
      try {
        const rt = buildRealtimeDateFilter(range, date, from, to);
        const [rtRows] = await pool.query(`
          SELECT
            CAST(SUM(CASE WHEN status IN ('sent','delivered','ok') THEN 1 ELSE 0 END) AS SIGNED) AS clean,
            CAST(SUM(CASE WHEN COALESCE(reason,'') LIKE '%spam%' OR COALESCE(classification,'') LIKE '%spam%' THEN 1 ELSE 0 END) AS SIGNED) AS spam,
            CAST(SUM(CASE WHEN COALESCE(reason,'') LIKE '%phish%' THEN 1 ELSE 0 END) AS SIGNED) AS phishing,
            CAST(SUM(CASE WHEN COALESCE(reason,'') LIKE '%virus%' OR COALESCE(reason,'') LIKE '%malware%' THEN 1 ELSE 0 END) AS SIGNED) AS malware,
            CAST(SUM(CASE WHEN COALESCE(reason,'') LIKE '%reject%' OR COALESCE(reason,'') LIKE '%blocked%' THEN 1 ELSE 0 END) AS SIGNED) AS blocked,
            CAST(SUM(CASE WHEN status = 'bounced' OR COALESCE(dsn,'') LIKE '5%' THEN 1 ELSE 0 END) AS SIGNED) AS bounced,
            CAST(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS SIGNED) AS failed,
            CAST(SUM(CASE WHEN status = 'deferred' OR COALESCE(dsn,'') LIKE '4%' THEN 1 ELSE 0 END) AS SIGNED) AS deferred
          FROM email_log_realtime
          WHERE ${rt.dateFilter}
        `, rt.params);
        rows = rtRows;
      } catch { /* ignore */ }
    }

    res.json({ success: true, data: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/stats/recent-logs?limit=20
router.get('/recent-logs', async (req, res) => {
  try {
    const { range = 'today', date, from, to, limit = 20 } = req.query;
    const server = normalizeServer(req.query.server, 'app');
    const pool = getPool(server);
    const { dateFilter, params } = buildDateFilter(range, date, from, to);
    const { directionCase } = buildDirectionSql(server);

    let [rows] = await pool.query(`
      SELECT
        id, log_date, log_time, mail_from, mail_to,
        campaign_id, status, delivery_status, dsn, reason, duration,
        ${directionCase} AS direction,
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

    if (!rows.length) {
      try {
        const rt = buildRealtimeDateFilter(range, date, from, to);
        const [rtRows] = await pool.query(`
          SELECT
            id, DATE(log_datetime) AS log_date, TIME(log_datetime) AS log_time,
            mail_from, mail_to, NULL AS campaign_id, status, status AS delivery_status,
            dsn, reason, duration_ms AS duration,
            COALESCE(direction,
              CASE WHEN mail_from LIKE '%@worktual%' THEN 'Outbound' ELSE 'Inbound' END
            ) AS direction,
            CASE
              WHEN status IN ('sent','delivered','ok') THEN 'Delivered'
              WHEN status = 'bounced' OR COALESCE(dsn,'') LIKE '5%' THEN 'Bounced'
              WHEN status = 'failed' THEN 'Failed'
              WHEN status = 'deferred' THEN 'Deferred'
              ELSE 'Processing'
            END AS action,
            COALESCE(classification, 'Other') AS threat_type
          FROM email_log_realtime
          WHERE ${rt.dateFilter}
          ORDER BY log_datetime DESC
          LIMIT ?
        `, [...rt.params, parseInt(limit)]);
        rows = rtRows;
      } catch { /* ignore */ }
    }

    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
