// /var/www/email-management/backend/routes/reports.js
// Report generation endpoint for Phase 3

const express = require('express');
const router  = express.Router();
const { getPool } = require('../db');
const { verifyToken } = require('../middleware/auth');

// ── Date filter helper ──────────────────────────────────────
function dateFilter(from, to, field = 'log_date') {
  return { sql: `${field} BETWEEN ? AND ?`, params: [from, to] };
}

// ── CSV builder ─────────────────────────────────────────────
function toCSV(rows) {
  if (!rows || rows.length === 0) return '';
  const headers = Object.keys(rows[0]).join(',');
  const lines   = rows.map(r =>
    Object.values(r).map(v =>
      v === null || v === undefined ? '' :
      String(v).includes(',') ? `"${String(v).replace(/"/g,'""')}"` : String(v)
    ).join(',')
  );
  return [headers, ...lines].join('\n');
}

// ── GET /api/reports/generate ───────────────────────────────
router.get('/generate', verifyToken, async (req, res) => {
  const { type, from, to, server = 'app', format = 'json', limit = 20 } = req.query;

  if (!type || !from || !to) {
    return res.status(400).json({ error: 'type, from, to are required' });
  }

  const pool   = getPool(server);
  const lim    = Math.min(parseInt(limit) || 20, 10000);
  const isJSON = format !== 'csv';

  try {
    let data, summary, total;

    switch (type) {

      // ── Delivery Summary ──────────────────────────────────
      case 'delivery_summary': {
        const [rows] = await pool.query(`
          SELECT
            log_date                                                                    AS date,
            COUNT(*)                                                                    AS total,
            SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS delivered,
            SUM(CASE WHEN status = 'failed'   OR delivery_status = 'failed'   THEN 1 ELSE 0 END) AS failed,
            SUM(CASE WHEN status = 'bounced'  OR delivery_status = 'bounced'  OR dsn LIKE '5%' THEN 1 ELSE 0 END) AS bounced,
            SUM(CASE WHEN status = 'deferred' OR delivery_status = 'deferred' THEN 1 ELSE 0 END) AS deferred,
            ROUND(SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) AS delivery_rate_pct,
            COUNT(DISTINCT campaign_id) AS campaigns,
            COUNT(DISTINCT mail_from)   AS unique_senders,
            ROUND(AVG(duration), 1)     AS avg_duration_sec
          FROM email_delivery_details
          WHERE log_date BETWEEN ? AND ?
          GROUP BY log_date
          ORDER BY log_date ASC
          LIMIT ?
        `, [from, to, lim]);
        total   = rows.length;
        data    = rows;
        summary = rows.reduce((a, r) => ({
          total:     (a.total     || 0) + Number(r.total    || 0),
          delivered: (a.delivered || 0) + Number(r.delivered|| 0),
          failed:    (a.failed    || 0) + Number(r.failed   || 0),
          bounced:   (a.bounced   || 0) + Number(r.bounced  || 0),
        }), {});
        break;
      }

      // ── Threat Report ─────────────────────────────────────
      case 'threat_report': {
        let threatPool;
        try {
          const mysql = require('mysql2/promise');
          threatPool  = mysql.createPool({
            host:     process.env.DB_HOST || '10.180.0.84',
            user:     process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: 'threat_platform',
            waitForConnections: true, connectionLimit: 5,
          });
        } catch(e) {
          return res.status(500).json({ error: 'Threat DB not available' });
        }

        const [rows] = await threatPool.query(`
          SELECT
            DATE(created_at)  AS date,
            indicator_type,
            threat_type,
            severity,
            COUNT(*)          AS new_indicators,
            AVG(confidence)   AS avg_confidence,
            MAX(confidence)   AS max_confidence
          FROM threat_indicators
          WHERE DATE(created_at) BETWEEN ? AND ?
          GROUP BY DATE(created_at), indicator_type, threat_type, severity
          ORDER BY date DESC, new_indicators DESC
          LIMIT ?
        `, [from, to, lim]);

        total   = rows.length;
        data    = rows;
        summary = { total_indicators: rows.reduce((a,r) => a + Number(r.new_indicators||0), 0) };
        await threatPool.end();
        break;
      }

      // ── Top Senders ───────────────────────────────────────
      case 'top_senders': {
        const [rows] = await pool.query(`
          SELECT
            mail_from                                                                   AS sender,
            COUNT(*)                                                                    AS total_emails,
            SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS delivered,
            SUM(CASE WHEN status = 'failed'  OR delivery_status = 'failed'   THEN 1 ELSE 0 END) AS failed,
            SUM(CASE WHEN status = 'bounced' OR delivery_status = 'bounced'  THEN 1 ELSE 0 END) AS bounced,
            ROUND(SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) AS success_rate_pct,
            COUNT(DISTINCT mail_to)    AS unique_recipients,
            COUNT(DISTINCT campaign_id) AS campaigns,
            MIN(log_date)              AS first_seen,
            MAX(log_date)              AS last_seen
          FROM email_delivery_details
          WHERE log_date BETWEEN ? AND ?
            AND mail_from IS NOT NULL AND mail_from != ''
          GROUP BY mail_from
          ORDER BY total_emails DESC
          LIMIT ?
        `, [from, to, lim]);
        total   = rows.length;
        data    = rows;
        summary = { unique_senders: rows.length,
                    total_emails: rows.reduce((a,r) => a + Number(r.total_emails||0), 0) };
        break;
      }

      // ── Bounce Analysis ───────────────────────────────────
      case 'bounce_analysis': {
        const [rows] = await pool.query(`
          SELECT
            log_date                AS date,
            mail_from               AS sender,
            mail_to                 AS recipient,
            dsn                     AS dsn_code,
            LEFT(reason, 300)       AS reason,
            status,
            delivery_status,
            campaign_id
          FROM email_delivery_details
          WHERE log_date BETWEEN ? AND ?
            AND (status = 'bounced' OR delivery_status = 'bounced'
                 OR dsn LIKE '5%')
          ORDER BY log_date DESC
          LIMIT ?
        `, [from, to, lim]);

        const [dsn] = await pool.query(`
          SELECT
            COALESCE(dsn,'unknown') AS dsn_code,
            COUNT(*)                AS count,
            LEFT(MAX(reason),200)   AS common_reason
          FROM email_delivery_details
          WHERE log_date BETWEEN ? AND ?
            AND (status='bounced' OR delivery_status='bounced' OR dsn LIKE '5%')
          GROUP BY dsn
          ORDER BY count DESC
          LIMIT 20
        `, [from, to]);

        total   = rows.length;
        data    = isJSON ? rows : rows;
        summary = {
          total_bounces: rows.length,
        };
        // attach dsn breakdown separately
        if (isJSON) data = { records: rows, dsn_breakdown: dsn };
        else data = rows;
        break;
      }

      // ── Spam Report ───────────────────────────────────────
      case 'spam_report': {
        const [rows] = await pool.query(`
          SELECT
            log_date            AS date,
            mail_from           AS sender,
            mail_to             AS recipient,
            LEFT(reason,300)    AS reason,
            status,
            dsn,
            campaign_id
          FROM email_delivery_details
          WHERE log_date BETWEEN ? AND ?
            AND (status IN ('rejected','blocked')
                 OR delivery_status IN ('rejected','blocked')
                 OR reason LIKE '%spam%'
                 OR reason LIKE '%blocked%'
                 OR reason LIKE '%DNSBL%'
                 OR dsn LIKE '5.7%')
          ORDER BY log_date DESC
          LIMIT ?
        `, [from, to, lim]);
        total   = rows.length;
        data    = rows;
        summary = { total_blocked: rows.length };
        break;
      }

      // ── Campaign Report ───────────────────────────────────
      case 'campaign_report': {
        const [rows] = await pool.query(`
          SELECT
            edd.campaign_id,
            MIN(edd.log_date)                AS start_date,
            MAX(edd.log_date)                AS end_date,
            COUNT(*)                         AS total_sent,
            SUM(CASE WHEN edd.status IN ('sent','delivered') OR edd.delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS delivered,
            SUM(CASE WHEN edd.status = 'bounced' OR edd.delivery_status = 'bounced' THEN 1 ELSE 0 END) AS bounced,
            SUM(CASE WHEN edd.status = 'failed'  OR edd.delivery_status = 'failed'  THEN 1 ELSE 0 END) AS failed,
            ROUND(SUM(CASE WHEN edd.status IN ('sent','delivered') OR edd.delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) AS success_rate_pct,
            COUNT(DISTINCT edd.mail_to)  AS unique_recipients,
            ROUND(AVG(edd.duration), 1)  AS avg_duration_sec
          FROM email_delivery_details edd
          WHERE edd.log_date BETWEEN ? AND ?
            AND edd.campaign_id IS NOT NULL
          GROUP BY edd.campaign_id
          ORDER BY total_sent DESC
          LIMIT ?
        `, [from, to, lim]);
        total   = rows.length;
        data    = rows;
        summary = {
          total_campaigns: rows.length,
          total_emails: rows.reduce((a,r) => a + Number(r.total_sent||0), 0),
        };
        break;
      }

      default:
        return res.status(400).json({ error: `Unknown report type: ${type}` });
    }

    // ── Response ────────────────────────────────────────────
    if (format === 'csv') {
      const csv = toCSV(data);
      res.set({
        'Content-Type':        'text/csv',
        'Content-Disposition': `attachment; filename="${type}_${from}_${to}.csv"`,
      });
      return res.send(csv);
    }

    res.json({
      success: true,
      report_type: type,
      server,
      date_range: { from, to },
      total,
      summary,
      data,
    });

  } catch (err) {
    console.error('[reports]', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
