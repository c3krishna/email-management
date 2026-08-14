// ============================================================
// /var/www/email-management/backend/routes/firewall.js
// Complete firewall + IP reputation + server metrics API
// ============================================================

const express    = require('express');
const router     = express.Router();
const mysql      = require('mysql2/promise');
const https      = require('https');
const http       = require('http');
const { verifyToken, requireRole } = require('../middleware/auth');

// ── DB pool ────────────────────────────────────────────────
let fwPool = null;
function getFWPool() {
  if (!fwPool) {
    fwPool = mysql.createPool({
      host:     process.env.DB_HOST || '10.180.0.84',
      port:            parseInt(process.env.DB_PORT) || 3306,
      user:     process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database:        'threat_platform',
      waitForConnections: true,
      connectionLimit: 10,
    });
  }
  return fwPool;
}

// ── Agent auth ─────────────────────────────────────────────
function agentAuth(req, res, next) {
  if (!process.env.AGENT_SECRET) {
    return res.status(500).json({ error: 'Server misconfigured: AGENT_SECRET is not set' });
  }
  if (req.headers['x-agent-secret'] !== process.env.AGENT_SECRET) {
    return res.status(401).json({ error: 'Invalid agent secret' });
  }
  next();
}

// ── Geo lookup cache ───────────────────────────────────────
const geoCache = new Map();

async function geoLookup(ip) {
  if (geoCache.has(ip)) return geoCache.get(ip);
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip)) {
    return { country_code: 'PRIV', country_name: 'Private Network' };
  }
  try {
    const result = await new Promise((resolve, reject) => {
      http.get(`http://ip-api.com/json/${ip}?fields=countryCode,country,city,isp,threat`, (res) => {
        let data = '';
        res.on('data', d => data += d);
        res.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { resolve({}); } });
      }).on('error', reject).setTimeout(3000, () => resolve({}));
    });
    const geo = {
      country_code: result.countryCode || null,
      country_name: result.country     || null,
      city:         result.city        || null,
      isp:          result.isp         || null,
    };
    geoCache.set(ip, geo);
    setTimeout(() => geoCache.delete(ip), 3600000); // 1hr TTL
    return geo;
  } catch(e) {
    return { country_code: null, country_name: null };
  }
}

// ── RBL check ──────────────────────────────────────────────
const RBL_LISTS = [
  'zen.spamhaus.org',
  'bl.spamcop.net',
  'dnsbl.sorbs.net',
  'b.barracudacentral.org',
  'psbl.surriel.com',
];

async function checkRBL(ip) {
  const reversed = ip.split('.').reverse().join('.');
  const results  = [];
  for (const rbl of RBL_LISTS) {
    try {
      const dns  = require('dns').promises;
      const host = `${reversed}.${rbl}`;
      await dns.lookup(host);
      results.push({ list: rbl, listed: true });
    } catch(e) {
      results.push({ list: rbl, listed: false });
    }
  }
  return results;
}

// ============================================================
// FIX: /api/stats/ip-reputation  (was returning 404)
// Called by IpReputationPage
// ============================================================
router.get('/ip-reputation', verifyToken, async (req, res) => {
  const { ip } = req.query;
  if (!ip) return res.status(400).json({ error: 'ip param required' });

  try {
    const pool = getFWPool();
    const geo  = await geoLookup(ip);

    // Get firewall events for this IP
    let fwStats = { denied: 0, allowed: 0, banned: 0, last_seen: null };
    let banInfo  = null;
    try {
      const [[stats]] = await pool.query(`
        SELECT
          SUM(CASE WHEN action='denied'  THEN 1 ELSE 0 END) AS denied,
          SUM(CASE WHEN action='allowed' THEN 1 ELSE 0 END) AS allowed,
          SUM(CASE WHEN action='banned'  THEN 1 ELSE 0 END) AS banned,
          MAX(log_datetime) AS last_seen
        FROM firewall_events WHERE src_ip = ?
      `, [ip]);
      fwStats = stats || fwStats;

      const [bans] = await pool.query(
        'SELECT * FROM firewall_bans WHERE ip_address=? AND active=1 LIMIT 1', [ip]
      );
      banInfo = bans[0] || null;
    } catch(e) { /* firewall tables may not exist yet */ }

    // Check RBL
    const rblResults = await checkRBL(ip);
    const blacklisted = rblResults.filter(r => r.listed);

    const score = Math.min(100,
      (blacklisted.length * 20) +
      (Number(fwStats.denied || 0) > 100 ? 30 : Number(fwStats.denied || 0) > 10 ? 15 : 0) +
      (banInfo ? 40 : 0)
    );

    res.json({
      success: true,
      ip,
      reputation_score: score,
      status: score >= 60 ? 'bad' : score >= 30 ? 'suspicious' : 'clean',
      geo,
      rbl: { checked: RBL_LISTS.length, listed: blacklisted.length, details: rblResults },
      firewall: fwStats,
      ban: banInfo,
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================================
// AGENT INGEST — POST /api/firewall/events
// ============================================================
router.post('/events', agentAuth, async (req, res) => {
  const { events = [], server } = req.body;
  if (!events.length) return res.json({ success: true, inserted: 0 });

  const pool = getFWPool();
  let inserted = 0;

  const CHUNK = 50;
  for (let i = 0; i < events.length; i += CHUNK) {
    const chunk = events.slice(i, i + CHUNK);

    // Geo for unique IPs (max 3 per batch to stay within free rate limit)
    const ips    = [...new Set(chunk.map(e => e.src_ip).filter(Boolean))].slice(0, 3);
    const geoMap = {};
    for (const ip of ips) geoMap[ip] = await geoLookup(ip);

    const values = chunk.map(e => {
      const geo = geoMap[e.src_ip] || {};
      return [
        e.server || server || 'app',
        (e.log_datetime || new Date().toISOString()).replace('T',' ').slice(0,19),
        e.event_type || 'unknown',
        e.src_ip     || '0.0.0.0',
        e.dst_ip     || null,
        e.protocol   || null,
        e.dst_port   ? parseInt(e.dst_port)  : null,
        e.src_port   ? parseInt(e.src_port)  : null,
        e.action     || 'denied',
        e.interface  || null,
        e.jail       || null,
        geo.country_code || null,
        geo.country_name || null,
        (e.raw_line  || '').slice(0, 300) || null,
      ];
    });

    try {
      await pool.query(
        `INSERT INTO firewall_events
           (server,log_datetime,event_type,src_ip,dst_ip,protocol,
            dst_port,src_port,action,interface_name,jail,
            country_code,country_name,raw_line)
         VALUES ?`,
        [values]
      );
      inserted += chunk.length;
    } catch(e) { console.error('[fw ingest]', e.message); }

    // Update bans table
    for (const e of chunk) {
      if (e.event_type === 'fail2ban_ban' && e.src_ip && e.jail) {
        try {
          const geo = geoMap[e.src_ip] || {};
          await pool.query(`
            INSERT INTO firewall_bans
              (server,ip_address,jail,banned_at,active,country_code,country_name)
            VALUES (?,?,?,?,1,?,?)
            ON DUPLICATE KEY UPDATE
              banned_at=VALUES(banned_at), ban_count=ban_count+1,
              active=1, unbanned_at=NULL
          `, [e.server||server, e.src_ip, e.jail,
              (e.log_datetime||new Date().toISOString()).replace('T',' ').slice(0,19),
              geo.country_code||null, geo.country_name||null]);
        } catch(err) {}
      } else if (e.event_type === 'fail2ban_unban' && e.src_ip) {
        try {
          await pool.query(
            `UPDATE firewall_bans SET active=0,unbanned_at=NOW()
             WHERE ip_address=? AND server=?`,
            [e.src_ip, e.server||server]
          );
        } catch(err) {}
      }
    }
  }
  res.json({ success: true, inserted });
});

// ============================================================
// DASHBOARD ENDPOINTS
// ============================================================

// GET /api/firewall/summary
router.get('/summary', verifyToken, async (req, res) => {
  try {
    const { server='all', hours=24 } = req.query;
    const pool   = getFWPool();
    const sWhere = server !== 'all' ? 'AND server=?' : '';
    const sParam = server !== 'all' ? [server] : [];

    const [[stats]] = await pool.query(`
      SELECT
        COUNT(*)                                                            AS total_events,
        SUM(CASE WHEN action='denied'           THEN 1 ELSE 0 END)         AS total_denied,
        SUM(CASE WHEN action='allowed'          THEN 1 ELSE 0 END)         AS total_allowed,
        SUM(CASE WHEN action='banned'           THEN 1 ELSE 0 END)         AS total_banned,
        SUM(CASE WHEN event_type='ssh_denied'   THEN 1 ELSE 0 END)         AS ssh_attacks,
        SUM(CASE WHEN event_type LIKE '%ratelimit%' THEN 1 ELSE 0 END)     AS smtp_ratelimit,
        SUM(CASE WHEN event_type='imap_ratelimit'   THEN 1 ELSE 0 END)     AS imap_ratelimit,
        SUM(CASE WHEN event_type='denied'           THEN 1 ELSE 0 END)     AS port_scans,
        COUNT(DISTINCT src_ip)                                              AS unique_ips,
        COUNT(DISTINCT country_code)                                        AS countries
      FROM firewall_events
      WHERE log_datetime >= DATE_SUB(NOW(), INTERVAL ? HOUR) ${sWhere}
    `, [parseInt(hours), ...sParam]);

    const [[bans]] = await pool.query(
      `SELECT COUNT(*) AS active_bans FROM firewall_bans WHERE active=1 ${sWhere}`,
      sParam
    );

    const [topAttackers] = await pool.query(`
      SELECT src_ip, country_code, country_name, COUNT(*) AS attempts,
             MAX(log_datetime) AS last_seen
      FROM firewall_events
      WHERE action='denied'
        AND log_datetime >= DATE_SUB(NOW(), INTERVAL ? HOUR) ${sWhere}
      GROUP BY src_ip, country_code, country_name
      ORDER BY attempts DESC LIMIT 10
    `, [parseInt(hours), ...sParam]);

    const [topPorts] = await pool.query(`
      SELECT dst_port, protocol, COUNT(*) AS attempts
      FROM firewall_events
      WHERE action='denied' AND dst_port IS NOT NULL
        AND log_datetime >= DATE_SUB(NOW(), INTERVAL ? HOUR) ${sWhere}
      GROUP BY dst_port, protocol
      ORDER BY attempts DESC LIMIT 10
    `, [parseInt(hours), ...sParam]);

    const [trend] = await pool.query(`
      SELECT
        DATE_FORMAT(log_datetime,'%H:%i') AS hour,
        SUM(CASE WHEN action='denied'  THEN 1 ELSE 0 END) AS denied,
        SUM(CASE WHEN action='allowed' THEN 1 ELSE 0 END) AS allowed,
        SUM(CASE WHEN action='banned'  THEN 1 ELSE 0 END) AS banned
      FROM firewall_events
      WHERE log_datetime >= DATE_SUB(NOW(), INTERVAL ? HOUR) ${sWhere}
      GROUP BY DATE_FORMAT(log_datetime,'%Y-%m-%d %H:%i')
      ORDER BY log_datetime ASC
    `, [parseInt(hours), ...sParam]);

    res.json({ success:true,
      data:{ stats:{...stats, active_bans:bans.active_bans}, topAttackers, topPorts, trend }
    });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// GET /api/firewall/events
router.get('/events', verifyToken, async (req, res) => {
  try {
    const { page=1, limit=100, action, server='all', ip, event_type, hours=24 } = req.query;
    const pool   = getFWPool();
    const where  = ['log_datetime >= DATE_SUB(NOW(), INTERVAL ? HOUR)'];
    const params = [parseInt(hours)];
    if (server !== 'all') { where.push('server=?');      params.push(server); }
    if (action)           { where.push('action=?');      params.push(action); }
    if (ip)               { where.push('src_ip LIKE ?'); params.push(`%${ip}%`); }
    if (event_type)       { where.push('event_type=?');  params.push(event_type); }
    const whereStr = where.join(' AND ');
    const offset   = (parseInt(page)-1) * parseInt(limit);
    const [[{total}]] = await pool.query(
      `SELECT COUNT(*) AS total FROM firewall_events WHERE ${whereStr}`, params
    );
    const [rows] = await pool.query(`
      SELECT id,server,log_datetime,event_type,src_ip,dst_ip,
             protocol,dst_port,src_port,action,jail,country_code,country_name
      FROM firewall_events WHERE ${whereStr}
      ORDER BY log_datetime DESC LIMIT ? OFFSET ?
    `, [...params, parseInt(limit), offset]);
    res.json({ success:true, data:rows, total, page:parseInt(page) });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// GET /api/firewall/bans
router.get('/bans', verifyToken, async (req, res) => {
  try {
    const { server='all', active='1' } = req.query;
    const pool   = getFWPool();
    const where  = [];
    const params = [];
    if (active !== 'all') { where.push('active=?');  params.push(active==='1'?1:0); }
    if (server !== 'all') { where.push('server=?');  params.push(server); }
    const whereStr = where.length ? 'WHERE '+where.join(' AND ') : '';
    const [rows] = await pool.query(
      `SELECT * FROM firewall_bans ${whereStr} ORDER BY banned_at DESC LIMIT 500`,
      params
    );
    res.json({ success:true, data:rows });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// GET /api/firewall/whitelist
router.get('/whitelist', verifyToken, async (req, res) => {
  try {
    const [rows] = await getFWPool().query(
      'SELECT * FROM firewall_whitelist WHERE active=1 ORDER BY created_at'
    );
    res.json({ success:true, data:rows });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// POST /api/firewall/whitelist
router.post('/whitelist', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  const { ip_cidr, description } = req.body;
  if (!ip_cidr) return res.status(400).json({ error:'ip_cidr required' });
  try {
    await getFWPool().query(
      `INSERT INTO firewall_whitelist (ip_cidr,description,added_by)
       VALUES (?,?,?) ON DUPLICATE KEY UPDATE active=1,description=?`,
      [ip_cidr, description||null, req.user?.email||'admin', description||null]
    );
    res.json({ success:true, message:`${ip_cidr} whitelisted` });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// POST /api/firewall/block
router.post('/block', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  const { ip_cidr, description, expires_hours } = req.body;
  if (!ip_cidr) return res.status(400).json({ error:'ip_cidr required' });
  try {
    const exp = expires_hours
      ? new Date(Date.now()+parseInt(expires_hours)*3600000).toISOString().replace('T',' ').slice(0,19)
      : null;
    await getFWPool().query(
      `INSERT INTO firewall_manual_blocks (ip_cidr,description,added_by,expires_at)
       VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE active=1,expires_at=?`,
      [ip_cidr, description||null, req.user?.email||'admin', exp, exp]
    );
    res.json({ success:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// GET /api/firewall/blocked
router.get('/blocked', verifyToken, async (req, res) => {
  try {
    const [rows] = await getFWPool().query(
      `SELECT * FROM firewall_manual_blocks
       WHERE active=1 AND (expires_at IS NULL OR expires_at>NOW())
       ORDER BY created_at DESC`
    );
    res.json({ success:true, data:rows });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// POST /api/firewall/unban
router.post('/unban', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  const { ip, jail, server } = req.body;
  if (!ip || !jail) return res.status(400).json({ error:'ip and jail required' });
  try {
    await getFWPool().query(
      `UPDATE firewall_bans SET active=0,unbanned_at=NOW()
       WHERE ip_address=? AND jail=? AND server=?`,
      [ip, jail, server]
    );
    res.json({ success:true, message:`${ip} unbanned from ${jail}` });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// GET /api/firewall/countries
router.get('/countries', verifyToken, async (req, res) => {
  try {
    const { hours=24, server='all' } = req.query;
    const pool   = getFWPool();
    const sWhere = server !== 'all' ? 'AND server=?' : '';
    const sParam = server !== 'all' ? [server] : [];
    const [rows] = await pool.query(`
      SELECT country_code, country_name,
             COUNT(*) AS attempts, COUNT(DISTINCT src_ip) AS unique_ips
      FROM firewall_events
      WHERE action='denied' AND country_code IS NOT NULL
        AND log_datetime >= DATE_SUB(NOW(), INTERVAL ? HOUR) ${sWhere}
      GROUP BY country_code, country_name
      ORDER BY attempts DESC LIMIT 30
    `, [parseInt(hours), ...sParam]);
    res.json({ success:true, data:rows });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ============================================================
// SERVER METRICS — GET /api/firewall/server-metrics
// Returns live metrics for both mail servers
// ============================================================
router.get('/server-metrics', verifyToken, async (req, res) => {
  try {
    const pool = getFWPool();

    // Get latest queue snapshots
    const { getPool } = require('../db');
    const emailPool   = getPool('app');

    const [queueApp] = await emailPool.query(`
      SELECT queue_count, deferred_count, active_count, incoming_count,
             snapshot_at, server_name
      FROM postfix_queue_snapshot
      WHERE server = 'app'
      ORDER BY id DESC LIMIT 1
    `).catch(() => [[]]);

    const emailPoolC = getPool('campaign');
    const [queueCamp] = await emailPoolC.query(`
      SELECT queue_count, deferred_count, active_count, incoming_count,
             snapshot_at, server_name
      FROM postfix_queue_snapshot
      WHERE server = 'campaign'
      ORDER BY id DESC LIMIT 1
    `).catch(() => [[]]);

    // Email volume last 24h per server
    const [volumeApp] = await emailPool.query(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS delivered,
        SUM(CASE WHEN status='bounced' OR delivery_status='bounced' THEN 1 ELSE 0 END) AS bounced,
        SUM(CASE WHEN status IN ('rejected','blocked') THEN 1 ELSE 0 END) AS rejected
      FROM email_delivery_details
      WHERE log_date >= DATE_SUB(CURDATE(), INTERVAL 1 DAY)
    `).catch(() => [[{}]]);

    const [volumeCamp] = await emailPoolC.query(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS delivered,
        SUM(CASE WHEN status='bounced' OR delivery_status='bounced' THEN 1 ELSE 0 END) AS bounced,
        SUM(CASE WHEN status IN ('rejected','blocked') THEN 1 ELSE 0 END) AS rejected
      FROM email_delivery_details
      WHERE log_date >= DATE_SUB(CURDATE(), INTERVAL 1 DAY)
    `).catch(() => [[{}]]);

    // Firewall stats per server last 1h
    const [fwApp] = await pool.query(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN action='denied' THEN 1 ELSE 0 END) AS denied,
        COUNT(DISTINCT src_ip) AS unique_ips
      FROM firewall_events
      WHERE server='app' AND log_datetime >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
    `).catch(() => [[{}]]);

    const [fwCamp] = await pool.query(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN action='denied' THEN 1 ELSE 0 END) AS denied,
        COUNT(DISTINCT src_ip) AS unique_ips
      FROM firewall_events
      WHERE server='campaign' AND log_datetime >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
    `).catch(() => [[{}]]);

    // Active bans per server
    const [[bansApp]]  = await pool.query(
      "SELECT COUNT(*) AS cnt FROM firewall_bans WHERE active=1 AND server='app'"
    ).catch(() => [[{cnt:0}]]);
    const [[bansCamp]] = await pool.query(
      "SELECT COUNT(*) AS cnt FROM firewall_bans WHERE active=1 AND server='campaign'"
    ).catch(() => [[{cnt:0}]]);

    res.json({
      success: true,
      servers: {
        app: {
          name:    'mail.worktual.tech',
          ip:      '10.180.0.84',
          vip:     '82.113.72.84',
          queue:   queueApp[0]   || null,
          volume:  volumeApp[0]  || null,
          firewall:{ ...(fwApp[0]||{}), active_bans: bansApp.cnt },
        },
        campaign: {
          name:    'mail.worktual.pl',
          ip:      '10.180.0.89',
          vip:     '82.113.72.80',
          queue:   queueCamp[0]  || null,
          volume:  volumeCamp[0] || null,
          firewall:{ ...(fwCamp[0]||{}), active_bans: bansCamp.cnt },
        },
      },
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================================
// WAVEFORM DATA — GET /api/firewall/waveform
// Returns per-minute hit counts for last N hours (sparkline)
// ============================================================
router.get('/waveform', verifyToken, async (req, res) => {
  try {
    const { server='all', hours=1 } = req.query;
    const pool   = getFWPool();
    const sWhere = server !== 'all' ? 'AND server=?' : '';
    const sParam = server !== 'all' ? [server] : [];

    const [rows] = await pool.query(`
      SELECT
        DATE_FORMAT(log_datetime,'%Y-%m-%d %H:%i') AS minute,
        SUM(CASE WHEN action='denied'  THEN 1 ELSE 0 END) AS denied,
        SUM(CASE WHEN action='allowed' THEN 1 ELSE 0 END) AS allowed,
        SUM(CASE WHEN action='banned'  THEN 1 ELSE 0 END) AS banned,
        COUNT(*) AS total
      FROM firewall_events
      WHERE log_datetime >= DATE_SUB(NOW(), INTERVAL ? HOUR) ${sWhere}
      GROUP BY DATE_FORMAT(log_datetime,'%Y-%m-%d %H:%i')
      ORDER BY minute ASC
    `, [parseInt(hours), ...sParam]);

    res.json({ success:true, data:rows });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

module.exports = router;
