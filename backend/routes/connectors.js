// ============================================================
// Connector Management API
// /var/www/email-management/backend/routes/connectors.js
// Manages platform connectors per customer
// ============================================================

const express  = require('express');
const router   = express.Router();
const mysql    = require('mysql2/promise');
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

const PLATFORM_INFO = {
  proofpoint: {
    label:       'Proofpoint TAP',
    icon:        '🛡️',
    description: 'Proofpoint Targeted Attack Protection API',
    cred_fields: [
      { key:'service_principal', label:'Service Principal', type:'text',     required:true  },
      { key:'secret_key',        label:'Secret Key',        type:'password', required:true  },
      { key:'tenant_id',         label:'Tenant ID',         type:'text',     required:false },
    ],
    docs_url: 'https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation',
  },
  microsoft_defender: {
    label:       'Microsoft Defender / O365',
    icon:        '🪟',
    description: 'Microsoft Defender for Office 365 via Graph API',
    cred_fields: [
      { key:'tenant_id',     label:'Azure Tenant ID',   type:'text',     required:true },
      { key:'client_id',     label:'Client ID',         type:'text',     required:true },
      { key:'client_secret', label:'Client Secret',     type:'password', required:true },
    ],
    docs_url: 'https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview',
  },
  google_workspace: {
    label:       'Google Workspace',
    icon:        '🔵',
    description: 'Google Workspace via Admin SDK Reports API',
    cred_fields: [
      { key:'admin_email',          label:'Admin Email',           type:'text',     required:true },
      { key:'customer_domain',      label:'Domain (e.g. company.com)',type:'text',  required:true },
      { key:'service_account_json', label:'Service Account JSON',  type:'textarea', required:true },
    ],
    docs_url: 'https://developers.google.com/admin-sdk/reports',
  },
  mimecast: {
    label:       'Mimecast',
    icon:        '🔐',
    description: 'Mimecast Email Security REST API',
    cred_fields: [
      { key:'base_url',   label:'Base URL (region)',  type:'text',     required:true },
      { key:'app_id',     label:'Application ID',     type:'text',     required:true },
      { key:'app_key',    label:'Application Key',    type:'password', required:true },
      { key:'access_key', label:'Access Key',         type:'password', required:true },
      { key:'secret_key', label:'Secret Key',         type:'password', required:true },
    ],
    docs_url: 'https://www.mimecast.com/tech-connect/documentation/',
  },
  barracuda: {
    label:       'Barracuda Email Security',
    icon:        '🐟',
    description: 'Barracuda Email Security Gateway REST API',
    cred_fields: [
      { key:'base_url', label:'Barracuda URL',  type:'text',     required:true },
      { key:'username', label:'Admin Username', type:'text',     required:true },
      { key:'password', label:'Password',       type:'password', required:true },
      { key:'domain',   label:'Domain',         type:'text',     required:false},
    ],
    docs_url: 'https://campus.barracuda.com/product/emailsecuritygateway/api/',
  },
  imap: {
    label:       'Generic IMAP',
    icon:        '📬',
    description: 'Any mail server with IMAP access (universal)',
    cred_fields: [
      { key:'host',     label:'IMAP Host',   type:'text',     required:true  },
      { key:'port',     label:'Port',        type:'number',   required:false },
      { key:'username', label:'Username',    type:'text',     required:true  },
      { key:'password', label:'Password',    type:'password', required:true  },
      { key:'folder',   label:'Spam Folder', type:'text',     required:false },
      { key:'use_ssl',  label:'Use SSL',     type:'boolean',  required:false },
    ],
    docs_url: null,
  },
  webhook: {
    label:       'Webhook (Push)',
    icon:        '🔗',
    description: 'Platform pushes events to your endpoint (real-time)',
    cred_fields: [
      { key:'secret', label:'Webhook Secret', type:'password', required:false },
    ],
    docs_url: null,
  },
  postfix_agent: {
    label:       'Postfix Log Agent',
    icon:        '📧',
    description: 'Your own Postfix mail server (already configured)',
    cred_fields: [],
    docs_url: null,
  },
};

// ── GET /api/connectors/platforms — list all supported platforms ──
router.get('/platforms', verifyToken, (req, res) => {
  res.json({ success:true, data: Object.entries(PLATFORM_INFO).map(([id,info])=>({
    id, ...info
  }))});
});

// ── GET /api/connectors — list all connectors ────────────────
router.get('/', verifyToken, async (req, res) => {
  try {
    const { customer_id } = req.query;
    const p = getPool();
    let sql = `
      SELECT pc.id, pc.customer_id, pc.platform, pc.display_name,
             pc.connector_type, pc.active, pc.last_sync_at,
             pc.last_sync_status, pc.last_error, pc.total_events,
             pc.created_at, c.name AS customer_name,
             cs.events_today, cs.events_total
      FROM platform_connectors pc
      JOIN customers c ON c.id = pc.customer_id
      LEFT JOIN connector_sync_state cs ON cs.connector_id = pc.id
    `;
    const params = [];
    if (customer_id) {
      sql += ' WHERE pc.customer_id = ?';
      params.push(customer_id);
    }
    sql += ' ORDER BY pc.customer_id, pc.id';
    const [rows] = await p.query(sql, params);

    // Add platform info (no credentials in response)
    const result = rows.map(r => ({
      ...r,
      platform_info: PLATFORM_INFO[r.connector_type] || null,
      webhook_url: r.connector_type === 'webhook'
        ? `${process.env.DASHBOARD_URL || 'https://email-management.worktual.tech'}/api/connectors/webhook/${r.customer_id}`
        : null,
    }));
    res.json({ success:true, data:result });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── POST /api/connectors — add new connector ─────────────────
router.post('/', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  const { customer_id, connector_type, display_name, credentials, config } = req.body;
  if (!customer_id || !connector_type || !credentials) {
    return res.status(400).json({ error:'customer_id, connector_type and credentials required' });
  }
  try {
    const p = getPool();
    const [r] = await p.query(`
      INSERT INTO platform_connectors
        (customer_id, platform, connector_type, display_name, credentials, config)
      VALUES (?,?,?,?,?,?)
    `, [
      customer_id,
      PLATFORM_INFO[connector_type]?.label || connector_type,
      connector_type,
      display_name || PLATFORM_INFO[connector_type]?.label || connector_type,
      JSON.stringify(credentials),
      JSON.stringify(config || {}),
    ]);

    // Create sync state entry
    await p.query(
      'INSERT IGNORE INTO connector_sync_state (connector_id) VALUES (?)',
      [r.insertId]
    );

    res.json({ success:true, id:r.insertId,
      message:`${connector_type} connector added for customer ${customer_id}` });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── POST /api/connectors/:id/test — test connection ──────────
router.post('/:id/test', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  try {
    const p = getPool();
    const [[row]] = await p.query(
      'SELECT * FROM platform_connectors WHERE id=?', [req.params.id]
    );
    if (!row) return res.status(404).json({ error:'Connector not found' });

    // Trigger Python test via subprocess
    const { execSync } = require('child_process');
    const creds = JSON.stringify(row.credentials || '{}');
    const result = execSync(
      `python3 /opt/virus-rescuers/connectors/test_connector.py '${row.connector_type}' '${creds}'`,
      { timeout:30000 }
    ).toString();

    res.json({ success:true, message:result.trim() });
  } catch(e) {
    res.json({ success:false, message:e.message });
  }
});

// ── PUT /api/connectors/:id — update connector ───────────────
router.put('/:id', verifyToken, requireRole('super_admin','admin'), async (req, res) => {
  const { display_name, credentials, config, active } = req.body;
  try {
    const p = getPool();
    await p.query(`
      UPDATE platform_connectors
      SET display_name=COALESCE(?,display_name),
          credentials=COALESCE(?,credentials),
          config=COALESCE(?,config),
          active=COALESCE(?,active)
      WHERE id=?
    `, [
      display_name || null,
      credentials ? JSON.stringify(credentials) : null,
      config      ? JSON.stringify(config)      : null,
      active !== undefined ? (active ? 1 : 0) : null,
      req.params.id,
    ]);
    res.json({ success:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── DELETE /api/connectors/:id ───────────────────────────────
router.delete('/:id', verifyToken, requireRole('super_admin'), async (req, res) => {
  try {
    await getPool().query(
      'UPDATE platform_connectors SET active=0 WHERE id=?', [req.params.id]
    );
    res.json({ success:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── GET /api/connectors/events — unified security events ─────
router.get('/events', verifyToken, async (req, res) => {
  try {
    const { customer_id, platform, threat_category,
            hours=24, page=1, limit=100 } = req.query;
    const p = getPool();
    const where = ['event_datetime >= DATE_SUB(NOW(), INTERVAL ? HOUR)'];
    const params = [parseInt(hours)];

    if (customer_id)     { where.push('customer_id=?');     params.push(customer_id); }
    if (platform)        { where.push('platform=?');        params.push(platform); }
    if (threat_category) { where.push('threat_category=?'); params.push(threat_category); }

    const whereStr = where.join(' AND ');
    const offset   = (parseInt(page)-1) * parseInt(limit);

    const [[{total}]] = await p.query(
      `SELECT COUNT(*) AS total FROM security_events WHERE ${whereStr}`, params
    );
    const [rows] = await p.query(`
      SELECT se.*, c.name AS customer_name
      FROM security_events se
      JOIN customers c ON c.id = se.customer_id
      WHERE ${whereStr}
      ORDER BY event_datetime DESC
      LIMIT ? OFFSET ?
    `, [...params, parseInt(limit), offset]);

    res.json({ success:true, data:rows, total, page:parseInt(page) });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── GET /api/connectors/summary ──────────────────────────────
router.get('/summary', verifyToken, async (req, res) => {
  try {
    const { hours=24 } = req.query;
    const p = getPool();

    const [[stats]] = await p.query(`
      SELECT
        COUNT(*)                                                              AS total_events,
        COUNT(DISTINCT customer_id)                                           AS active_customers,
        COUNT(DISTINCT platform)                                              AS platforms,
        SUM(CASE WHEN threat_category='phishing'    THEN 1 ELSE 0 END)       AS phishing,
        SUM(CASE WHEN threat_category='spam'        THEN 1 ELSE 0 END)       AS spam,
        SUM(CASE WHEN threat_category='malware'     THEN 1 ELSE 0 END)       AS malware,
        SUM(CASE WHEN threat_category='bec'         THEN 1 ELSE 0 END)       AS bec,
        SUM(CASE WHEN threat_category='url_threat'  THEN 1 ELSE 0 END)       AS url_threats,
        SUM(CASE WHEN event_type='blocked'          THEN 1 ELSE 0 END)       AS blocked,
        SUM(CASE WHEN event_type='delivered'        THEN 1 ELSE 0 END)       AS delivered,
        COUNT(DISTINCT sender_domain)                                         AS unique_domains
      FROM security_events
      WHERE event_datetime >= DATE_SUB(NOW(), INTERVAL ? HOUR)
    `, [parseInt(hours)]);

    const [byCustomer] = await p.query(`
      SELECT c.name AS customer_name, c.id AS customer_id,
             se.platform, COUNT(*) AS events,
             SUM(CASE WHEN threat_category IS NOT NULL THEN 1 ELSE 0 END) AS threats
      FROM security_events se
      JOIN customers c ON c.id = se.customer_id
      WHERE se.event_datetime >= DATE_SUB(NOW(), INTERVAL ? HOUR)
      GROUP BY c.id, c.name, se.platform
      ORDER BY events DESC
    `, [parseInt(hours)]);

    const [byPlatform] = await p.query(`
      SELECT platform, COUNT(*) AS events,
             COUNT(DISTINCT customer_id) AS customers
      FROM security_events
      WHERE event_datetime >= DATE_SUB(NOW(), INTERVAL ? HOUR)
      GROUP BY platform ORDER BY events DESC
    `, [parseInt(hours)]);

    const [topThreats] = await p.query(`
      SELECT mail_from, threat_category, COUNT(*) AS count
      FROM security_events
      WHERE threat_category IS NOT NULL
        AND event_datetime >= DATE_SUB(NOW(), INTERVAL ? HOUR)
      GROUP BY mail_from, threat_category
      ORDER BY count DESC LIMIT 10
    `, [parseInt(hours)]);

    res.json({ success:true, data:{ stats, byCustomer, byPlatform, topThreats } });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ── POST /api/connectors/process — AI handoff from universal_connector.py ──
router.post('/process', async (req, res) => {
  const secret = req.headers['x-agent-secret'];
  if (!process.env.AGENT_SECRET || secret !== process.env.AGENT_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const { customer_id, event_ids = [], mail_server = 'app' } = req.body;
    if (!customer_id) return res.status(400).json({ error: 'customer_id required' });
    const p = getPool();
    // Mark security events for AI re-score queue (best-effort)
    let queued = 0;
    if (event_ids.length) {
      const [r] = await p.query(
        `UPDATE security_events SET ai_status='queued'
         WHERE customer_id=? AND id IN (?)`,
        [customer_id, event_ids]
      ).catch(() => [{ affectedRows: 0 }]);
      queued = r.affectedRows || 0;
    } else {
      const [r] = await p.query(
        `UPDATE security_events SET ai_status='queued'
         WHERE customer_id=? AND (ai_status IS NULL OR ai_status='new')
         ORDER BY event_datetime DESC LIMIT 50`,
        [customer_id]
      ).catch(() => [{ affectedRows: 0 }]);
      queued = r.affectedRows || 0;
    }
    res.json({
      success: true,
      queued,
      mail_server,
      message: `${queued} security event(s) queued for AI processing`,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/connectors/webhook/:customer_id — receive push events ──
router.post('/webhook/:customer_id', async (req, res) => {
  const { customer_id } = req.params;
  const secret = req.headers['x-webhook-secret'];

  // Verify secret
  try {
    const p = getPool();
    const [[conn]] = await p.query(
      `SELECT id, credentials FROM platform_connectors
       WHERE customer_id=? AND connector_type='webhook' AND active=1`,
      [customer_id]
    );
    if (!conn) return res.status(404).json({ error:'No webhook connector' });

    const creds = typeof conn.credentials === 'string'
      ? JSON.parse(conn.credentials) : conn.credentials;

    if (creds.secret && secret !== creds.secret) {
      return res.status(401).json({ error:'Invalid webhook secret' });
    }

    // Parse incoming event (format varies by platform)
    const body = req.body;
    const event = {
      customer_id:    parseInt(customer_id),
      platform:       'webhook',
      event_type:     body.event_type || body.type || 'threat',
      mail_from:      body.sender || body.from || body.mail_from || '',
      mail_to:        body.recipient || body.to || body.mail_to || '',
      subject:        body.subject || '',
      event_datetime: body.timestamp || body.date ||
                      new Date().toISOString().replace('T',' ').slice(0,19),
      threat_category:body.threat_type || body.category || null,
      threat_score:   body.score || null,
      sender_ip:      body.sender_ip || body.ip || null,
      urls:           JSON.stringify(body.urls || []),
      platform_guid:  body.id || body.guid || '',
      raw_json:       JSON.stringify(body).slice(0,8000),
      dedup_hash:     require('crypto').createHash('md5')
                        .update(`${body.from}${body.to}${body.subject}${body.timestamp||''}`)
                        .digest('hex'),
    };

    await p.query(`
      INSERT IGNORE INTO security_events
        (customer_id, connector_id, platform, event_type, mail_from, mail_to,
         subject, event_datetime, threat_category, threat_score, sender_ip,
         urls, platform_guid, raw_json, dedup_hash)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `, [
      event.customer_id, conn.id, event.platform, event.event_type,
      event.mail_from, event.mail_to, event.subject, event.event_datetime,
      event.threat_category, event.threat_score, event.sender_ip,
      event.urls, event.platform_guid, event.raw_json, event.dedup_hash,
    ]);

    res.json({ success:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

module.exports = router;
