// ============================================================
// Wazuh SIEM Integration API
// /var/www/email-management/backend/routes/wazuh.js
// ============================================================

const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');
const { verifyToken } = require('../middleware/auth');
const { normalizeServer, serverFilter, ensureWazuhMailServer } = require('../mailServers');

let pool = null;
function getPool() {
  if (!pool) pool = mysql.createPool({
    host: process.env.DB_HOST || '10.180.0.84', user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.PLATFORM_DB || 'threat_platform', waitForConnections: true, connectionLimit: 10,
  });
  return pool;
}

// GET /api/wazuh/summary?customer_id=&mail_server=app|campaign|all
router.get('/summary', verifyToken, async (req, res) => {
  try {
    const { customer_id = 1, mail_server = 'all' } = req.query;
    const p = getPool();
    await ensureWazuhMailServer(p);
    const ms = normalizeServer(mail_server, 'all');
    const agentParams = [customer_id];
    const agentSf = serverFilter('mail_server', ms, agentParams);

    const [[agents]] = await p.query(`
      SELECT COUNT(*) AS total, SUM(status='active') AS active
      FROM wazuh_agents WHERE customer_id=? AND ${agentSf.sql}
    `, agentSf.params).catch(() => [[{ total: 0, active: 0 }]]);

    const vulnParams = [customer_id];
    const vulnSf = serverFilter('mail_server', ms, vulnParams);
    const [[vulns]] = await p.query(`
      SELECT COUNT(*) AS total,
        SUM(severity='Critical') AS critical,
        SUM(severity='High')     AS high,
        SUM(severity='Medium')   AS medium,
        SUM(severity='Low')      AS low
      FROM wazuh_vulnerabilities WHERE customer_id=? AND status='active' AND ${vulnSf.sql}
    `, vulnSf.params).catch(() => [[{ total: 0, critical: 0, high: 0, medium: 0, low: 0 }]]);

    const alertParams = [customer_id];
    const alertSf = serverFilter('mail_server', ms, alertParams);
    const [[alerts]] = await p.query(`
      SELECT COUNT(DISTINCT rule_id) AS total,
        COUNT(DISTINCT CASE WHEN rule_level >= 12 THEN rule_id END) AS critical,
        COUNT(DISTINCT CASE WHEN rule_level >= 7 AND rule_level < 12 THEN rule_id END) AS high,
        COUNT(*) AS total_events
      FROM wazuh_alerts
      WHERE customer_id=? AND alert_datetime >= DATE_SUB(NOW(), INTERVAL 7 DAY) AND ${alertSf.sql}
    `, alertSf.params).catch(() => [[{ total: 0, critical: 0, high: 0, total_events: 0 }]]);

    // Source 1: SCA-based compliance (only CIS has a policy file installed)
    const scaParams = [customer_id];
    const scaSf = serverFilter('mail_server', ms, scaParams);
    const [scaCompliance] = await p.query(`
      SELECT framework, AVG(score_pct) AS avg_score,
        SUM(pass_count) AS total_pass, SUM(fail_count) AS total_fail,
        MAX(checked_at) AS last_checked, 'sca' AS source
      FROM wazuh_compliance
      WHERE customer_id=? AND ${scaSf.sql}
      GROUP BY framework
    `, scaSf.params).catch(() => [[]]);

    // Source 2: Alert-rule-tag-based compliance — GDPR/PCI-DSS/HIPAA/NIST/SOC2
    // have no installed SCA policy file, but Wazuh's core ruleset already
    // tags relevant security events (auth, FIM, etc.) with these groups.
    const ALERT_FRAMEWORKS = [
      { id: 'gdpr',        like: 'gdpr' },
      { id: 'pci_dss',     like: 'pci_dss' },
      { id: 'hipaa',       like: 'hipaa' },
      { id: 'nist_800_53', like: 'nist_800_53' },
      { id: 'tsc',         like: 'tsc' },
    ];
    const alertCompliance = [];
    for (const fw of ALERT_FRAMEWORKS) {
      try {
        const [[row]] = await p.query(`
          SELECT COUNT(DISTINCT rule_id) AS event_count,
            COUNT(DISTINCT CASE WHEN rule_level >= 7 THEN rule_id END) AS high_severity_events,
            COUNT(*) AS total_occurrences,
            MAX(alert_datetime) AS last_checked
          FROM wazuh_alerts
          WHERE customer_id=?
            AND compliance_tags LIKE ?
            AND alert_datetime >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        `, [customer_id, `%${fw.like}%`]);
        if (row && row.event_count > 0) {
          alertCompliance.push({
            framework: fw.id,
            event_count: row.event_count,
            high_severity_events: row.high_severity_events,
            last_checked: row.last_checked,
            source: 'alerts',
          });
        }
      } catch (e) { /* skip on error, non-fatal */ }
    }

    // Merge both sources — SCA takes priority where it exists (CIS),
    // alert-tag data fills in for frameworks with no SCA policy
    const complianceMap = {};
    for (const row of scaCompliance) complianceMap[row.framework] = row;
    for (const row of alertCompliance) {
      if (!complianceMap[row.framework]) complianceMap[row.framework] = row;
    }
    const compliance = Object.values(complianceMap);

    res.json({
      success: true,
      data: {
        agents: agents || { total: 0, active: 0 },
        vulnerabilities: vulns || { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
        alerts: alerts || { total: 0, critical: 0, high: 0 },
        compliance,
      },
      filter: { mail_server: ms },
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/wazuh/clusters
router.get('/clusters', verifyToken, async (req, res) => {
  try {
    const p = getPool();
    await ensureWazuhMailServer(p);
    const [rows] = await p.query('SELECT id, name, mail_server, customer_id, api_url, indexer_url, active FROM wazuh_clusters ORDER BY mail_server');
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/wazuh/agents?customer_id=&mail_server=
router.get('/agents', verifyToken, async (req, res) => {
  try {
    const { customer_id = 1, mail_server = 'all' } = req.query;
    const p = getPool();
    await ensureWazuhMailServer(p);
    const params = [customer_id];
    const sf = serverFilter('mail_server', mail_server, params);
    const [rows] = await p.query(
      `SELECT * FROM wazuh_agents WHERE customer_id=? AND ${sf.sql} ORDER BY status DESC, agent_name`,
      sf.params
    );
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/wazuh/vulnerabilities?customer_id=&severity=
router.get('/vulnerabilities', verifyToken, async (req, res) => {
  try {
    const { customer_id = 1, severity, limit = 100 } = req.query;
    const p = getPool();
    const where = ['customer_id=?', "status='active'"];
    const params = [customer_id];
    if (severity) { where.push('severity=?'); params.push(severity); }

    const [rows] = await p.query(`
      SELECT * FROM wazuh_vulnerabilities
      WHERE ${where.join(' AND ')}
      ORDER BY FIELD(severity,'Critical','High','Medium','Low'), cvss_score DESC
      LIMIT ?
    `, [...params, parseInt(limit)]);
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/wazuh/compliance?customer_id=&framework=
router.get('/compliance', verifyToken, async (req, res) => {
  try {
    const { customer_id = 1, framework } = req.query;
    const p = getPool();
    const where = ['customer_id=?'];
    const params = [customer_id];
    if (framework) { where.push('framework=?'); params.push(framework); }

    const [rows] = await p.query(`
      SELECT wc.*, wa.agent_name
      FROM wazuh_compliance wc
      LEFT JOIN wazuh_agents wa ON wa.agent_id=wc.agent_id AND wa.customer_id=wc.customer_id
      WHERE ${where.join(' AND ')}
      ORDER BY checked_at DESC
    `, params);
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/wazuh/alerts?customer_id=&framework=&min_level=
router.get('/alerts', verifyToken, async (req, res) => {
  try {
    const { customer_id = 1, framework, min_level, hours = 168, limit = 100 } = req.query;
    const p = getPool();
    const where = ['customer_id=?', 'alert_datetime >= DATE_SUB(NOW(), INTERVAL ? HOUR)'];
    const params = [customer_id, parseInt(hours)];
    if (framework)  { where.push('FIND_IN_SET(?, compliance_tags)'); params.push(framework); }
    if (min_level)  { where.push('rule_level >= ?'); params.push(parseInt(min_level)); }

    const [rows] = await p.query(`
      SELECT * FROM wazuh_alerts
      WHERE ${where.join(' AND ')}
      ORDER BY alert_datetime DESC LIMIT ?
    `, [...params, parseInt(limit)]);
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;
