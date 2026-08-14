const express = require('express');
const router = express.Router();
const { getPool } = require('../db');
const { requireRole } = require('../middleware/auth');

const DEFAULT_POLICIES = {
  spam_threshold: '5.0',
  block_threshold: '8.0',
  quarantine_threshold: '10.0',
  max_recipients: '50',
  bounce_rate_alert: '5',
  failed_rate_alert: '2',
  alert_email: '',
  alert_slack: '',
  retention_hot_days: '90',
  retention_archive_days: '1825',
  alert_failed_threshold: '50',
  alert_bounce_threshold: '20',
  alert_spam_threshold: '10',
};

const DEFAULT_SETTINGS = {
  dashboard_timezone: 'Asia/Kolkata',
  agent_poll_seconds: '30',
  notify_enabled: 'true',
  ollama_url: process.env.OLLAMA_URL || '',
  retention_note: 'Managed via Policies retention tab',
};

async function ensurePolicyTables(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_settings (
      setting_key   VARCHAR(128) PRIMARY KEY,
      setting_value TEXT NULL,
      updated_by    VARCHAR(128) NULL,
      updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS policy_blocklist (
      id         BIGINT AUTO_INCREMENT PRIMARY KEY,
      type       ENUM('domain','ip','email','cidr') NOT NULL,
      value      VARCHAR(255) NOT NULL,
      reason     VARCHAR(500) NULL,
      active     TINYINT NOT NULL DEFAULT 1,
      added_by   VARCHAR(128) NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uk_block_type_value (type, value),
      INDEX idx_block_active (active)
    )
  `);
}

async function readSettingsMap(pool, keys) {
  const [rows] = await pool.query(
    `SELECT setting_key, setting_value FROM app_settings WHERE setting_key IN (?)`,
    [keys]
  );
  const map = {};
  for (const r of rows) map[r.setting_key] = r.setting_value;
  return map;
}

async function writeSettings(pool, values, actor) {
  for (const [key, value] of Object.entries(values)) {
    await pool.query(
      `INSERT INTO app_settings (setting_key, setting_value, updated_by)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value), updated_by=VALUES(updated_by)`,
      [key, value == null ? '' : String(value), actor]
    );
  }
}

// GET /api/policies
router.get('/', async (req, res) => {
  try {
    const server = req.query.server || 'app';
    const pool = getPool(server);
    await ensurePolicyTables(pool);

    const keys = Object.keys(DEFAULT_POLICIES);
    const stored = await readSettingsMap(pool, keys);
    const policies = { ...DEFAULT_POLICIES, ...stored };

    // Keep process env alert thresholds in sync for read display
    policies.alert_failed_threshold =
      stored.alert_failed_threshold || process.env.ALERT_FAILED_THRESHOLD || DEFAULT_POLICIES.alert_failed_threshold;
    policies.alert_bounce_threshold =
      stored.alert_bounce_threshold || process.env.ALERT_BOUNCE_THRESHOLD || DEFAULT_POLICIES.alert_bounce_threshold;
    policies.alert_spam_threshold =
      stored.alert_spam_threshold || process.env.ALERT_SPAM_THRESHOLD || DEFAULT_POLICIES.alert_spam_threshold;

    const [blocklist] = await pool.query(
      `SELECT id, type, value, reason, created_at AS added, added_by
       FROM policy_blocklist WHERE active=1 ORDER BY created_at DESC`
    );

    res.json({ success: true, policies, blocklist });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/policies — persist policy values
router.put('/', requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    const server = req.query.server || req.body.server || 'app';
    const pool = getPool(server);
    await ensurePolicyTables(pool);

    const incoming = req.body.policies || req.body;
    const toSave = {};
    for (const key of Object.keys(DEFAULT_POLICIES)) {
      if (incoming[key] !== undefined && incoming[key] !== null) {
        const val = typeof incoming[key] === 'object' ? incoming[key].value : incoming[key];
        toSave[key] = val;
      }
    }
    if (!Object.keys(toSave).length) {
      return res.status(400).json({ error: 'No policy fields provided' });
    }

    const actor = req.user?.email || req.user?.username || 'admin';
    await writeSettings(pool, toSave, actor);

    // Apply alert count thresholds into process env for live use
    // NOTE: process env is process-global — prefer reading app_settings per server in alerts.js
    if (toSave.alert_failed_threshold != null) {
      // kept for backward compat; alerts.js loads per-server settings first
    }

    res.json({ success: true, message: 'Policies saved', saved: Object.keys(toSave), server });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/policies/for-agent — milter/spam_detector pulls thresholds for AGENT_SERVER
router.get('/for-agent', async (req, res) => {
  try {
    const secret = req.headers['x-agent-secret'];
    if (!process.env.AGENT_SECRET || secret !== process.env.AGENT_SECRET) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const server = (req.query.server || req.headers['x-agent-server'] || 'app').toLowerCase();
    const pool = getPool(server === 'campaign' ? 'campaign' : 'app');
    await ensurePolicyTables(pool);
    const keys = Object.keys(DEFAULT_POLICIES);
    const stored = await readSettingsMap(pool, keys);
    const policies = { ...DEFAULT_POLICIES, ...stored };
    res.json({
      success: true,
      server: server === 'campaign' ? 'campaign' : 'app',
      thresholds: {
        spam: parseFloat(policies.spam_threshold),
        block: parseFloat(policies.block_threshold),
        quarantine: parseFloat(policies.quarantine_threshold),
        reject: parseFloat(policies.quarantine_threshold) + 5,
        tag: parseFloat(policies.spam_threshold) + 2,
        ai: Math.max(50, parseFloat(policies.spam_threshold) * 10),
      },
      policies,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/policies/blocklist
router.get('/blocklist', async (req, res) => {
  try {
    const pool = getPool(req.query.server || 'app');
    await ensurePolicyTables(pool);
    const [rows] = await pool.query(
      `SELECT id, type, value, reason, created_at AS added, added_by
       FROM policy_blocklist WHERE active=1 ORDER BY created_at DESC`
    );
    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/policies/blocklist
router.post('/blocklist', requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    const pool = getPool(req.query.server || req.body.server || 'app');
    await ensurePolicyTables(pool);
    const { type, value, reason } = req.body;
    if (!type || !value) return res.status(400).json({ error: 'type and value required' });
    const actor = req.user?.email || req.user?.username || 'admin';
    await pool.query(
      `INSERT INTO policy_blocklist (type, value, reason, active, added_by)
       VALUES (?, ?, ?, 1, ?)
       ON DUPLICATE KEY UPDATE active=1, reason=VALUES(reason), added_by=VALUES(added_by)`,
      [type, String(value).trim(), reason || null, actor]
    );

    // Mirror into firewall_manual_blocks when available (enforcement hand-off for agents)
    try {
      const { getThreatPool } = require('../threatDb');
      await getThreatPool().query(
        `INSERT INTO firewall_manual_blocks (block_value, block_type, reason, created_by, active)
         VALUES (?, ?, ?, ?, 1)
         ON DUPLICATE KEY UPDATE active=1, reason=VALUES(reason)`,
        [String(value).trim(), type, reason || 'policy blocklist', actor]
      );
    } catch {
      // table may not exist
    }

    res.json({ success: true, message: `${value} added to blocklist` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/policies/blocklist/:id
router.delete('/blocklist/:id', requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    const pool = getPool(req.query.server || 'app');
    await ensurePolicyTables(pool);
    await pool.query(`UPDATE policy_blocklist SET active=0 WHERE id=?`, [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/policies/settings
router.get('/settings', async (req, res) => {
  try {
    const pool = getPool(req.query.server || 'app');
    await ensurePolicyTables(pool);
    const keys = Object.keys(DEFAULT_SETTINGS);
    const stored = await readSettingsMap(pool, keys);
    res.json({
      success: true,
      settings: { ...DEFAULT_SETTINGS, ...stored },
      runtime: {
        node_env: process.env.NODE_ENV || 'development',
        port: process.env.PORT || '5200',
        frontend_url: process.env.FRONTEND_URL || '',
        db_host: process.env.DB_HOST || '',
        db_host_campaign: process.env.DB_HOST_CAMPAIGN || '',
        platform_db: process.env.PLATFORM_DB || 'threat_platform',
        ollama_url: process.env.OLLAMA_URL || stored.ollama_url || '',
        mail_imap_host: process.env.MAIL_IMAP_HOST || '',
        mail_smtp_host: process.env.MAIL_SMTP_HOST || '',
        jwt_configured: Boolean(process.env.JWT_SECRET),
        agent_secret_configured: Boolean(process.env.AGENT_SECRET),
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/policies/settings
router.put('/settings', requireRole('super_admin'), async (req, res) => {
  try {
    const pool = getPool(req.query.server || req.body.server || 'app');
    await ensurePolicyTables(pool);
    const incoming = req.body.settings || req.body;
    const toSave = {};
    for (const key of Object.keys(DEFAULT_SETTINGS)) {
      if (incoming[key] !== undefined && incoming[key] !== null) {
        toSave[key] = incoming[key];
      }
    }
    if (!Object.keys(toSave).length) {
      return res.status(400).json({ error: 'No settings provided' });
    }
    const actor = req.user?.email || req.user?.username || 'admin';
    await writeSettings(pool, toSave, actor);
    if (toSave.ollama_url) process.env.OLLAMA_URL = String(toSave.ollama_url);
    res.json({ success: true, message: 'Settings saved', saved: Object.keys(toSave) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
module.exports.DEFAULT_POLICIES = DEFAULT_POLICIES;
