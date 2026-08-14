/**
 * Dual mail infrastructure helpers:
 *   app      = mail.worktual.tech  (CCaaS / app notifications / client-from via Worktual)
 *   campaign = mail.worktual.pl    (bulk campaign sending)
 */

const MAIL_SERVERS = {
  app: {
    key: 'app',
    label: 'App Mail',
    domain: 'mail.worktual.tech',
    role: 'Application notifications, CCaaS email channel, AI CCaaS, client-domain From via Worktual',
    vip: '82.113.72.84',
    active_ip: '10.180.0.84',
  },
  campaign: {
    key: 'campaign',
    label: 'Campaign Bulk',
    domain: 'mail.worktual.pl',
    role: 'Bulk campaign sending with delivery/bounce reporting',
    vip: '82.113.72.80',
    active_ip: '10.180.0.89',
  },
};

function normalizeServer(value, fallback = 'app') {
  const v = String(value || '').toLowerCase().trim();
  if (v === 'campaign' || v === 'bulk') return 'campaign';
  if (v === 'app' || v === 'application') return 'app';
  if (v === 'all' || v === 'both') return 'all';
  return fallback;
}

/** SQL fragment + params for filtering a `server` column. skip if all/both. */
function serverFilter(column, server, params = []) {
  const s = normalizeServer(server, 'all');
  if (s === 'all') return { sql: '1=1', params };
  params.push(s);
  return { sql: `${column} = ?`, params };
}

/**
 * Resolve which mail pool a customer uses.
 * Prefer customers.mail_server; fallback legacy id===2 → campaign.
 */
async function resolveCustomerMailServer(platformPool, customerId) {
  try {
    const [[row]] = await platformPool.query(
      'SELECT mail_server FROM customers WHERE id=?',
      [customerId]
    );
    if (row?.mail_server) {
      const s = normalizeServer(row.mail_server, 'app');
      return s === 'all' ? 'app' : s;
    }
  } catch {
    // column may not exist yet
  }
  // Legacy binding used in older deploys
  if (Number(customerId) === 2) return 'campaign';
  return 'app';
}

async function ensureCustomerMailServerColumn(platformPool) {
  try {
    await platformPool.query(`
      ALTER TABLE customers
        ADD COLUMN mail_server ENUM('app','campaign','both') NOT NULL DEFAULT 'app'
        AFTER domain
    `);
  } catch (e) {
    if (!String(e.message).includes('Duplicate column')) {
      // ignore other alter failures (permissions / already exists differently)
    }
  }
}

async function ensureSpamWhitelistMailServer(platformPool) {
  try {
    await platformPool.query(`
      ALTER TABLE spam_whitelist
        ADD COLUMN mail_server ENUM('app','campaign','both') NOT NULL DEFAULT 'both'
        AFTER value
    `);
  } catch (e) {
    if (!String(e.message).includes('Duplicate column')) { /* ok */ }
  }
}

async function ensureWazuhMailServer(platformPool) {
  for (const table of ['wazuh_agents', 'wazuh_alerts', 'wazuh_vulnerabilities', 'wazuh_compliance']) {
    try {
      await platformPool.query(`
        ALTER TABLE ${table}
          ADD COLUMN mail_server ENUM('app','campaign','both') NOT NULL DEFAULT 'app'
      `);
    } catch (e) {
      if (!String(e.message).includes('Duplicate column')) { /* ok */ }
    }
  }
  try {
    await platformPool.query(`
      CREATE TABLE IF NOT EXISTS wazuh_clusters (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(128) NOT NULL,
        mail_server ENUM('app','campaign') NOT NULL,
        customer_id INT NOT NULL DEFAULT 1,
        api_url VARCHAR(255) NULL,
        indexer_url VARCHAR(255) NULL,
        active TINYINT NOT NULL DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_mail_server (mail_server, customer_id)
      )
    `);
    await platformPool.query(`
      INSERT IGNORE INTO wazuh_clusters (name, mail_server, customer_id, active)
      VALUES
        ('App Mail Wazuh', 'app', 1, 1),
        ('Campaign Mail Wazuh', 'campaign', 1, 1)
    `);
  } catch { /* ok */ }
}

module.exports = {
  MAIL_SERVERS,
  normalizeServer,
  serverFilter,
  resolveCustomerMailServer,
  ensureCustomerMailServerColumn,
  ensureSpamWhitelistMailServer,
  ensureWazuhMailServer,
};
