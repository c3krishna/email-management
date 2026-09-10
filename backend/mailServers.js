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
    mail_domains: ['worktual.tech', 'worktual.com'],
    role: 'Application notifications, CCaaS email channel, AI CCaaS, client-domain From via Worktual',
    vip: '82.113.72.84',
    active_ip: '10.180.0.84',
  },
  campaign: {
    key: 'campaign',
    label: 'Campaign Bulk',
    domain: 'mail.worktual.pl',
    mail_domains: ['worktual.pl', 'worktual.tech', 'worktual.com'],
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

/** Today's date in Asia/Kolkata (IST) as YYYY-MM-DD */
function istToday() {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(new Date());
}

/**
 * Shared date filter for log_date columns.
 * Supports today | 7d | 30d | custom (+ optional date/from/to).
 * Uses IST "today" when no explicit date is provided.
 */
function buildDateFilter(range, date, from, to, column = 'log_date') {
  if (range === 'custom' && from && to) {
    return { dateFilter: `${column} BETWEEN ? AND ?`, params: [from, to] };
  }
  if (range === 'today' || (date && range !== '7d' && range !== '30d')) {
    const d = date || istToday();
    return { dateFilter: `${column} = ?`, params: [d] };
  }
  if (range === '7d') {
    return { dateFilter: `${column} >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)`, params: [] };
  }
  if (range === '30d') {
    return { dateFilter: `${column} >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)`, params: [] };
  }
  return { dateFilter: `${column} = CURDATE()`, params: [] };
}

/**
 * Domains that count as "our" mail for inbound/outbound classification.
 * App → worktual.tech/com; Campaign → worktual.pl + shared Worktual domains.
 * Extra domains from env MAIL_DOMAIN / MAIL_DOMAINS_CAMPAIGN or MAIL_SERVERS.
 */
function getOwnedDomains(server) {
  const key = normalizeServer(server, 'app');
  const base = [...(MAIL_SERVERS[key]?.mail_domains || ['worktual.tech'])];
  const envExtra = key === 'campaign'
    ? (process.env.MAIL_DOMAINS_CAMPAIGN || process.env.MAIL_DOMAIN || '')
    : (process.env.MAIL_DOMAIN || '');
  for (const d of String(envExtra).split(/[,\s]+/).filter(Boolean)) {
    if (!base.includes(d)) base.push(d);
  }
  // Always include worktual wildcard-friendly roots
  if (!base.some(d => d.includes('worktual'))) {
    base.push(key === 'campaign' ? 'worktual.pl' : 'worktual.tech');
  }
  return base;
}

/**
 * SQL CASE fragments for inbound/outbound matching owned domains.
 * Directions are mutually exclusive so Inbound + Outbound + Other = Total:
 *   Outbound — From our domains (priority; typical for MTA send logs)
 *   Inbound  — To our domains and NOT from our domains
 *   Other    — Neither (relay / unclassified)
 */
function buildDirectionSql(server) {
  const domains = getOwnedDomains(server);
  const fromParts = [];
  const toParts = [];
  for (const d of domains) {
    const esc = d.replace(/'/g, "''");
    fromParts.push(`mail_from LIKE '%@${esc}' OR mail_from LIKE '%@%.${esc}' OR mail_from LIKE '%@${esc}%'`);
    toParts.push(`mail_to LIKE '%@${esc}' OR mail_to LIKE '%@%.${esc}' OR mail_to LIKE '%@${esc}%'`);
  }
  // Broader worktual catch-all for both infrastructures
  fromParts.push(`mail_from LIKE '%@worktual%'`);
  toParts.push(`mail_to LIKE '%@worktual%'`);
  const fromOwned = `(${fromParts.join(' OR ')})`;
  const toOwned = `(${toParts.join(' OR ')})`;
  return {
    outboundSql: `SUM(CASE WHEN ${fromOwned} THEN 1 ELSE 0 END)`,
    // Exclusive: received to us, not also counted as outbound
    inboundSql:  `SUM(CASE WHEN ${toOwned} AND NOT ${fromOwned} THEN 1 ELSE 0 END)`,
    otherSql:    `SUM(CASE WHEN NOT ${fromOwned} AND NOT ${toOwned} THEN 1 ELSE 0 END)`,
    directionCase: `CASE WHEN ${fromOwned} THEN 'Outbound' WHEN ${toOwned} THEN 'Inbound' ELSE 'Other' END`,
    fromOwned,
    toOwned,
    domains,
  };
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
  istToday,
  buildDateFilter,
  getOwnedDomains,
  buildDirectionSql,
  resolveCustomerMailServer,
  ensureCustomerMailServerColumn,
  ensureSpamWhitelistMailServer,
  ensureWazuhMailServer,
};
