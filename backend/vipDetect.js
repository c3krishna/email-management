/**
 * VIP impersonation + sender anomaly detection helpers.
 * Used by /api/protection/detect and optionally by agent ingest.
 */

function normalizeEmail(addr) {
  if (!addr) return '';
  const m = String(addr).match(/<([^>]+)>/);
  return (m ? m[1] : String(addr)).trim().toLowerCase();
}

function extractDisplayName(addr) {
  if (!addr) return '';
  const s = String(addr).trim();
  const m = s.match(/^"?([^"<]+)"?\s*</);
  if (m) return m[1].trim();
  if (!s.includes('@')) return s;
  return '';
}

function namesSimilar(a, b) {
  const na = String(a || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const nb = String(b || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!na || !nb) return false;
  if (na === nb) return true;
  if (na.length >= 4 && nb.includes(na)) return true;
  if (nb.length >= 4 && na.includes(nb)) return true;
  return false;
}

async function ensureVipTables(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS vip_contacts (
      id INT AUTO_INCREMENT PRIMARY KEY,
      customer_id INT NOT NULL,
      display_name VARCHAR(255) NOT NULL,
      real_email VARCHAR(255) NOT NULL,
      title VARCHAR(255) DEFAULT NULL,
      active TINYINT(1) NOT NULL DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      KEY idx_customer (customer_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS impersonation_alerts (
      id INT AUTO_INCREMENT PRIMARY KEY,
      customer_id INT NOT NULL,
      vip_contact_id INT DEFAULT NULL,
      vip_name VARCHAR(255) DEFAULT NULL,
      vip_email VARCHAR(255) DEFAULT NULL,
      spoofed_from VARCHAR(512) DEFAULT NULL,
      spoofed_display VARCHAR(255) DEFAULT NULL,
      mail_to VARCHAR(512) DEFAULT NULL,
      subject VARCHAR(512) DEFAULT NULL,
      confidence INT DEFAULT 70,
      reason TEXT,
      mail_server ENUM('app','campaign') DEFAULT 'app',
      reviewed TINYINT(1) DEFAULT 0,
      status VARCHAR(32) DEFAULT 'open',
      detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      KEY idx_customer_time (customer_id, detected_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sender_anomaly_alerts (
      id INT AUTO_INCREMENT PRIMARY KEY,
      customer_id INT NOT NULL,
      mail_from VARCHAR(512) DEFAULT NULL,
      mail_to VARCHAR(512) DEFAULT NULL,
      subject VARCHAR(512) DEFAULT NULL,
      anomaly_type VARCHAR(64) DEFAULT 'unusual_sender',
      reason TEXT,
      confidence INT DEFAULT 60,
      mail_server ENUM('app','campaign') DEFAULT 'app',
      reviewed TINYINT(1) DEFAULT 0,
      status VARCHAR(32) DEFAULT 'open',
      detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      KEY idx_customer_time (customer_id, detected_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);
}

/**
 * Check one email against VIP contacts for a customer (or all customers).
 * Writes impersonation_alerts when display-name matches VIP but envelope email does not.
 */
async function detectVipImpersonation(pool, {
  customer_id = null,
  mail_from,
  mail_to,
  subject,
  display_name,
  mail_server = 'app',
} = {}) {
  await ensureVipTables(pool);
  const fromEmail = normalizeEmail(mail_from);
  const fromDisplay = display_name || extractDisplayName(mail_from);
  if (!fromEmail && !fromDisplay) return { alerts: [] };

  let sql = 'SELECT * FROM vip_contacts WHERE active=1';
  const params = [];
  if (customer_id) {
    sql += ' AND customer_id=?';
    params.push(customer_id);
  }
  const [vips] = await pool.query(sql, params);
  const alerts = [];

  for (const vip of vips) {
    const vipEmail = normalizeEmail(vip.real_email);
    const nameHit = namesSimilar(fromDisplay, vip.display_name)
      || namesSimilar(fromEmail.split('@')[0], vip.display_name);
    if (!nameHit) continue;
    if (fromEmail && vipEmail && fromEmail === vipEmail) continue; // legitimate VIP

    // Avoid duplicate alerts in last 24h for same pair
    const [[dup]] = await pool.query(`
      SELECT id FROM impersonation_alerts
      WHERE customer_id=? AND vip_contact_id=?
        AND spoofed_from=? AND detected_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
      LIMIT 1
    `, [vip.customer_id, vip.id, mail_from || fromEmail]).catch(() => [[null]]);
    if (dup) continue;

    const reason = `Display/name resembles VIP "${vip.display_name}" <${vip.real_email}> but From is ${mail_from || fromEmail}`;
    const [ins] = await pool.query(`
      INSERT INTO impersonation_alerts
        (customer_id, vip_contact_id, vip_name, vip_email, spoofed_from, spoofed_display,
         mail_to, subject, confidence, reason, mail_server)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)
    `, [
      vip.customer_id, vip.id, vip.display_name, vip.real_email,
      mail_from || fromEmail, fromDisplay || null,
      mail_to || null, subject || null, 85, reason, mail_server === 'campaign' ? 'campaign' : 'app',
    ]);
    alerts.push({ id: ins.insertId, customer_id: vip.customer_id, vip: vip.display_name, reason });
  }

  return { alerts };
}

/**
 * Lightweight anomaly: external sender to many recipients / known risky patterns.
 * Optional — only writes when customer_id provided.
 */
async function detectSenderAnomaly(pool, {
  customer_id,
  mail_from,
  mail_to,
  subject,
  mail_server = 'app',
  reason,
} = {}) {
  if (!customer_id || !mail_from) return { alerts: [] };
  await ensureVipTables(pool);
  const fromEmail = normalizeEmail(mail_from);
  const risky = /urgent|wire transfer|gift card|password reset|invoice attached/i.test(subject || '');
  if (!risky) return { alerts: [] };

  const [[dup]] = await pool.query(`
    SELECT id FROM sender_anomaly_alerts
    WHERE customer_id=? AND mail_from=? AND detected_at >= DATE_SUB(NOW(), INTERVAL 12 HOUR)
    LIMIT 1
  `, [customer_id, mail_from]).catch(() => [[null]]);
  if (dup) return { alerts: [] };

  const [ins] = await pool.query(`
    INSERT INTO sender_anomaly_alerts
      (customer_id, mail_from, mail_to, subject, anomaly_type, reason, confidence, mail_server)
    VALUES (?,?,?,?,?,?,?,?)
  `, [
    customer_id, mail_from, mail_to || null, subject || null,
    'risky_subject', reason || `Risky subject language from ${fromEmail}`,
    65, mail_server === 'campaign' ? 'campaign' : 'app',
  ]);
  return { alerts: [{ id: ins.insertId }] };
}

module.exports = {
  normalizeEmail,
  extractDisplayName,
  ensureVipTables,
  detectVipImpersonation,
  detectSenderAnomaly,
};
