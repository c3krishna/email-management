require('dotenv').config();
const mysql = require('mysql2/promise');

let pool = null;

/**
 * Shared MariaDB pool for threat_platform.
 * Uses existing production DB settings (same as app DB host).
 */
function getThreatPool() {
  if (!pool) {
    pool = mysql.createPool({
      host:     process.env.DB_HOST || '10.180.0.84',
      port:     parseInt(process.env.DB_PORT, 10) || 3306,
      user:     process.env.DB_USER || 'mailmetrics',
      password: process.env.DB_PASSWORD || 'WorktualMailMetrics@123',
      database: process.env.PLATFORM_DB || 'threat_platform',
      waitForConnections: true,
      connectionLimit: 10,
      enableKeepAlive: true,
      timezone: '+05:30',
    });
  }
  return pool;
}

module.exports = { getThreatPool };
