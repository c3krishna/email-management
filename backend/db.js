require('dotenv').config();
const mysql = require('mysql2/promise');

const baseConfig = {
  port:               parseInt(process.env.DB_PORT) || 3306,
  user:               process.env.DB_USER,
  password:           process.env.DB_PASSWORD,
  database:           process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit:    20,
  enableKeepAlive:    true,
  keepAliveInitialDelay: 10000,
  timezone:           '+05:30'
};

const pools = {
  app: mysql.createPool({
    ...baseConfig,
    host: process.env.DB_HOST
  }),
  campaign: mysql.createPool({
    ...baseConfig,
    host: process.env.DB_HOST_CAMPAIGN || process.env.DB_HOST
  })
};

// Test both on startup
(async () => {
  for (const [name, pool] of Object.entries(pools)) {
    try {
      const conn = await pool.getConnection();
      console.log(`✅ DB [${name}] connected to ${name === 'campaign' ? (process.env.DB_HOST_CAMPAIGN || process.env.DB_HOST) : process.env.DB_HOST}`);
      conn.release();
    } catch (err) {
      console.error(`❌ DB [${name}] failed: ${err.message}`);
    }
  }
})();

function getPool(server) {
  return pools[server] === undefined ? pools.app : pools[server];
}

// Default export = app pool (keeps old routes working without changes)
module.exports = pools.app;
module.exports.getPool = getPool;
module.exports.pools   = pools;
