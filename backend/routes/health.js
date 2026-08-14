const express = require('express');
const router = express.Router();
const pool = require('../db');

router.get('/', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT COUNT(*) AS total FROM email_delivery_details WHERE log_date = CURDATE()');
    res.json({
      status: 'healthy',
      db: 'connected',
      today_records: rows[0].total,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(503).json({ status: 'unhealthy', db: 'disconnected', error: err.message });
  }
});

module.exports = router;
