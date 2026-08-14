// ============================================================
// Mailchimp Webhook Receiver
// /var/www/email-management/backend/routes/mailchimp-webhook.js
//
// Mailchimp calls this URL when a campaign is created/edited/
// about to send. We trigger validate_mailchimp_campaign.py
// and respond fast (Mailchimp requires <5s response).
// ============================================================

const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');
const { execFile } = require('child_process');

let pool = null;
function getPool() {
  if (!pool) pool = mysql.createPool({
    host: process.env.DB_HOST || '10.180.0.84', user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'threat_platform', waitForConnections: true, connectionLimit: 10,
  });
  return pool;
}

// Mailchimp sends a GET to verify the webhook URL exists — must return 200
router.get('/mailchimp/:customer_id', (req, res) => res.sendStatus(200));

// POST — actual campaign event
router.post('/mailchimp/:customer_id', async (req, res) => {
  const { customer_id } = req.params;
  const { type, data } = req.body;

  // Respond immediately — Mailchimp times out fast, validation runs async
  res.sendStatus(200);

  if (!['campaign', 'campaign_send'].includes(type)) return;

  try {
    const p = getPool();
    const [[conn]] = await p.query(
      `SELECT credentials FROM platform_connectors
       WHERE customer_id=? AND connector_type='mailchimp' AND active=1 LIMIT 1`,
      [customer_id]
    );
    if (!conn) return;

    const creds = typeof conn.credentials === 'string' ? JSON.parse(conn.credentials) : conn.credentials;
    const apiKey = creds.api_key;
    const campaignId = data?.id;
    if (!apiKey || !campaignId) return;

    execFile('python3', [
      '/opt/virus-rescuers/connectors/mailchimp_validator.py',
      apiKey, campaignId
    ], { timeout: 30000 }, (err, stdout, stderr) => {
      if (err) console.error('[mailchimp-webhook] validation error:', stderr);
      else console.log('[mailchimp-webhook] validated:', stdout.slice(0, 200));
    });

  } catch (e) {
    console.error('[mailchimp-webhook] error:', e.message);
  }
});

module.exports = router;
