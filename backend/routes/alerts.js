const express = require('express');
const router = express.Router();
const { getPool } = require('../db');
const nodemailer = require('nodemailer');

// Notification transporter (via local postfix)
const transporter = nodemailer.createTransport({
  host: process.env.NOTIFY_SMTP_HOST || 'localhost',
  port: parseInt(process.env.NOTIFY_SMTP_PORT) || 25,
  secure: false,
  tls: { rejectUnauthorized: false }
});

// Team routing config
const TEAMS = {
  devops: {
    name: 'DevOps Team',
    email: process.env.NOTIFY_TEAM_DEVOPS || 'devops-team@worktual.tech',
    issues: ['spam_blocked', 'ip_blocked', 'blacklist', 'deferred', 'timedout']
  },
  backend: {
    name: 'Backend/App Team',
    email: process.env.NOTIFY_TEAM_BACKEND || 'backend-team@worktual.tech',
    issues: ['failed', 'invalid', 'unformatted', 'malformed']
  },
  email: {
    name: 'Email/Campaign Team',
    email: process.env.NOTIFY_TEAM_EMAIL || 'email-team@worktual.tech',
    issues: ['bounced', 'high_bounce_rate', 'campaign_failure']
  }
};

async function loadStoredThresholds(server) {
  try {
    const pool = getPool(server);
    const [rows] = await pool.query(
      `SELECT setting_key, setting_value FROM app_settings
       WHERE setting_key IN ('alert_failed_threshold','alert_bounce_threshold','alert_spam_threshold')`
    );
    const map = {};
    for (const r of rows) map[r.setting_key] = r.setting_value;
    return map;
  } catch {
    return {};
  }
}

function resolveThresholds(stored) {
  return {
    failed: parseInt(stored.alert_failed_threshold || process.env.ALERT_FAILED_THRESHOLD, 10) || 50,
    bounce: parseInt(stored.alert_bounce_threshold || process.env.ALERT_BOUNCE_THRESHOLD, 10) || 20,
    spam: parseInt(stored.alert_spam_threshold || process.env.ALERT_SPAM_THRESHOLD, 10) || 10,
  };
}

// GET /api/alerts/thresholds — current auto-alert status
router.get('/thresholds', async (req, res) => {
  try {
    const stored = await loadStoredThresholds(req.query.server);
    const th = resolveThresholds(stored);

    const [rows] = await getPool(req.query.server).query(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN status = 'failed' OR delivery_status = 'failed' THEN 1 ELSE 0 END) AS failed,
        SUM(CASE WHEN status = 'bounced' OR delivery_status = 'bounced' OR dsn LIKE '5%' THEN 1 ELSE 0 END) AS bounced,
        SUM(CASE WHEN reason LIKE '%spam%' OR reason LIKE '%blocked%' OR reason LIKE '%blacklist%' OR reason LIKE '%spamhaus%' THEN 1 ELSE 0 END) AS spam,
        SUM(CASE WHEN status = 'deferred' OR delivery_status = 'deferred' THEN 1 ELSE 0 END) AS deferred,
        SUM(CASE WHEN status = 'timeout' OR delivery_status = 'timeout' THEN 1 ELSE 0 END) AS timedout
      FROM email_delivery_details
      WHERE log_date = CURDATE()
    `);

    const stats = rows[0];
    const alerts = [];
    const failedThreshold = th.failed;
    const bounceThreshold = th.bounce;
    const spamThreshold = th.spam;

    if (stats.failed >= failedThreshold) {
      alerts.push({ type: 'failed', severity: 'critical', count: stats.failed, threshold: failedThreshold, team: 'backend', message: `${stats.failed} failed emails today (threshold: ${failedThreshold})` });
    }
    if (stats.bounced >= bounceThreshold) {
      alerts.push({ type: 'bounced', severity: 'high', count: stats.bounced, threshold: bounceThreshold, team: 'email', message: `${stats.bounced} bounced emails today (threshold: ${bounceThreshold})` });
    }
    if (stats.spam >= spamThreshold) {
      alerts.push({ type: 'spam_blocked', severity: 'critical', count: stats.spam, threshold: spamThreshold, team: 'devops', message: `${stats.spam} emails blocked as spam today (threshold: ${spamThreshold}) — IP may be blacklisted` });
    }
    if (stats.deferred >= 100) {
      alerts.push({ type: 'deferred', severity: 'warning', count: stats.deferred, threshold: 100, team: 'devops', message: `${stats.deferred} emails deferred today — check receiving server availability` });
    }
    if (stats.timedout >= 30) {
      alerts.push({ type: 'timedout', severity: 'warning', count: stats.timedout, threshold: 30, team: 'devops', message: `${stats.timedout} emails timed out today — check network/postfix queue` });
    }

    res.json({
      success: true,
      stats,
      alerts,
      teams: TEAMS,
      thresholds: { failed: failedThreshold, bounce: bounceThreshold, spam: spamThreshold },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/alerts/update-thresholds — persist + apply live alert thresholds
router.post('/update-thresholds', async (req, res) => {
  try {
    const server = req.query.server || req.body.server || 'app';
    const pool = getPool(server);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_settings (
        setting_key   VARCHAR(128) PRIMARY KEY,
        setting_value TEXT NULL,
        updated_by    VARCHAR(128) NULL,
        updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    const failed = req.body.failed_threshold ?? req.body.alert_failed_threshold;
    const bounce = req.body.bounce_threshold ?? req.body.alert_bounce_threshold;
    const spam = req.body.spam_threshold ?? req.body.alert_spam_threshold;
    const actor = req.user?.email || req.user?.username || 'admin';

    const updates = {};
    if (failed != null && failed !== '') updates.alert_failed_threshold = String(failed);
    if (bounce != null && bounce !== '') updates.alert_bounce_threshold = String(bounce);
    if (spam != null && spam !== '') updates.alert_spam_threshold = String(spam);

    if (!Object.keys(updates).length) {
      return res.status(400).json({ error: 'No threshold values provided' });
    }

    for (const [key, value] of Object.entries(updates)) {
      await pool.query(
        `INSERT INTO app_settings (setting_key, setting_value, updated_by)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value), updated_by=VALUES(updated_by)`,
        [key, value, actor]
      );
    }

    if (updates.alert_failed_threshold) process.env.ALERT_FAILED_THRESHOLD = updates.alert_failed_threshold;
    if (updates.alert_bounce_threshold) process.env.ALERT_BOUNCE_THRESHOLD = updates.alert_bounce_threshold;
    if (updates.alert_spam_threshold) process.env.ALERT_SPAM_THRESHOLD = updates.alert_spam_threshold;

    res.json({ success: true, message: 'Alert thresholds updated', thresholds: updates });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/alerts/notify — send notification to team
router.post('/notify', async (req, res) => {
  try {
    const { team, subject, issue_type, details, mail_ids, custom_message } = req.body;

    if (!team || !TEAMS[team]) {
      return res.status(400).json({ error: 'Invalid team. Must be: devops, backend, email' });
    }

    const teamConfig = TEAMS[team];

    // Build problematic mails summary if mail_ids given
    let mailTable = '';
    if (mail_ids && mail_ids.length > 0) {
      const [mails] = await getPool(req.query.server).query(
        `SELECT id, log_date, log_time, mail_from, mail_to, campaign_id, status, delivery_status, dsn, reason
         FROM email_delivery_details WHERE id IN (?) LIMIT 100`,
        [mail_ids.slice(0, 100)]
      );

      if (mails.length > 0) {
        mailTable = `
          <h3>Affected Emails (${mails.length} records)</h3>
          <table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-size:12px;width:100%">
            <tr style="background:#1e3a5f;color:#fff">
              <th>ID</th><th>Date/Time</th><th>From</th><th>To</th><th>Campaign</th><th>Status</th><th>DSN</th><th>Reason</th>
            </tr>
            ${mails.map((m, i) => `
              <tr style="background:${i % 2 === 0 ? '#f9f9f9' : '#fff'}">
                <td>${m.id}</td>
                <td>${m.log_date} ${m.log_time}</td>
                <td>${m.mail_from || '-'}</td>
                <td>${m.mail_to || '-'}</td>
                <td>${m.campaign_id || '-'}</td>
                <td><b style="color:${getStatusColor(m.status)}">${m.status || m.delivery_status || '-'}</b></td>
                <td>${m.dsn || '-'}</td>
                <td style="max-width:300px;word-break:break-all">${(m.reason || '-').substring(0, 150)}</td>
              </tr>`).join('')}
          </table>`;
      }
    }

    const html = buildEmailHTML(teamConfig.name, issue_type, custom_message || details, mailTable);

    await transporter.sendMail({
      from: `"Email Alert System" <${process.env.NOTIFY_FROM || 'noreply@worktual.tech'}>`,
      to: teamConfig.email,
      subject: subject || `[EMAIL ALERT] ${issue_type} — Action Required`,
      html
    });

    res.json({ success: true, message: `Alert sent to ${teamConfig.name} (${teamConfig.email})` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/alerts/auto-notify — triggered by scheduler or manual button
router.post('/auto-notify', async (req, res) => {
  try {
    const [rows] = await getPool(req.query.server).query(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN status = 'failed' OR delivery_status = 'failed' THEN 1 ELSE 0 END) AS failed,
        SUM(CASE WHEN status = 'bounced' OR delivery_status = 'bounced' OR dsn LIKE '5%' THEN 1 ELSE 0 END) AS bounced,
        SUM(CASE WHEN reason LIKE '%spam%' OR reason LIKE '%blocked%' OR reason LIKE '%spamhaus%' THEN 1 ELSE 0 END) AS spam,
        SUM(CASE WHEN status = 'deferred' OR delivery_status = 'deferred' THEN 1 ELSE 0 END) AS deferred,
        SUM(CASE WHEN status IN ('sent','delivered') OR delivery_status IN ('sent','delivered') THEN 1 ELSE 0 END) AS success
      FROM email_delivery_details
      WHERE log_date = CURDATE()
    `);

    const stats = rows[0];
    const sent = [];

    // Notify DevOps for spam
    if (stats.spam >= parseInt(process.env.ALERT_SPAM_THRESHOLD || 10)) {
      await transporter.sendMail({
        from: `"Email Alert System" <${process.env.NOTIFY_FROM}>`,
        to: TEAMS.devops.email,
        subject: `🚨 [CRITICAL] IP Spam Blocking Alert — ${stats.spam} emails blocked today`,
        html: buildEmailHTML('DevOps Team', 'IP SPAM BLOCKING', `
          <b>${stats.spam} emails</b> were blocked by spam filters/RBL today.<br><br>
          Your mail server IP may be listed on Spamhaus or other blacklists.<br><br>
          <b>Immediate actions required:</b>
          <ul>
            <li>Check IP on <a href="https://www.spamhaus.org/lookup/">Spamhaus Lookup</a></li>
            <li>Check MXToolbox: <a href="https://mxtoolbox.com/blacklists.aspx">Blacklist Check</a></li>
            <li>Review /var/log/mail.log for rejection patterns</li>
            <li>Verify PTR/rDNS, SPF, DKIM, DMARC records</li>
            <li>Check if NOTIFY_FROM IP has valid rDNS</li>
          </ul>
          <b>Today's Summary:</b><br>
          Total: ${stats.total} | Success: ${stats.success} | Failed: ${stats.failed} | Spam Blocked: ${stats.spam} | Bounced: ${stats.bounced}
        `, '')
      });
      sent.push('devops (spam alert)');
    }

    // Notify Backend for high failures
    if (stats.failed >= parseInt(process.env.ALERT_FAILED_THRESHOLD || 50)) {
      await transporter.sendMail({
        from: `"Email Alert System" <${process.env.NOTIFY_FROM}>`,
        to: TEAMS.backend.email,
        subject: `⚠️ [HIGH] Email Delivery Failures — ${stats.failed} failed today`,
        html: buildEmailHTML('Backend Team', 'HIGH FAILURE RATE', `
          <b>${stats.failed} emails</b> failed delivery today.<br><br>
          <b>Common causes to check:</b>
          <ul>
            <li>Invalid/malformed email addresses in application</li>
            <li>Missing or incorrect email headers (From, To, Subject)</li>
            <li>Unsubscribe/complaint handling not implemented</li>
            <li>Large attachment causing rejection</li>
            <li>Template rendering failures producing malformed content</li>
          </ul>
          <b>Today's Summary:</b><br>
          Total: ${stats.total} | Success: ${stats.success} | Failed: ${stats.failed} | Bounced: ${stats.bounced}
        `, '')
      });
      sent.push('backend (failure alert)');
    }

    // Notify Email team for bounce
    if (stats.bounced >= parseInt(process.env.ALERT_BOUNCE_THRESHOLD || 20)) {
      await transporter.sendMail({
        from: `"Email Alert System" <${process.env.NOTIFY_FROM}>`,
        to: TEAMS.email.email,
        subject: `⚠️ [HIGH] High Bounce Rate — ${stats.bounced} bounces today`,
        html: buildEmailHTML('Email/Campaign Team', 'HIGH BOUNCE RATE', `
          <b>${stats.bounced} emails</b> bounced today.<br><br>
          <b>Actions required:</b>
          <ul>
            <li>Review and clean mailing lists — remove hard bounces immediately</li>
            <li>Check campaign targeting criteria</li>
            <li>Implement double opt-in for new subscribers</li>
            <li>Use email validation before adding to lists</li>
            <li>Review DSN codes for 5.1.1 (no such user) patterns</li>
          </ul>
          <b>Today's Summary:</b><br>
          Total: ${stats.total} | Success: ${stats.success} | Bounced: ${stats.bounced} | Failed: ${stats.failed}
        `, '')
      });
      sent.push('email-team (bounce alert)');
    }

    res.json({
      success: true,
      notifications_sent: sent,
      stats,
      message: sent.length > 0 ? `Alerts sent to: ${sent.join(', ')}` : 'No thresholds exceeded — no alerts sent'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function getStatusColor(status) {
  const map = { sent: '#16a34a', delivered: '#16a34a', failed: '#dc2626', bounced: '#ea580c', deferred: '#d97706', processing: '#2563eb', timeout: '#7c3aed', invalid: '#b91c1c', spam: '#be185d' };
  return map[status] || '#374151';
}

function buildEmailHTML(teamName, issueType, body, mailTable) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
  <body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px;margin:0">
    <div style="max-width:900px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)">
      <div style="background:linear-gradient(135deg,#1e3a5f,#2563eb);color:#fff;padding:24px 32px">
        <h1 style="margin:0;font-size:22px">📧 Email Management Alert</h1>
        <p style="margin:8px 0 0;opacity:0.85">Worktual Innovations — email-management.worktual.tech</p>
      </div>
      <div style="padding:32px">
        <p>Dear <b>${teamName}</b>,</p>
        <p>An automated alert has been triggered for your team:</p>
        <div style="background:#fef3c7;border-left:4px solid #f59e0b;padding:16px;border-radius:4px;margin:16px 0">
          <b>Issue Type: ${issueType}</b>
        </div>
        <div style="margin:16px 0;line-height:1.7">${body}</div>
        ${mailTable}
        <br>
        <p style="color:#6b7280;font-size:13px">
          Generated at: ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })} IST<br>
          Dashboard: <a href="https://email-management.worktual.tech">email-management.worktual.tech</a>
        </p>
      </div>
      <div style="background:#f9fafb;padding:16px 32px;border-top:1px solid #e5e7eb;text-align:center;color:#6b7280;font-size:12px">
        Worktual Innovations Pvt Ltd, Chennai — Email Management System
      </div>
    </div>
  </body></html>`;
}

module.exports = router;
