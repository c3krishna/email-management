// /var/www/email-management/backend/routes/agent.js
// Receives log events from log-agent.mjs running on mail servers
// Stores in email_log_realtime and email_subjects tables

//import express from 'express';
const express  = require('express');
const router = express.Router();

// We use CommonJS here since backend uses require()
const { getPool } = require('../db');
const { detectVipImpersonation } = require('../vipDetect');
const { getThreatPool } = require('../threatDb');
const { decodeRfc2047Subject, mapRowsDecodeSubject } = require('../decodeSubject');

const decodeSubject = decodeRfc2047Subject;


const AGENT_SECRET = process.env.AGENT_SECRET;
const { verifyToken } = require('../middleware/auth');

// ---- Auth middleware for agent requests ----
function agentAuth(req, res, next) {
  if (!AGENT_SECRET) {
    return res.status(500).json({ error: 'Server misconfigured: AGENT_SECRET is not set' });
  }
  const secret = req.headers['x-agent-secret'];
  if (secret !== AGENT_SECRET) {
    return res.status(401).json({ error: 'Invalid agent secret' });
  }
  next();
}

// ---- POST /api/agent/ingest — receive batch of log events ----
router.post('/ingest', agentAuth, async (req, res) => {
  const { events } = req.body;
  if (!events || !Array.isArray(events) || events.length === 0) {
    return res.status(400).json({ error: 'No events provided' });
  }

  const server = req.headers['x-agent-server'] || 'app';
  const pool   = getPool(server);

  let inserted = 0;
  let subjects  = 0;

  try {
    // Process events in parallel batches
    const CHUNK = 50;
    for (let i = 0; i < events.length; i += CHUNK) {
      const chunk = events.slice(i, i + CHUNK);
      await Promise.all(chunk.map(e => processEvent(pool, e, server)));
      inserted += chunk.length;
    }

    // Update subjects in email_delivery_details
    const subjectEvents = events.filter(e => e.subject && e.queue_id);
    if (subjectEvents.length > 0) {
      await updateSubjects(pool, subjectEvents);
      subjects = subjectEvents.length;
    }

    // Propagate subjects async
    setImmediate(async () => {
      try {
        await pool.query(
          'UPDATE email_log_realtime d ' +
          'JOIN (SELECT queue_id, subject, mail_from FROM email_log_realtime ' +
          '      WHERE event_type IN (?) AND subject IS NOT NULL AND queue_id IS NOT NULL ' +
          '      AND log_datetime >= DATE_SUB(NOW(), INTERVAL 2 HOUR)) q ' +
          'ON d.queue_id = q.queue_id ' +
          'SET d.subject = q.subject, ' +
          '    d.mail_from = CASE WHEN (d.mail_from IS NULL OR d.mail_from = \'\') THEN q.mail_from ELSE d.mail_from END ' +
          'WHERE d.event_type = ? ' +
          'AND (d.subject IS NULL OR d.subject = \'\') ' +
          'AND d.log_datetime >= DATE_SUB(NOW(), INTERVAL 2 HOUR)',
          [['queued','connection','amavis'], 'delivery']
        );
      } catch(e) {}
    });
    res.json({ success: true, inserted, subjects });
  } catch (err) {
    console.error('[agent-ingest] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---- POST /api/agent/queue-snapshot ----
router.post('/queue-snapshot', agentAuth, async (req, res) => {
  try {
    const pool = getPool(req.headers['x-agent-server'] || 'app');
    await pool.query(`
      INSERT INTO postfix_queue_snapshot
        (server, server_name, snapshot_at, queue_count, deferred_count, active_count, incoming_count, top_senders)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      req.body.server,
      req.body.server_name,
      req.body.snapshot_at ? req.body.snapshot_at.replace('T',' ').replace('Z','').slice(0,19) : null,
      req.body.queue_count     || 0,
      req.body.deferred_count  || 0,
      req.body.active_count    || 0,
      req.body.incoming_count  || 0,
      JSON.stringify(req.body.top_senders || []),
    ]);
    res.json({ success: true });
  } catch (err) {
    console.error('[agent-queue] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---- GET /api/agent/status — dashboard polls this ----
router.get('/status', verifyToken, async (req, res) => {
  try {
    const appPool = getPool('app');
    const campPool = getPool('campaign');

    const [[appRow]]  = await appPool.query(`
      SELECT server, server_name, snapshot_at, queue_count, deferred_count, active_count
      FROM postfix_queue_snapshot
      ORDER BY id DESC LIMIT 1
    `).catch(() => [[null]]);

    const [[campRow]] = await campPool.query(`
      SELECT server, server_name, snapshot_at, queue_count, deferred_count, active_count
      FROM postfix_queue_snapshot
      ORDER BY id DESC LIMIT 1
    `).catch(() => [[null]]);

    const [[appLog]]  = await appPool.query(`
      SELECT MAX(log_datetime) as last_event, COUNT(*) as total_today
      FROM email_log_realtime
      WHERE DATE(log_datetime) = CURDATE()
    `).catch(() => [[{ last_event: null, total_today: 0 }]]);

    const [[campLog]] = await campPool.query(`
      SELECT MAX(log_datetime) as last_event, COUNT(*) as total_today
      FROM email_log_realtime
      WHERE DATE(log_datetime) = CURDATE()
    `).catch(() => [[{ last_event: null, total_today: 0 }]]);

    res.json({
      success: true,
      agents: {
        app: {
          queue:    appRow  || { queue_count: 0, deferred_count: 0 },
          realtime: appLog  || { last_event: null, total_today: 0 },
          online:   appRow ? (Date.now() - new Date(appRow.snapshot_at.toString().replace(' ', 'T') + 'Z').getTime() < 180000) : false,
        },
        campaign: {
          queue:    campRow || { queue_count: 0, deferred_count: 0 },
          realtime: campLog || { last_event: null, total_today: 0 },
          online:   campRow ? (Date.now() - new Date(campRow.snapshot_at.toString().replace(' ', 'T') + 'Z').getTime() < 180000) : false,
        }
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- GET /api/agent/realtime-logs ----
router.get('/realtime-logs', verifyToken, async (req, res) => {
  try {
    const { server = 'app', limit = 100, since, event_type, direction, status } = req.query;
    const pool = getPool(server);

    const conditions = ['1=1'];
    const params     = [];

    if (since)       { conditions.push('log_datetime > ?');  params.push(since); }
    if (event_type)  { conditions.push('event_type = ?');    params.push(event_type); }
    if (direction)   { conditions.push('direction = ?');     params.push(direction); }
    if (status)      { conditions.push('status = ?');        params.push(status); }

    const [rows] = await pool.query(`
      SELECT
        id, server, log_datetime, event_type, queue_id, message_id,
        mail_from, mail_to, subject, status, dsn, reason,
        spam_score, dkim_result, spf_result, relay_ip,
        size_bytes, duration_ms, direction, classification
      FROM email_log_realtime
      WHERE ${conditions.join(' AND ')}
      ORDER BY log_datetime DESC
      LIMIT ?
    `, [...params, parseInt(limit)]);

    res.json({ success: true, data: mapRowsDecodeSubject(rows) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- GET /api/agent/queue-status ----
router.get('/queue-status', verifyToken, async (req, res) => {
  try {
    const { server = 'app' } = req.query;
    const pool = getPool(server);

    const [snapshots] = await pool.query(`
      SELECT * FROM postfix_queue_snapshot
      ORDER BY id DESC LIMIT 48
    `);

    const [latest] = await pool.query(`
      SELECT * FROM postfix_queue_snapshot ORDER BY id DESC LIMIT 1
    `);

    res.json({
      success: true,
      current: latest[0] || null,
      history: snapshots.reverse(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- PROCESS SINGLE EVENT ----
async function processEvent(pool, event, server) {
  try {
    await pool.query(`
      INSERT INTO email_log_realtime
        (server, server_name, log_datetime, event_type, queue_id, message_id,
         mail_from, mail_to, subject, direction, status, dsn, reason,
         spam_score, dkim_result, spf_result, relay_ip, sasl_user,
         size_bytes, duration_ms, classification, amavis_policy, raw_line)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        status = COALESCE(VALUES(status), status),
        dsn    = COALESCE(VALUES(dsn),    dsn),
        reason = COALESCE(VALUES(reason), reason),
        subject= COALESCE(VALUES(subject), subject)
    `, [
      server,
      event.server_name    || null,
      event.log_datetime ? event.log_datetime.toString().replace('T',' ').replace('Z','').slice(0,19) : new Date().toISOString().replace('T',' ').replace('Z','').slice(0,19),
      event.event_type     || 'unknown',
      event.queue_id       || null,
      event.message_id     || null,
      event.mail_from      || null,
      event.mail_to        || null,
      decodeSubject(event.subject) || null,
      event.direction      || null,
      event.status         || null,
      event.dsn            || null,
      event.reason         ? event.reason.slice(0, 500) : null,
      event.spam_score     || null,
      event.dkim_result    || null,
      event.spf_result     || null,
      event.relay_ip       || null,
      event.sasl_user      || null,
      event.size_bytes     || null,
      event.duration_ms    || null,
      event.classification || null,
      event.amavis_policy  || null,
      event.raw_line       ? event.raw_line.slice(0, 500) : null,
    ]);

    // Propagate mail_from from queued→delivery events (same queue_id)
    if (event.event_type === 'queued' && event.mail_from && event.queue_id) {
      await pool.query(`
        UPDATE email_log_realtime
        SET mail_from = ?
        WHERE queue_id = ? AND (mail_from IS NULL OR mail_from = '')
          AND event_type != 'queued'
      `, [event.mail_from, event.queue_id]).catch(() => {});
    }

    // Also update subject in email_delivery_details if we have queue_id + subject
    const decodedSubj = decodeSubject(event.subject);
    if (decodedSubj && event.queue_id) {
      await pool.query(`
        UPDATE email_delivery_details
        SET subject = ?
        WHERE queue_id = ? AND (subject IS NULL OR subject = '' OR subject LIKE '=?%')
      `, [decodedSubj, event.queue_id]).catch(() => {});

      await pool.query(`
        UPDATE email_log_realtime
        SET subject = ?
        WHERE queue_id = ? AND (subject IS NULL OR subject = '' OR subject LIKE '=?%')
      `, [decodedSubj, event.queue_id]).catch(() => {});
    }
    // VIP impersonation check on inbound-looking messages with a From header
    if (event.mail_from && (event.direction === 'inbound' || event.event_type === 'received' || !event.direction)) {
      detectVipImpersonation(getThreatPool(), {
        mail_from: event.mail_from,
        mail_to: event.mail_to,
        subject: event.subject,
        mail_server: server === 'campaign' ? 'campaign' : 'app',
      }).catch(e => console.warn('[vip-detect]', e.message));
    }
  } catch (err) {
    // Ignore duplicate key errors
    if (!err.message.includes('Duplicate entry') && !err.message.includes('ER_DUP')) {
      console.error('[processEvent] Error:', err.message, '| Event type:', event.event_type);
    }
  }
}

// ---- UPDATE SUBJECTS in email_delivery_details ----
async function updateSubjects(pool, events) {
  try {
    // First ensure subject column exists
    await pool.query(`
      ALTER TABLE email_delivery_details
      ADD COLUMN IF NOT EXISTS subject VARCHAR(500) DEFAULT NULL
    `).catch(() => {}); // Ignore if already exists

    for (const event of events) {
      if (!event.subject || !event.queue_id) continue;
      const decoded = decodeSubject(event.subject);
      if (!decoded) continue;
      await pool.query(`
        UPDATE email_delivery_details
        SET subject = ?
        WHERE queue_id = ? AND (subject IS NULL OR subject = '' OR subject LIKE '=?%')
        LIMIT 10
      `, [decoded, event.queue_id]);
    }
  } catch (err) {
    console.error('[updateSubjects] Error:', err.message);
  }
}

module.exports = router;
