#!/usr/bin/env node
// ============================================================
// log-agent.mjs — Worktual Mail Server Log Agent
// Deploy on: 10.180.0.84 (worktual.tech) and 10.180.0.89 (worktual.pl)
// Pushes to: https://email-management.worktual.tech/api/agent/ingest
// Run: pm2 start log-agent.mjs --name mail-log-agent
// ============================================================

import { createReadStream, statSync, readFileSync, existsSync } from 'fs';
import { stat, readFile, writeFile } from 'fs/promises';
import { exec } from 'child_process';
import { promisify } from 'util';
import { createInterface } from 'readline';
import https from 'https';
import http from 'http';

const execAsync = promisify(exec);

// ---- CONFIG (edit these) ----
const CONFIG = {
  // Which server is this agent running on
  server:         process.env.AGENT_SERVER     || 'campaign',   // 'app' or 'campaign'
  serverName:     process.env.AGENT_SERVER_NAME || 'mail.worktual.pl',
  vip:            process.env.AGENT_VIP        || '82.113.72.80',

  // Dashboard endpoint
  dashboardUrl:   process.env.DASHBOARD_URL    || 'https://email-management.worktual.tech',
  agentSecret:    process.env.AGENT_SECRET     || 'WorktualAgent@2026',

  // Log file to tail
  mailLog:        process.env.MAIL_LOG         || '/var/log/mail.log',

  // State file (tracks position in log file)
  stateFile:      process.env.STATE_FILE       || '/var/lib/mail-agent/state.json',

  // Polling interval (ms)
  pollInterval:   parseInt(process.env.POLL_INTERVAL) || 2000,

  // Queue snapshot interval (ms)
  queueInterval:  parseInt(process.env.QUEUE_INTERVAL) || 60000,

  // Batch size before flushing to dashboard
  batchSize:      parseInt(process.env.BATCH_SIZE) || 20,

  // Max age of pending events before force-flush (ms)
  flushTimeout:   parseInt(process.env.FLUSH_TIMEOUT) || 5000,

  // Domain to classify inbound/outbound
  ownDomain:      process.env.OWN_DOMAIN       || 'worktual.pl',
};

// ---- STATE ----
let filePosition = 0;
let pendingBatch = [];
let lastFlush    = Date.now();
let isActive     = true; // HA check
let stats        = { parsed: 0, pushed: 0, errors: 0, subjects: 0 };

// ---- STARTUP ----
console.log(`[agent] Starting Worktual Mail Log Agent`);
console.log(`[agent] Server: ${CONFIG.server} (${CONFIG.serverName})`);
console.log(`[agent] Log file: ${CONFIG.mailLog}`);
console.log(`[agent] Dashboard: ${CONFIG.dashboardUrl}`);

await loadState();
await checkHAStatus();

// Start all loops
setInterval(tailLog,          CONFIG.pollInterval);
setInterval(checkHAStatus,    30000);
setInterval(snapshotQueue,    CONFIG.queueInterval);
setInterval(forceFlushCheck,  1000);

// Initial run
await tailLog();
await snapshotQueue();

// ---- HA CHECK: only push if we hold the VIP ----
async function checkHAStatus() {
  try {
    const { stdout } = await execAsync(`ip addr show | grep '${CONFIG.vip}'`);
    isActive = stdout.includes(CONFIG.vip);
  } catch (e) {
    // If grep finds nothing it exits with code 1 — means we're passive
    isActive = false;
  }
  console.log(`[agent] HA status: ${isActive ? '✅ ACTIVE (pushing)' : '⏸ PASSIVE (standby)'}`);
}

// ---- LOAD STATE (resume from last position) ----
async function loadState() {
  try {
    if (existsSync(CONFIG.stateFile)) {
      const s = JSON.parse(await readFile(CONFIG.stateFile, 'utf8'));
      filePosition = s.position || 0;
      console.log(`[agent] Resuming from position ${filePosition}`);
    } else {
      // First run — start from end of file to avoid replaying old logs
      const s = statSync(CONFIG.mailLog);
      filePosition = s.size;
      console.log(`[agent] First run — starting from end of log (${filePosition} bytes)`);
      await saveState();
    }
  } catch (e) {
    console.error('[agent] State load error:', e.message);
    filePosition = 0;
  }
}

async function saveState() {
  try {
    const dir = CONFIG.stateFile.replace(/\/[^/]+$/, '');
    await execAsync(`mkdir -p ${dir}`);
    await writeFile(CONFIG.stateFile, JSON.stringify({ position: filePosition, updated: new Date().toISOString().replace('T',' ').replace('Z','').slice(0,19) }));
  } catch (e) {
    console.error('[agent] State save error:', e.message);
  }
}

// ---- TAIL LOG ----
async function tailLog() {
  try {
    const s = await stat(CONFIG.mailLog);
    const currentSize = s.size;

    // Log rotated — reset
    if (currentSize < filePosition) {
      console.log('[agent] Log rotation detected — resetting position');
      filePosition = 0;
    }

    if (currentSize === filePosition) return; // No new data

    // Read new data since last position
    const newData = await readNewLines(filePosition, currentSize);
    filePosition = currentSize;
    await saveState();

    if (newData.length > 0) {
      const events = parseLines(newData);
      if (events.length > 0) {
        // Enrich with subjects
        await enrichWithSubjects(events);
        pendingBatch.push(...events);
        stats.parsed += events.length;

        if (pendingBatch.length >= CONFIG.batchSize) {
          await flushBatch();
        }
      }
    }
  } catch (e) {
    console.error('[agent] tailLog error:', e.message);
    stats.errors++;
  }
}

// ---- READ NEW LINES ----
function readNewLines(start, end) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const stream = createReadStream(CONFIG.mailLog, {
      start,
      end: end - 1,
      encoding: 'utf8'
    });
    stream.on('data', chunk => chunks.push(chunk));
    stream.on('end', () => resolve(chunks.join('').split('\n').filter(l => l.trim())));
    stream.on('error', reject);
  });
}

// ---- PARSE LOG LINES ----
// Handles both syslog format and ISO8601 format
function parseLines(lines) {
  const events = [];

  for (const line of lines) {
    try {
      const event = parseLine(line);
      if (event) events.push(event);
    } catch (e) {
      // Skip unparseable lines silently
    }
  }

  return events;
}

function parseLine(line) {
  // Skip non-postfix / non-amavis lines
  if (!line.includes('postfix') && !line.includes('amavis') && !line.includes('dovecot')) return null;

  // Parse timestamp — support both formats:
  // ISO: 2026-06-28T14:34:29.847454+00:00 mail postfix/...
  // Syslog: Jun 29 07:26:56 mail postfix/...
  let datetime, rest;

  const isoMatch = line.match(/^(\d{4}-\d{2}-\d{2}T[\d:.+]+)\s+\S+\s+(.+)$/);
  const sysMatch = line.match(/^(\w{3}\s+\d+\s+[\d:]+)\s+\S+\s+(.+)$/);

  if (isoMatch) {
    datetime = new Date(isoMatch[1]);
    rest = isoMatch[2];
  } else if (sysMatch) {
    datetime = new Date(`${sysMatch[1]} ${new Date().getFullYear()}`);
    rest = sysMatch[2];
  } else {
    return null;
  }

  const base = {
    server:    CONFIG.server,
    server_name: CONFIG.serverName,
    log_datetime: datetime.toISOString().replace('T',' ').replace('Z','').slice(0,19),
    raw_line: line.slice(0, 500),
  };

  // ---- Postfix SMTP delivery ----
  // postfix/smtp[pid]: QUEUEID: to=<email>, relay=..., delay=..., status=sent
  const deliveryMatch = rest.match(/postfix\/(?:smtp|lmtp|local)\[\d+\]:\s+([A-Z0-9]+):\s+to=<([^>]+)>.*status=(\w+)(?:\s+\((.+)\))?/);
  if (deliveryMatch) {
    const [, queueId, mailTo, status, reason] = deliveryMatch;
    const dsnMatch = rest.match(/dsn=(\d+\.\d+\.\d+)/);
    const delayMatch = rest.match(/delay=([\d.]+)/);
    const relayMatch = rest.match(/relay=([^,]+)/);

    return {
      ...base,
      event_type:   'delivery',
      queue_id:     queueId,
      mail_to:      mailTo,
      status:       normalizeStatus(status),
      dsn:          dsnMatch?.[1] || null,
      reason:       reason?.slice(0, 500) || null,
      duration_ms:  delayMatch ? Math.round(parseFloat(delayMatch[1]) * 1000) : null,
      relay:        relayMatch?.[1]?.split('[')[0]?.trim() || null,
      direction:    mailTo.includes(CONFIG.ownDomain) ? 'inbound' : 'outbound',
    };
  }

  // ---- Postfix QMGR (from= line — captures sender + size) ----
  const qmgrMatch = rest.match(/postfix\/qmgr\[\d+\]:\s+([A-Z0-9]+):\s+from=<([^>]*)>,\s+size=(\d+)/);
  if (qmgrMatch) {
    const [, queueId, mailFrom, size] = qmgrMatch;
    return {
      ...base,
      event_type: 'queued',
      queue_id:   queueId,
      mail_from:  mailFrom,
      size_bytes: parseInt(size),
      direction:  mailFrom.includes(CONFIG.ownDomain) ? 'outbound' : 'inbound',
    };
  }

  // ---- Postfix SMTPD (connection + SASL auth) ----
  const smtpdMatch = rest.match(/postfix\/smtpd\[\d+\]:\s+([A-Z0-9]+):\s+client=([^,\[]+)(?:\[([^\]]+)\])?(?:.*sasl_username=(\S+))?/);
  if (smtpdMatch && !rest.includes('NOQUEUE')) {
    const [, queueId, clientName, clientIp, saslUser] = smtpdMatch;
    return {
      ...base,
      event_type:  'connection',
      queue_id:    queueId,
      relay_ip:    clientIp || null,
      sasl_user:   saslUser || null,
    };
  }

  // ---- Postfix REJECT ----
  const rejectMatch = rest.match(/postfix\/smtpd\[\d+\]:\s+NOQUEUE: reject:.*from=<([^>]*)>\s+to=<([^>]*)>.*:\s*(.+)/);
  if (rejectMatch) {
    const [, mailFrom, mailTo, reason] = rejectMatch;
    const dsnMatch = reason.match(/(\d+\.\d+\.\d+)/);
    return {
      ...base,
      event_type: 'reject',
      mail_from:  mailFrom,
      mail_to:    mailTo,
      status:     'rejected',
      dsn:        dsnMatch?.[1] || null,
      reason:     reason.slice(0, 500),
      direction:  'inbound',
    };
  }

  // ---- Amavis (spam score + actions) ----
  // amavis[pid]: (pid) Passed/Blocked SPAM/CLEAN {action}, ... Hits: score, ...
  const amavisMatch = rest.match(/amavis\[\d+\]:\s+\(\d+-\d+\)\s+(Passed|Blocked)\s+(\S+)\s+\{([^}]+)\}.*?<([^>]+)>\s*->\s*<([^>]+)>.*?Queue-ID:\s*(\S+).*?Message-ID:\s*<([^>]+)>.*?(?:Hits|score):\s*([-\d.]+)/i);
  if (amavisMatch) {
    const [, action, classification, policy, mailFrom, mailTo, queueId, messageId, score] = amavisMatch;
    const sizeMatch = rest.match(/size:\s*(\d+)/i);
    return {
      ...base,
      event_type:     'amavis',
      queue_id:       queueId,
      message_id:     `<${messageId}>`,
      mail_from:      mailFrom,
      mail_to:        mailTo,
      status:         action === 'Passed' ? 'delivered' : 'blocked',
      spam_score:     parseFloat(score),
      classification: classification,
      amavis_policy:  policy,
      size_bytes:     sizeMatch ? parseInt(sizeMatch[1]) : null,
      direction:      mailTo.includes(CONFIG.ownDomain) ? 'inbound' : 'outbound',
    };
  }

  // ---- Dovecot LMTP delivery (inbound to mailbox) ----
  const dovecotMatch = rest.match(/dovecot: lmtp\([^)]+\)<[^>]+><([^>]+)>: msgid=<([^>]+)>: saved mail to (\S+)/);
  if (dovecotMatch) {
    const [, user, messageId, mailbox] = dovecotMatch;
    return {
      ...base,
      event_type:  'delivered_to_mailbox',
      mail_to:     user,
      message_id:  `<${messageId}>`,
      mailbox:     mailbox,
      status:      'delivered',
      direction:   'inbound',
    };
  }

  return null;
}

// ---- EXTRACT SUBJECTS via postcat ----
// For each queued event with a queue_id, extract subject from mail spool
async function enrichWithSubjects(events) {
  const queueEvents = events.filter(e => e.queue_id && e.event_type === 'queued');

  await Promise.all(queueEvents.map(async event => {
    try {
      const subject = await getSubject(event.queue_id);
      if (subject) {
        event.subject = subject;
        // Apply to other events with same queue_id in this batch
        events.forEach(e => {
          if (e.queue_id === event.queue_id && !e.subject) {
            e.subject = subject;
          }
        });
        stats.subjects++;
      }
    } catch (e) {
      // Subject extraction is best-effort
    }
  }));
}

// Extract subject from postfix queue using postcat
async function getSubject(queueId) {
  try {
    // Method 1: postcat -q (works while mail is in queue)
    try {
      const { stdout } = await execAsync(
        `postcat -q ${queueId} 2>/dev/null | grep -i "^Subject:" | head -1`,
        { timeout: 3000 }
      );
      if (stdout && stdout.trim()) {
        return stdout.replace(/^Subject:\s*/i, '').trim().slice(0, 500);
      }
    } catch (e) {}

    // Method 2: grep mail.log for queue_id context
    try {
      const { stdout } = await execAsync(
        `grep -a "${queueId}" /var/log/mail.log 2>/dev/null | grep -i "subject" | sed 's/.*[Ss]ubject: //' | head -1`,
        { timeout: 2000 }
      );
      if (stdout && stdout.trim()) return stdout.trim().slice(0, 500);
    } catch (e) {}

    // Method 3: check spool directories directly
    const subdirChar = queueId.charAt(0).toUpperCase();
    for (const spoolDir of [
      '/var/spool/postfix/deferred/' + subdirChar,
      '/var/spool/postfix/active/'   + subdirChar,
      '/var/spool/postfix/incoming/' + subdirChar,
    ]) {
      try {
        const { stdout } = await execAsync(
          `postcat ${spoolDir}/${queueId} 2>/dev/null | grep -i "^Subject:" | head -1`,
          { timeout: 2000 }
        );
        if (stdout && stdout.trim()) {
          return stdout.replace(/^Subject:\s*/i, '').trim().slice(0, 500);
        }
      } catch (e) {}
    }

    return null;
  } catch (e) {
    return null;
  }
}


// ---- NORMALIZE STATUS ----
function normalizeStatus(status) {
  const map = {
    'sent':        'sent',
    'delivered':   'delivered',
    'bounced':     'bounced',
    'deferred':    'deferred',
    'expired':     'failed',
    'rejected':    'rejected',
    'undeliverable': 'failed',
  };
  return map[status?.toLowerCase()] || status?.toLowerCase() || 'unknown';
}

// ---- FLUSH BATCH TO DASHBOARD ----
async function flushBatch() {
  if (pendingBatch.length === 0 || !isActive) return;

  const batch = pendingBatch.splice(0, CONFIG.batchSize);
  lastFlush = Date.now();

  try {
    await pushToDashboard('/api/agent/ingest', { events: batch });
    stats.pushed += batch.length;
    console.log(`[agent] Pushed ${batch.length} events (total: ${stats.pushed})`);
  } catch (e) {
    console.error('[agent] Push failed:', e.message);
    stats.errors++;
    // Re-queue failed events (up to 500 to avoid memory issues)
    if (pendingBatch.length < 500) {
      pendingBatch.unshift(...batch);
    }
  }
}

async function forceFlushCheck() {
  if (pendingBatch.length > 0 && Date.now() - lastFlush > CONFIG.flushTimeout) {
    await flushBatch();
  }
}

// ---- QUEUE SNAPSHOT ----
async function snapshotQueue() {
  if (!isActive) return;

  try {
    const { stdout: mailq } = await execAsync('mailq 2>/dev/null || postqueue -p 2>/dev/null', { timeout: 10000 });
    const lines = mailq.split('\n');

    let queueCount = 0;
    let deferredCount = 0;
    const senders = {};

    for (const line of lines) {
      if (line.match(/^[A-Z0-9]{10,}/)) queueCount++;
      if (line.includes('(deferred)') || line.includes('(connection refused)')) deferredCount++;
      const fromMatch = line.match(/^[A-Z0-9]+\s+\d+\s+\S+\s+(\S+@\S+)/);
      if (fromMatch) {
        senders[fromMatch[1]] = (senders[fromMatch[1]] || 0) + 1;
      }
    }

    // Also get queue stats via postqueue
    let activeCount = 0, incomingCount = 0;
    try {
      const { stdout: active } = await execAsync('ls /var/spool/postfix/active/ 2>/dev/null | wc -l');
      const { stdout: incoming } = await execAsync('ls /var/spool/postfix/incoming/ 2>/dev/null | wc -l');
      activeCount   = parseInt(active.trim()) || 0;
      incomingCount = parseInt(incoming.trim()) || 0;
    } catch (e) { /* skip */ }

    await pushToDashboard('/api/agent/queue-snapshot', {
      server:        CONFIG.server,
      server_name:   CONFIG.serverName,
      snapshot_at:   new Date().toISOString().replace('T',' ').replace('Z','').slice(0,19).replace('T',' ').replace('Z','').slice(0,19),
      queue_count:   queueCount,
      deferred_count: deferredCount,
      active_count:  activeCount,
      incoming_count: incomingCount,
      top_senders:   Object.entries(senders).sort((a,b) => b[1]-a[1]).slice(0, 10),
    });

    console.log(`[agent] Queue snapshot: ${queueCount} queued, ${deferredCount} deferred`);
  } catch (e) {
    console.error('[agent] Queue snapshot error:', e.message);
  }
}

// ---- HTTP PUSH ----
function pushToDashboard(path, data) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(data);
    const url  = new URL(CONFIG.dashboardUrl + path);
    const isHttps = url.protocol === 'https:';
    const mod  = isHttps ? https : http;

    const options = {
      hostname: url.hostname,
      port:     url.port || (isHttps ? 443 : 80),
      path:     url.pathname,
      method:   'POST',
      headers: {
        'Content-Type':  'application/json',
        'Content-Length': Buffer.byteLength(body),
        'X-Agent-Secret': CONFIG.agentSecret,
        'X-Agent-Server': CONFIG.server,
      },
      timeout: 10000,
      rejectUnauthorized: false, // Accept self-signed / internal certs
    };

    const req = mod.request(options, res => {
      let responseBody = '';
      res.on('data', chunk => responseBody += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(JSON.parse(responseBody || '{}'));
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${responseBody.slice(0, 100)}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
    req.write(body);
    req.end();
  });
}

// ---- STATS REPORTING ----
setInterval(() => {
  console.log(`[agent] Stats — parsed: ${stats.parsed} | pushed: ${stats.pushed} | subjects: ${stats.subjects} | errors: ${stats.errors} | pending: ${pendingBatch.length}`);
}, 60000);

// ---- GRACEFUL SHUTDOWN ----
process.on('SIGTERM', async () => {
  console.log('[agent] SIGTERM received — flushing and exiting...');
  await flushBatch();
  await saveState();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('[agent] SIGINT received — flushing and exiting...');
  await flushBatch();
  await saveState();
  process.exit(0);
});
