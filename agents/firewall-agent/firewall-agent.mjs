#!/usr/bin/env node
// ============================================================
// Worktual Firewall Log Agent
// File: firewall-agent.mjs
// Deploy: /home/worktual/firewall-agent/ on BOTH mail servers
// Parses: /var/log/iptables.log + /var/log/fail2ban.log
// Pushes: /api/firewall/events every 30s
// PM2: pm2 start firewall-agent.mjs --name firewall-agent
// ============================================================

import fs   from 'fs';
import path from 'path';
import https from 'https';
import http  from 'http';
import { createReadStream } from 'fs';
import { createInterface } from 'readline';

// ── CONFIG ──────────────────────────────────────────────────
const DASHBOARD_URL = process.env.DASHBOARD_URL   || 'https://email-management.worktual.tech';
const AGENT_SECRET  = process.env.AGENT_SECRET    || 'WorktualAgent@2026';
const SERVER_NAME   = process.env.AGENT_SERVER    || 'app';
const OWN_IP        = process.env.OWN_IP          || '10.180.0.84';
const PUSH_INTERVAL = parseInt(process.env.PUSH_INTERVAL || '30') * 1000;
const IPTABLES_LOG  = process.env.IPTABLES_LOG    || '/var/log/iptables.log';
const FAIL2BAN_LOG  = process.env.FAIL2BAN_LOG    || '/var/log/fail2ban.log';
const STATE_FILE    = process.env.STATE_FILE       || '/var/lib/firewall-agent/state.json';

// ── STATE ───────────────────────────────────────────────────
let state = { iptables_pos: 0, fail2ban_pos: 0, last_push: 0 };
let eventBuffer = [];

// ── LOGGING ─────────────────────────────────────────────────
const log = (msg) => console.log(`[${new Date().toISOString().replace('T',' ').slice(0,19)}] ${msg}`);

// ── STATE PERSISTENCE ────────────────────────────────────────
function loadState() {
  try {
    const dir = path.dirname(STATE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (fs.existsSync(STATE_FILE)) {
      state = { ...state, ...JSON.parse(fs.readFileSync(STATE_FILE,'utf8')) };
    }
  } catch(e) { log(`State load error: ${e.message}`); }
}

function saveState() {
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
  } catch(e) { log(`State save error: ${e.message}`); }
}

// ── PARSE iptables LOG ───────────────────────────────────────
/*
Kernel log formats:
[FW-DENIED]   IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=10.180.0.84 ... PROTO=TCP DPT=22
[FW-SSH-DENIED] IN=eth0 ... SRC=5.6.7.8 ... DPT=4204
[FW-SMTP-NEW]   IN=eth0 ... SRC=9.10.11.12 ... DPT=25
[FW-SMTP-RATELIMIT] IN=eth0 ... SRC=... DPT=25
*/

function parseIptablesLine(line) {
  // Must contain [FW- prefix
  if (!line.includes('[FW-')) return null;

  const extract = (key) => {
    const m = new RegExp(`${key}=(\\S+)`).exec(line);
    return m ? m[1] : null;
  };

  // Determine event type from prefix
  let eventType = 'denied';
  if (line.includes('[FW-SMTP-NEW]'))      eventType = 'smtp_new';
  else if (line.includes('[FW-SMTP-RATELIMIT]')) eventType = 'smtp_ratelimit';
  else if (line.includes('[FW-SSH-DENIED]'))     eventType = 'ssh_denied';
  else if (line.includes('[FW-IMAP-NEW]'))        eventType = 'imap_new';
  else if (line.includes('[FW-IMAP-RATELIMIT]'))  eventType = 'imap_ratelimit';
  else if (line.includes('[FW-DENIED]'))          eventType = 'denied';
  else if (line.includes('[FW-FORWARD-DENIED]'))  eventType = 'forward_denied';

  const src   = extract('SRC');
  const dst   = extract('DST');
  const proto = extract('PROTO');
  const dpt   = extract('DPT');
  const spt   = extract('SPT');
  const iface = extract('IN');
  const ttl   = extract('TTL');
  const len   = extract('LEN');

  if (!src) return null;

  // Extract timestamp from kernel log line (format: Jul 15 13:45:22)
  const tsMatch = /^(\w+\s+\d+\s+\d+:\d+:\d+)/.exec(line);
  const timestamp = tsMatch
    ? new Date(new Date().getFullYear() + ' ' + tsMatch[1]).toISOString().replace('T',' ').slice(0,19)
    : new Date().toISOString().replace('T',' ').slice(0,19);

  return {
    event_type:  eventType,
    src_ip:      src,
    dst_ip:      dst || OWN_IP,
    protocol:    proto || 'unknown',
    dst_port:    dpt   ? parseInt(dpt)  : null,
    src_port:    spt   ? parseInt(spt)  : null,
    interface:   iface || 'eth0',
    action:      eventType.includes('new') ? 'allowed' : 'denied',
    log_datetime:timestamp,
    server:      SERVER_NAME,
    raw_line:    line.slice(0, 300),
  };
}

// ── PARSE fail2ban LOG ───────────────────────────────────────
/*
fail2ban format:
2026-07-15 13:45:22,123 fail2ban.actions [INFO] [sshd] Ban 1.2.3.4
2026-07-15 13:46:30,456 fail2ban.actions [INFO] [postfix-sasl] Ban 5.6.7.8
2026-07-15 14:00:00,789 fail2ban.actions [INFO] [sshd] Unban 1.2.3.4
*/

function parseFail2BanLine(line) {
  const banMatch = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*\[(\w[\w-]*)\]\s+(Ban|Unban)\s+([\d.]+)/.exec(line);
  if (!banMatch) return null;

  const [, timestamp, jail, action, ip] = banMatch;
  return {
    event_type:  action === 'Ban' ? 'fail2ban_ban' : 'fail2ban_unban',
    src_ip:      ip,
    dst_ip:      OWN_IP,
    protocol:    'tcp',
    dst_port:    null,
    action:      action === 'Ban' ? 'banned' : 'unbanned',
    jail:        jail,
    log_datetime:timestamp.slice(0,19),
    server:      SERVER_NAME,
    raw_line:    line.slice(0, 300),
  };
}

// ── READ NEW LINES FROM LOG FILE ─────────────────────────────
async function readNewLines(filePath, posKey, parser) {
  if (!fs.existsSync(filePath)) return;

  const stat = fs.statSync(filePath);
  const size = stat.size;

  // Handle log rotation (file smaller than last position)
  if (size < state[posKey]) {
    log(`${filePath} rotated — resetting position`);
    state[posKey] = 0;
  }

  if (size <= state[posKey]) return;

  const stream = createReadStream(filePath, {
    start:    state[posKey],
    end:      size - 1,
    encoding: 'utf8',
  });

  const rl      = createInterface({ input: stream, crlfDelay: Infinity });
  let   newPos  = state[posKey];
  let   newEvts = 0;

  for await (const line of rl) {
    newPos += Buffer.byteLength(line, 'utf8') + 1; // +1 for \n
    if (!line.trim()) continue;
    const evt = parser(line);
    if (evt) {
      eventBuffer.push(evt);
      newEvts++;
    }
  }

  state[posKey] = size;
  if (newEvts > 0) log(`${path.basename(filePath)}: ${newEvts} new events`);
}

// ── PUSH EVENTS TO DASHBOARD ─────────────────────────────────
async function pushEvents() {
  if (eventBuffer.length === 0) return;

  const batch = eventBuffer.splice(0, 200); // max 200 per push
  const body  = JSON.stringify({ events: batch, server: SERVER_NAME });

  return new Promise((resolve) => {
    const url     = new URL(`${DASHBOARD_URL}/api/firewall/events`);
    const isHttps = url.protocol === 'https:';
    const lib     = isHttps ? https : http;

    const options = {
      hostname: url.hostname,
      port:     url.port || (isHttps ? 443 : 80),
      path:     url.pathname,
      method:   'POST',
      headers:  {
        'Content-Type':  'application/json',
        'Content-Length': Buffer.byteLength(body),
        'X-Agent-Secret': AGENT_SECRET,
        'X-Server-Name':  SERVER_NAME,
      },
      rejectUnauthorized: false, // allow self-signed in dev
    };

    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        if (res.statusCode === 200) {
          log(`Pushed ${batch.length} events → ${res.statusCode}`);
        } else {
          log(`Push failed: ${res.statusCode} ${data.slice(0,100)}`);
          // Put events back in buffer
          eventBuffer.unshift(...batch);
        }
        resolve();
      });
    });

    req.on('error', (e) => {
      log(`Push error: ${e.message}`);
      eventBuffer.unshift(...batch); // requeue
      resolve();
    });

    req.write(body);
    req.end();
  });
}

// ── MAIN LOOP ─────────────────────────────────────────────────
async function tick() {
  try {
    await readNewLines(IPTABLES_LOG, 'iptables_pos', parseIptablesLine);
    await readNewLines(FAIL2BAN_LOG, 'fail2ban_pos', parseFail2BanLine);
    saveState();
    if (eventBuffer.length > 0) await pushEvents();
  } catch(e) {
    log(`Tick error: ${e.message}`);
  }
}

// ── STARTUP ──────────────────────────────────────────────────
log('='.repeat(60));
log('Worktual Firewall Log Agent starting');
log(`Server: ${SERVER_NAME} (${OWN_IP})`);
log(`Dashboard: ${DASHBOARD_URL}`);
log(`iptables log: ${IPTABLES_LOG}`);
log(`fail2ban log: ${FAIL2BAN_LOG}`);
log(`Push interval: ${PUSH_INTERVAL/1000}s`);
log('='.repeat(60));

loadState();

// Initial tick then schedule
tick();
setInterval(tick, PUSH_INTERVAL);
