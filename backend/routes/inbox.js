const express  = require('express');
const router   = express.Router();
const Imap     = require('imap');
const { simpleParser } = require('mailparser');
const nodemailer = require('nodemailer');
const mysql = require('mysql2/promise');
const { requireRole } = require('../middleware/auth');
const { normalizeServer, MAIL_SERVERS } = require('../mailServers');

let threatPool = null;
function getThreatPool() {
  if (!threatPool) {
    threatPool = mysql.createPool({
      host: process.env.DB_HOST || '10.180.0.84',
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.PLATFORM_DB || 'threat_platform',
      waitForConnections: true,
      connectionLimit: 5,
    });
  }
  return threatPool;
}

/** Admin IMAP for App or Campaign from env */
function getAdminImapConfig(server = 'app') {
  const s = normalizeServer(server, 'app');
  if (s === 'campaign') {
    return {
      id: 'admin-campaign',
      kind: 'admin',
      mail_server: 'campaign',
      display_name: 'Campaign Admin',
      customer_id: null,
      customer_name: 'Worktual (Campaign)',
      user:     process.env.MAIL_IMAP_CAMPAIGN_USER || process.env.MAIL_IMAP_USER_CAMPAIGN || 'admin@worktual.pl',
      password: process.env.MAIL_IMAP_CAMPAIGN_PASSWORD || process.env.MAIL_IMAP_PASSWORD_CAMPAIGN || process.env.MAIL_IMAP_PASSWORD,
      host:     process.env.MAIL_IMAP_CAMPAIGN_HOST || process.env.MAIL_IMAP_HOST_CAMPAIGN || 'mail.worktual.pl',
      port:     parseInt(process.env.MAIL_IMAP_CAMPAIGN_PORT || process.env.MAIL_IMAP_PORT || '993', 10),
      tls:      true,
      tlsOptions: { rejectUnauthorized: false },
      connTimeout: 15000,
      authTimeout: 10000,
      smtp_host: process.env.MAIL_SMTP_CAMPAIGN_HOST || 'mail.worktual.pl',
      smtp_port: parseInt(process.env.MAIL_SMTP_CAMPAIGN_PORT || '587', 10),
      smtp_user: process.env.MAIL_SMTP_CAMPAIGN_USER || process.env.MAIL_IMAP_CAMPAIGN_USER,
      smtp_pass: process.env.MAIL_SMTP_CAMPAIGN_PASSWORD || process.env.MAIL_IMAP_CAMPAIGN_PASSWORD || process.env.MAIL_IMAP_PASSWORD,
      mail_from: process.env.MAIL_FROM_CAMPAIGN || process.env.MAIL_IMAP_CAMPAIGN_USER || 'admin@worktual.pl',
    };
  }
  return {
    id: 'admin-app',
    kind: 'admin',
    mail_server: 'app',
    display_name: 'App Admin',
    customer_id: null,
    customer_name: 'Worktual (App Mail)',
    user:     process.env.MAIL_IMAP_USER     || 'admin@worktual.tech',
    password: process.env.MAIL_IMAP_PASSWORD,
    host:     process.env.MAIL_IMAP_HOST     || 'mail.worktual.tech',
    port:     parseInt(process.env.MAIL_IMAP_PORT) || 993,
    tls:      true,
    tlsOptions: { rejectUnauthorized: false },
    connTimeout: 15000,
    authTimeout: 10000,
    smtp_host: process.env.MAIL_SMTP_HOST || 'mail.worktual.tech',
    smtp_port: parseInt(process.env.MAIL_SMTP_PORT || '587', 10),
    smtp_user: process.env.MAIL_SMTP_USER || process.env.MAIL_IMAP_USER,
    smtp_pass: process.env.MAIL_SMTP_PASSWORD || process.env.MAIL_IMAP_PASSWORD,
    mail_from: process.env.MAIL_FROM || process.env.MAIL_IMAP_USER || 'admin@worktual.tech',
  };
}

async function resolveMailbox(req) {
  const mailboxId = req.query.mailbox_id || req.body?.mailbox_id;
  const server = normalizeServer(req.query.server || req.body?.server, 'app');

  if (!mailboxId || String(mailboxId).startsWith('admin-')) {
    const cfg = getAdminImapConfig(
      String(mailboxId || '').includes('campaign') ? 'campaign' : server
    );
    if (!cfg.password) {
      const err = new Error(`IMAP password not configured for ${cfg.mail_server} admin inbox`);
      err.status = 503;
      throw err;
    }
    return cfg;
  }

  const [[row]] = await getThreatPool().query(
    `SELECT mm.*, c.name AS customer_name
     FROM mailbox_monitors mm
     JOIN customers c ON c.id = mm.customer_id
     WHERE mm.id = ?`,
    [mailboxId]
  );
  if (!row) {
    const err = new Error('Mailbox not found');
    err.status = 404;
    throw err;
  }
  return {
    id: String(row.id),
    kind: 'monitor',
    mail_server: row.mail_server || 'app',
    display_name: row.display_name || row.imap_user,
    customer_id: row.customer_id,
    customer_name: row.customer_name,
    user: row.imap_user,
    password: row.imap_pass,
    host: row.imap_host,
    port: row.imap_port || 993,
    tls: row.use_ssl !== 0,
    tlsOptions: { rejectUnauthorized: false },
    connTimeout: 15000,
    authTimeout: 10000,
    folder_default: row.folder || 'INBOX',
    smtp_host: row.imap_host,
    smtp_port: 587,
    smtp_user: row.imap_user,
    smtp_pass: row.imap_pass,
    mail_from: row.imap_user,
  };
}

function getSmtp(cfg) {
  return nodemailer.createTransport({
    host: cfg.smtp_host,
    port: cfg.smtp_port || 587,
    secure: false,
    tls: { rejectUnauthorized: false },
    ...(cfg.smtp_user ? {
      auth: { user: cfg.smtp_user, pass: cfg.smtp_pass },
    } : {}),
  });
}

function openImap(config) {
  return new Promise((resolve, reject) => {
    const imap = new Imap({
      user: config.user,
      password: config.password,
      host: config.host,
      port: config.port,
      tls: config.tls !== false,
      tlsOptions: config.tlsOptions || { rejectUnauthorized: false },
      connTimeout: config.connTimeout || 15000,
      authTimeout: config.authTimeout || 10000,
    });
    imap.once('ready', () => resolve(imap));
    imap.once('error', reject);
    imap.connect();
  });
}

function openBox(imap, mailbox = 'INBOX', readOnly = true) {
  return new Promise((resolve, reject) => {
    imap.openBox(mailbox, readOnly, (err, box) => {
      if (err) reject(err);
      else resolve(box);
    });
  });
}

function fetchMessages(imap, range, options) {
  return new Promise((resolve, reject) => {
    const messages = [];
    const fetch = imap.fetch(range, options);
    fetch.on('message', (msg, seqno) => {
      const msgData = { seqno, attrs: {} };
      msg.on('body', (stream, info) => {
        let buffer = '';
        stream.on('data', chunk => buffer += chunk.toString('utf8'));
        stream.once('end', () => { msgData[info.which] = buffer; });
      });
      msg.once('attributes', attrs => { msgData.attrs = attrs; });
      msg.once('end', () => messages.push(msgData));
    });
    fetch.once('error', reject);
    fetch.once('end', () => resolve(messages));
  });
}

async function ensureMonitorMailServer() {
  try {
    await getThreatPool().query(`
      ALTER TABLE mailbox_monitors
        ADD COLUMN mail_server ENUM('app','campaign','both') NOT NULL DEFAULT 'app'
        AFTER customer_id
    `);
  } catch (e) {
    if (!String(e.message).includes('Duplicate column')) { /* ok */ }
  }
}
ensureMonitorMailServer().catch(() => {});

// ---- GET /api/inbox/mailboxes?server=&customer_id= ----
// Lists admin + customer monitor mailboxes (no passwords)
router.get('/mailboxes', requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    await ensureMonitorMailServer();
    const server = normalizeServer(req.query.server, 'all');
    const { customer_id } = req.query;
    const list = [];

    // Infra admin inboxes
    for (const key of ['app', 'campaign']) {
      if (server !== 'all' && server !== key) continue;
      const cfg = getAdminImapConfig(key);
      list.push({
        id: cfg.id,
        kind: 'admin',
        mail_server: key,
        display_name: cfg.display_name,
        email: cfg.user,
        host: cfg.host,
        customer_id: null,
        customer_name: cfg.customer_name,
        domain: MAIL_SERVERS[key]?.domain,
      });
    }

    // Customer monitors
    let sql = `
      SELECT mm.id, mm.customer_id, mm.display_name, mm.imap_host, mm.imap_port,
             mm.imap_user, mm.folder, mm.mail_server, mm.active, c.name AS customer_name
      FROM mailbox_monitors mm
      JOIN customers c ON c.id = mm.customer_id
      WHERE mm.active = 1
    `;
    const params = [];
    if (customer_id) {
      sql += ' AND mm.customer_id = ?';
      params.push(customer_id);
    }
    if (server !== 'all') {
      sql += ` AND (mm.mail_server = ? OR mm.mail_server = 'both' OR mm.mail_server IS NULL)`;
      params.push(server);
    }
    sql += ' ORDER BY c.name, mm.display_name';

    try {
      const [rows] = await getThreatPool().query(sql, params);
      for (const r of rows) {
        list.push({
          id: String(r.id),
          kind: 'monitor',
          mail_server: r.mail_server || 'app',
          display_name: r.display_name || r.imap_user,
          email: r.imap_user,
          host: r.imap_host,
          customer_id: r.customer_id,
          customer_name: r.customer_name,
          folder: r.folder,
        });
      }
    } catch (e) {
      console.warn('[inbox/mailboxes] monitors:', e.message);
    }

    // Customers list for picker
    let customers = [];
    try {
      const [crows] = await getThreatPool().query(
        'SELECT id, name, domain, mail_server FROM customers ORDER BY name'
      );
      customers = crows;
    } catch { /* ok */ }

    res.json({ success: true, data: list, customers });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function withMailbox(req, res, fn) {
  let imap = null;
  try {
    const cfg = await resolveMailbox(req);
    imap = await openImap(cfg);
    await fn(imap, cfg);
  } catch (err) {
    if (imap) try { imap.end(); } catch { /* */ }
    res.status(err.status || 500).json({ error: err.message });
  }
}

// ---- GET /api/inbox/folders ----
router.get('/folders', requireRole('super_admin', 'admin'), async (req, res) => {
  await withMailbox(req, res, async (imap) => {
    imap.getBoxes((err, boxes) => {
      imap.end();
      if (err) return res.status(500).json({ error: err.message });
      const list = [];
      const walk = (obj, prefix = '') => {
        for (const [name, box] of Object.entries(obj)) {
          const fullName = prefix ? `${prefix}${box.delimiter}${name}` : name;
          list.push({ name, fullName, delimiter: box.delimiter, attribs: box.attribs });
          if (box.children) walk(box.children, fullName);
        }
      };
      walk(boxes);
      res.json({ success: true, data: list });
    });
  });
});

// ---- GET /api/inbox/messages ----
router.get('/messages', requireRole('super_admin', 'admin'), async (req, res) => {
  const { folder = 'INBOX', page = 1, limit = 30, search } = req.query;
  await withMailbox(req, res, async (imap, cfg) => {
    try {
      let box;
      try {
        box = await openBox(imap, folder || cfg.folder_default || 'INBOX', true);
      } catch {
        imap.end();
        return res.json({ success: true, data: [], total: 0, page: parseInt(page), pages: 0 });
      }
      const total = box.messages.total;
      if (total === 0) {
        imap.end();
        return res.json({ success: true, data: [], total: 0, page: 1, pages: 0 });
      }

      const pg    = parseInt(page);
      const lim   = parseInt(limit);
      const start = Math.max(1, total - (pg * lim) + 1);
      const end   = Math.max(1, total - ((pg - 1) * lim));
      const range = `${start}:${end}`;

      const rawMessages = await fetchMessages(imap, range, {
        bodies: ['HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID CC)'],
        struct: false
      });
      imap.end();

      const messages = await Promise.all(
        rawMessages.reverse().map(async (msg) => {
          const headerStr = msg['HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID CC)'] || '';
          const parsed    = await simpleParser(headerStr).catch(() => ({}));
          return {
            seqno:      msg.seqno,
            uid:        msg.attrs?.uid,
            flags:      msg.attrs?.flags || [],
            date:       msg.attrs?.date  || parsed.date,
            from:       parsed.from?.text || '',
            to:         parsed.to?.text   || '',
            cc:         parsed.cc?.text   || '',
            subject:    parsed.subject    || '(no subject)',
            message_id: parsed.messageId || '',
            seen:       (msg.attrs?.flags || []).includes('\\Seen'),
          };
        })
      );

      const filtered = search
        ? messages.filter(m =>
            m.subject.toLowerCase().includes(search.toLowerCase()) ||
            m.from.toLowerCase().includes(search.toLowerCase()) ||
            m.to.toLowerCase().includes(search.toLowerCase())
          )
        : messages;

      res.json({
        success: true,
        data: filtered,
        total,
        page: pg,
        pages: Math.ceil(total / lim),
        folder,
        mailbox: { id: cfg.id, display_name: cfg.display_name, email: cfg.user },
      });
    } catch (err) {
      imap.end();
      res.status(500).json({ error: err.message });
    }
  });
});

// ---- GET /api/inbox/message/:uid ----
router.get('/message/:uid', requireRole('super_admin', 'admin'), async (req, res) => {
  const { uid } = req.params;
  const { folder = 'INBOX' } = req.query;

  await withMailbox(req, res, async (imap) => {
    try {
      await openBox(imap, folder, false);
      await new Promise((resolve, reject) => {
        imap.addFlags(uid, '\\Seen', err => err ? reject(err) : resolve());
      });
      const rawMessages = await fetchMessages(imap, uid, { bodies: [''], struct: true });
      imap.end();

      if (rawMessages.length === 0) {
        return res.status(404).json({ error: 'Message not found' });
      }

      const raw    = rawMessages[0][''];
      const parsed = await simpleParser(raw);

      res.json({
        success: true,
        data: {
          uid,
          from:        parsed.from?.text       || '',
          to:          parsed.to?.text         || '',
          cc:          parsed.cc?.text         || '',
          subject:     parsed.subject          || '(no subject)',
          date:        parsed.date,
          text:        parsed.text             || '',
          html:        parsed.html             || '',
          message_id:  parsed.messageId        || '',
          attachments: (parsed.attachments || []).map(a => ({
            filename:    a.filename,
            contentType: a.contentType,
            size:        a.size,
          })),
          flags: rawMessages[0].attrs?.flags || [],
        }
      });
    } catch (err) {
      imap.end();
      res.status(500).json({ error: err.message });
    }
  });
});

// ---- DELETE /api/inbox/message/:uid ----
router.delete('/message/:uid', requireRole('super_admin', 'admin'), async (req, res) => {
  const { uid } = req.params;
  const { folder = 'INBOX' } = req.query;

  await withMailbox(req, res, async (imap) => {
    try {
      await openBox(imap, folder, false);
      await new Promise((resolve, reject) => {
        imap.addFlags(uid, '\\Deleted', err => err ? reject(err) : resolve());
      });
      await new Promise((resolve, reject) => {
        imap.expunge(err => err ? reject(err) : resolve());
      });
      imap.end();
      res.json({ success: true, message: 'Message deleted' });
    } catch (err) {
      imap.end();
      res.status(500).json({ error: err.message });
    }
  });
});

// ---- POST /api/inbox/send ----
router.post('/send', requireRole('super_admin', 'admin'), async (req, res) => {
  const { to, cc, bcc, subject, body, html, reply_to_message_id, reply_to_subject, mailbox_id, server } = req.body;

  if (!to || !subject || (!body && !html)) {
    return res.status(400).json({ error: 'to, subject, and body are required.' });
  }

  try {
    req.query.mailbox_id = mailbox_id;
    req.query.server = server;
    const cfg = await resolveMailbox(req);
    const smtp = getSmtp(cfg);
    const info = await smtp.sendMail({
      from:       `"${req.user.name}" <${cfg.mail_from}>`,
      to,
      cc:         cc  || undefined,
      bcc:        bcc || undefined,
      subject:    reply_to_subject ? `Re: ${reply_to_subject.replace(/^Re:\s*/i, '')}` : subject,
      text:       body,
      html:       html || `<pre style="font-family:Arial,sans-serif">${body}</pre>`,
      ...(reply_to_message_id && { inReplyTo: reply_to_message_id, references: reply_to_message_id }),
    });

    res.json({ success: true, message: `Email sent to ${to}`, messageId: info.messageId });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ---- GET /api/inbox/count ----
router.get('/count', requireRole('super_admin', 'admin'), async (req, res) => {
  await withMailbox(req, res, async (imap, cfg) => {
    try {
      await openBox(imap, cfg.folder_default || 'INBOX', true);
      imap.search(['UNSEEN'], (err, uids) => {
        imap.end();
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, unread: uids.length });
      });
    } catch (err) {
      imap.end();
      res.status(500).json({ error: err.message });
    }
  });
});

module.exports = router;
