const express  = require('express');
const router   = express.Router();
const Imap     = require('imap');
const { simpleParser } = require('mailparser');
const nodemailer = require('nodemailer');
const { requireRole } = require('../middleware/auth');

// IMAP config from env
function getImapConfig() {
  return {
    user:     process.env.MAIL_IMAP_USER     || 'admin@worktual.tech',
    password: process.env.MAIL_IMAP_PASSWORD,
    host:     process.env.MAIL_IMAP_HOST     || 'mail.worktual.tech',
    port:     parseInt(process.env.MAIL_IMAP_PORT) || 993,
    tls:      true,
    tlsOptions: { rejectUnauthorized: false },
    connTimeout: 15000,
    authTimeout: 10000,
  };
}

// SMTP transporter for sending
const getSmtp = () => nodemailer.createTransport({
  host: process.env.MAIL_SMTP_HOST || 'mail.worktual.tech',
  port: parseInt(process.env.MAIL_SMTP_PORT) || 587,
  secure: false,
  tls: { rejectUnauthorized: false },
  ...(process.env.MAIL_SMTP_USER ? {
    auth: {
      user: process.env.MAIL_SMTP_USER,
      pass: process.env.MAIL_SMTP_PASSWORD,
    }
  } : {}),
});

// ---- Helper: open IMAP connection ----
function openImap(config) {
  return new Promise((resolve, reject) => {
    const imap = new Imap(config);
    imap.once('ready', () => resolve(imap));
    imap.once('error', reject);
    imap.connect();
  });
}

// ---- Helper: open mailbox ----
function openBox(imap, mailbox = 'INBOX', readOnly = true) {
  return new Promise((resolve, reject) => {
    imap.openBox(mailbox, readOnly, (err, box) => {
      if (err) reject(err);
      else resolve(box);
    });
  });
}

// ---- Helper: fetch message list ----
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

// ---- GET /api/inbox/folders ----
router.get('/folders', requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    const imap = await openImap(getImapConfig());
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- GET /api/inbox/messages?folder=INBOX&page=1&limit=30&search= ----
router.get('/messages', requireRole('super_admin', 'admin'), async (req, res) => {
  const { folder = 'INBOX', page = 1, limit = 30, search } = req.query;
  const imap = await openImap(getImapConfig()).catch(err => {
    res.status(500).json({ error: err.message }); return null;
  });
  if (!imap) return;

  try {
    let box;
    try {
      box = await openBox(imap, folder, true);
    } catch (boxErr) {
      imap.end();
      return res.json({ success: true, data: [], total: 0, page: parseInt(page), pages: 0 });
    }
    const total = box.messages.total;

    if (total === 0) {
      imap.end();
      return res.json({ success: true, data: [], total: 0, page: 1, pages: 0 });
    }

    // Calculate range — newest first
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

    // Parse headers
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

    // Client-side search filter
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
      folder
    });
  } catch (err) {
    imap.end();
    res.status(500).json({ error: err.message });
  }
});

// ---- GET /api/inbox/message/:uid?folder=INBOX ----
router.get('/message/:uid', requireRole('super_admin', 'admin'), async (req, res) => {
  const { uid }    = req.params;
  const { folder = 'INBOX' } = req.query;

  const imap = await openImap(getImapConfig()).catch(err => {
    res.status(500).json({ error: err.message }); return null;
  });
  if (!imap) return;

  try {
    await openBox(imap, folder, false);

    // Mark as read
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

// ---- DELETE /api/inbox/message/:uid — move to Trash ----
router.delete('/message/:uid', requireRole('super_admin', 'admin'), async (req, res) => {
  const { uid }    = req.params;
  const { folder = 'INBOX' } = req.query;

  const imap = await openImap(getImapConfig()).catch(err => {
    res.status(500).json({ error: err.message }); return null;
  });
  if (!imap) return;

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

// ---- POST /api/inbox/send — compose and send ----
router.post('/send', requireRole('super_admin', 'admin'), async (req, res) => {
  const { to, cc, bcc, subject, body, html, reply_to_message_id, reply_to_subject } = req.body;

  if (!to || !subject || (!body && !html)) {
    return res.status(400).json({ error: 'to, subject, and body are required.' });
  }

  try {
    const smtp = getSmtp();
    const info = await smtp.sendMail({
      from:       `"${req.user.name}" <${process.env.MAIL_FROM || 'admin@worktual.tech'}>`,
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
    res.status(500).json({ error: err.message });
  }
});

// ---- GET /api/inbox/count — unread count per folder ----
router.get('/count', requireRole('super_admin', 'admin'), async (req, res) => {
  const imap = await openImap(getImapConfig()).catch(err => {
    res.status(500).json({ error: err.message }); return null;
  });
  if (!imap) return;

  try {
    await openBox(imap, 'INBOX', true);
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

module.exports = router;
