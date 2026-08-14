const Imap = require('imap');
const { simpleParser } = require('mailparser');
require('dotenv').config();

const imap = new Imap({
  user:     process.env.MAIL_IMAP_USER,
  password: process.env.MAIL_IMAP_PASSWORD,
  host:     process.env.MAIL_IMAP_HOST || 'mail.worktual.tech',
  port:     parseInt(process.env.MAIL_IMAP_PORT, 10) || 993, tls: true,
  tlsOptions: { rejectUnauthorized: false }
});

imap.once('ready', () => {
  console.log('✅ Connected');
  imap.openBox('INBOX', true, (err, box) => {
    if (err) { console.error('openBox error:', err); imap.end(); return; }
    console.log('Total messages:', box.messages.total);

    if (box.messages.total === 0) { imap.end(); return; }

    const total = box.messages.total;
    const start = Math.max(1, total - 4);
    const range = `${start}:${total}`;
    console.log('Fetching range:', range);

    const fetch = imap.fetch(range, {
      bodies: ['HEADER.FIELDS (FROM TO SUBJECT DATE)'],
      struct: false
    });

    fetch.on('message', (msg, seqno) => {
      msg.on('body', (stream) => {
        let buf = '';
        stream.on('data', c => buf += c);
        stream.once('end', async () => {
          const p = await simpleParser(buf);
          console.log(`MSG ${seqno}: from=${p.from?.text} | subj=${p.subject} | date=${p.date}`);
        });
      });
      msg.once('attributes', a => console.log(`  uid=${a.uid} flags=${JSON.stringify(a.flags)}`));
    });
    fetch.once('error', err => console.error('fetch error:', err));
    fetch.once('end', () => { console.log('Done'); imap.end(); });
  });
});

imap.once('error', err => console.error('IMAP error:', err.message));
imap.connect();
