/**
 * Decode RFC 2047 encoded-words in email Subject headers.
 * Handles =?charset?Q?...?= and =?charset?B?...?= (including multi-word).
 */
function decodeRfc2047Subject(raw) {
  if (raw == null) return null;
  let s = String(raw).trim();
  if (!s) return null;

  // Already plain text (no RFC2047 encoded-word opener)
  if (!/=\?[^?]+\?[BbQq]\?/i.test(s)) {
    return s.slice(0, 500);
  }

  try {
    // RFC 2047: linear whitespace between adjacent encoded-words is ignored
    s = s.replace(/\?=\s+=\?/g, '?==?');

    s = s.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_m, _charset, enc, text) => {
      try {
        if (String(enc).toUpperCase() === 'B') {
          return Buffer.from(text.replace(/\s+/g, ''), 'base64').toString('utf8');
        }
        // Q-encoding: _ = space; =HH = byte
        const bytes = [];
        const qp = String(text).replace(/_/g, ' ');
        for (let i = 0; i < qp.length; i++) {
          if (qp[i] === '=' && /^[0-9A-Fa-f]{2}$/.test(qp.slice(i + 1, i + 3))) {
            bytes.push(parseInt(qp.slice(i + 1, i + 3), 16));
            i += 2;
          } else {
            bytes.push(qp.charCodeAt(i) & 0xff);
          }
        }
        return Buffer.from(bytes).toString('utf8');
      } catch {
        return text;
      }
    });

    // Best-effort for truncated Q/B encoding missing trailing ?=
    // Note: do NOT use /\?=/ alone — Q payloads start with ?=HH and false-positive.
    const hasOpenEncoded = /=\?[^?]+\?[BbQq]\?/i.test(s);
    const hasCompleteEncoded = /=\?[^?]+\?[BbQq]\?[^?]*\?=/i.test(s);
    if (hasOpenEncoded && !hasCompleteEncoded) {
      s = s.replace(/=\?([^?]+)\?([BbQq])\?([\s\S]*)/i, (_m, _c, enc, text) => {
        try {
          if (String(enc).toUpperCase() === 'B') {
            return Buffer.from(String(text).replace(/\s+/g, ''), 'base64').toString('utf8');
          }
          const bytes = [];
          const qp = String(text).replace(/_/g, ' ');
          for (let i = 0; i < qp.length; i++) {
            if (qp[i] === '=' && /^[0-9A-Fa-f]{2}$/.test(qp.slice(i + 1, i + 3))) {
              bytes.push(parseInt(qp.slice(i + 1, i + 3), 16));
              i += 2;
            } else if (qp[i] === '=' && i >= qp.length - 2) {
              break; // truncated hex
            } else {
              bytes.push(qp.charCodeAt(i) & 0xff);
            }
          }
          return Buffer.from(bytes).toString('utf8');
        } catch {
          return text;
        }
      });
    }

    // Collapse leftover MIME noise
    s = s.replace(/\s+/g, ' ').trim();
    return (s || String(raw).trim()).slice(0, 500);
  } catch {
    return String(raw).trim().slice(0, 500);
  }
}

function mapRowsDecodeSubject(rows) {
  if (!Array.isArray(rows)) return rows;
  return rows.map((r) => {
    if (!r || r.subject == null) return r;
    const decoded = decodeRfc2047Subject(r.subject);
    return decoded === r.subject ? r : { ...r, subject: decoded };
  });
}

module.exports = { decodeRfc2047Subject, decodeSubject: decodeRfc2047Subject, mapRowsDecodeSubject };
