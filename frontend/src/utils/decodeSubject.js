/**
 * Decode RFC 2047 MIME encoded-words in Subject headers for UI display.
 * e.g. =?utf-8?q?=E2=84=B9_ALERT?= → ℹ️ ALERT
 */
export function decodeEmailSubject(raw) {
  if (raw == null || raw === '') return raw;
  let s = String(raw);
  if (!/=\?[^?]+\?[BbQq]\?/i.test(s)) return s;

  try {
    s = s.replace(/\?=\s+=\?/g, '?==?');
    s = s.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_m, _cs, enc, text) => {
      try {
        if (String(enc).toUpperCase() === 'B') {
          const bin = atob(String(text).replace(/\s+/g, ''));
          const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
          return new TextDecoder('utf-8').decode(bytes);
        }
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
        return new TextDecoder('utf-8').decode(new Uint8Array(bytes));
      } catch {
        return text;
      }
    });
    // Truncated encoding without closing ?= (Q payloads contain ?=HH — don't use /\?=/)
    const hasOpenEncoded = /=\?[^?]+\?[BbQq]\?/i.test(s);
    const hasCompleteEncoded = /=\?[^?]+\?[BbQq]\?[^?]*\?=/i.test(s);
    if (hasOpenEncoded && !hasCompleteEncoded) {
      s = s.replace(/=\?([^?]+)\?([BbQq])\?([\s\S]*)/i, (_m, _c, enc, text) => {
        try {
          if (String(enc).toUpperCase() === 'B') {
            const bin = atob(String(text).replace(/\s+/g, ''));
            const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
            return new TextDecoder('utf-8').decode(bytes);
          }
          const bytes = [];
          const qp = String(text).replace(/_/g, ' ');
          for (let i = 0; i < qp.length; i++) {
            if (qp[i] === '=' && /^[0-9A-Fa-f]{2}$/.test(qp.slice(i + 1, i + 3))) {
              bytes.push(parseInt(qp.slice(i + 1, i + 3), 16));
              i += 2;
            } else if (qp[i] === '=' && i >= qp.length - 2) {
              break;
            } else {
              bytes.push(qp.charCodeAt(i) & 0xff);
            }
          }
          return new TextDecoder('utf-8').decode(new Uint8Array(bytes));
        } catch {
          return text;
        }
      });
    }
    return s.replace(/\s+/g, ' ').trim() || String(raw);
  } catch {
    return String(raw);
  }
}
