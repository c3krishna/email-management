import { useState, useEffect, useCallback, useRef } from 'react';
import {
  RefreshCw, Send, Trash2, Reply, Plus, Search,
  Inbox, Mail, ChevronRight, X, Paperclip
} from 'lucide-react';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

function ComposeModal({ onClose, onSent, replyTo = null, mailboxId, server }) {
  const [form, setForm]   = useState({
    to:      replyTo?.from || '',
    cc:      '',
    bcc:     '',
    subject: replyTo ? `Re: ${(replyTo.subject || '').replace(/^Re:\s*/i, '')}` : '',
    body:    replyTo
      ? `\n\n\n--- Original Message ---\nFrom: ${replyTo.from}\nDate: ${new Date(replyTo.date).toLocaleString('en-IN')}\n\n${replyTo.text || ''}`.slice(0, 2000)
      : '',
  });
  const [sending, setSending] = useState(false);
  const [error,   setError]   = useState('');
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const send = async () => {
    if (!form.to || !form.subject || !form.body) {
      return setError('To, Subject and Body are required.');
    }
    setSending(true); setError('');
    try {
      await api.post('/inbox/send', {
        ...form,
        mailbox_id: mailboxId,
        server,
        reply_to_message_id: replyTo?.message_id,
        reply_to_subject:    replyTo?.subject,
      });
      onSent?.();
      onClose();
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    } finally {
      setSending(false);
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'flex-end', justifyContent: 'flex-end', zIndex: 1000, padding: 20 }}>
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, width: 560, maxHeight: '85vh', display: 'flex', flexDirection: 'column', boxShadow: '0 8px 40px rgba(0,0,0,0.5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 20px', borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', borderRadius: '12px 12px 0 0' }}>
          <div style={{ fontWeight: 700, fontSize: 14 }}>{replyTo ? '↩ Reply' : '✉ New Message'}</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}><X size={16} /></button>
        </div>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
          {[
            { key: 'to',      label: 'To',      required: true },
            { key: 'cc',      label: 'Cc',      required: false },
            { key: 'bcc',     label: 'Bcc',     required: false },
            { key: 'subject', label: 'Subject', required: true },
          ].map(f => (
            <div key={f.key} style={{ display: 'flex', alignItems: 'center', borderBottom: '1px solid var(--border)', padding: '6px 0' }}>
              <label style={{ width: 60, fontSize: 12, color: 'var(--text-muted)', flexShrink: 0 }}>{f.label}</label>
              <input
                style={{ flex: 1, background: 'none', border: 'none', outline: 'none', color: 'var(--text-primary)', fontSize: 13, fontFamily: 'var(--font-sans)' }}
                value={form[f.key]}
                onChange={e => set(f.key, e.target.value)}
                placeholder={f.required ? `${f.label} *` : f.label}
              />
            </div>
          ))}
        </div>
        <textarea
          style={{
            flex: 1, padding: '16px 20px', background: 'none', border: 'none', outline: 'none',
            color: 'var(--text-primary)', fontSize: 13, fontFamily: 'var(--font-sans)',
            resize: 'none', lineHeight: 1.6, minHeight: 200
          }}
          placeholder="Write your message..."
          value={form.body}
          onChange={e => set('body', e.target.value)}
        />
        <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10 }}>
          {error && <span style={{ fontSize: 12, color: '#f87171', flex: 1 }}>❌ {error}</span>}
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
            <button className="btn btn-ghost btn-sm" onClick={onClose}>Cancel</button>
            <button className="btn btn-primary btn-sm" onClick={send} disabled={sending}>
              {sending ? <RefreshCw size={13} className="spin" /> : <Send size={13} />}
              {sending ? 'Sending...' : 'Send'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function MessageItem({ msg, selected, onClick }) {
  const isUnread = !msg.seen;
  return (
    <div
      onClick={onClick}
      style={{
        padding: '12px 16px', cursor: 'pointer',
        borderBottom: '1px solid var(--border)',
        background: selected ? 'rgba(37,99,235,0.1)' : isUnread ? 'rgba(37,99,235,0.04)' : 'transparent',
        borderLeft: selected ? '3px solid var(--accent-blue)' : '3px solid transparent',
        transition: 'background 0.1s',
      }}
      onMouseEnter={e => { if (!selected) e.currentTarget.style.background = 'var(--bg-hover)'; }}
      onMouseLeave={e => { if (!selected) e.currentTarget.style.background = isUnread ? 'rgba(37,99,235,0.04)' : 'transparent'; }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
        <span style={{ fontSize: 13, fontWeight: isUnread ? 700 : 500, color: isUnread ? 'var(--text-primary)' : 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '70%' }}>
          {msg.from?.replace(/<.*>/, '').trim() || '(unknown)'}
        </span>
        <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0, marginLeft: 8 }}>
          {msg.date ? new Date(msg.date).toLocaleString('en-IN', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : ''}
        </span>
      </div>
      <div style={{ fontSize: 12, fontWeight: isUnread ? 600 : 400, color: isUnread ? 'var(--text-primary)' : 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {msg.subject}
      </div>
      {isUnread && (
        <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-blue)', marginTop: 4 }} />
      )}
    </div>
  );
}

export default function InboxPage({ currentUser, server = 'app' }) {
  const [customers,    setCustomers]    = useState([]);
  const [mailboxes,    setMailboxes]    = useState([]);
  const [customerId,   setCustomerId]   = useState('');
  const [mailboxId,    setMailboxId]    = useState('');
  const [folders,      setFolders]      = useState([]);
  const [activeFolder, setActiveFolder] = useState('INBOX');
  const [messages,     setMessages]     = useState([]);
  const [selectedMsg,  setSelectedMsg]  = useState(null);
  const [msgDetail,    setMsgDetail]    = useState(null);
  const [loading,      setLoading]      = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [compose,      setCompose]      = useState(false);
  const [replyTo,      setReplyTo]      = useState(null);
  const [search,       setSearch]       = useState('');
  const [page,         setPage]         = useState(1);
  const [pagination,   setPagination]   = useState({ total: 0, pages: 0 });
  const [unread,       setUnread]       = useState(0);
  const [loadError,    setLoadError]    = useState(null);
  const searchRef = useRef(null);

  const mbParams = useCallback(() => ({
    mailbox_id: mailboxId || (server === 'campaign' ? 'admin-campaign' : 'admin-app'),
    server,
  }), [mailboxId, server]);

  // Load mailbox catalog when server / customer changes
  useEffect(() => {
    setLoadError(null);
    api.get('/inbox/mailboxes', {
      params: {
        server,
        ...(customerId ? { customer_id: customerId } : {}),
      },
    }).then(r => {
      const list = r.data.data || [];
      setMailboxes(list);
      setCustomers(r.data.customers || []);
      const preferAdmin = server === 'campaign' ? 'admin-campaign' : 'admin-app';
      const stillValid = list.find(m => String(m.id) === String(mailboxId));
      if (!stillValid) {
        const admin = list.find(m => m.id === preferAdmin);
        const first = admin || list[0];
        setMailboxId(first ? String(first.id) : preferAdmin);
      }
    }).catch(e => setLoadError(e.response?.data?.error || e.message));
  }, [server, customerId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Reset folder when mailbox changes
  useEffect(() => {
    if (!mailboxId) return;
    setActiveFolder('INBOX');
    setPage(1);
    setSelectedMsg(null);
    setMsgDetail(null);
    api.get('/inbox/folders', { params: mbParams() }).then(r => {
      setFolders(r.data.data || []);
    }).catch(() => setFolders([]));
    api.get('/inbox/count', { params: mbParams() })
      .then(r => setUnread(r.data.unread || 0))
      .catch(() => setUnread(0));
  }, [mailboxId, server]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadMessages = useCallback(async () => {
    if (!mailboxId) return;
    setLoading(true);
    setSelectedMsg(null);
    setMsgDetail(null);
    setLoadError(null);
    try {
      const r = await api.get('/inbox/messages', {
        params: { ...mbParams(), folder: activeFolder, page, limit: 30, search: search || undefined }
      });
      setMessages(r.data.data || []);
      setPagination({ total: r.data.total, pages: r.data.pages });
    } catch (e) {
      setLoadError(e.response?.data?.error || e.message);
      setMessages([]);
    } finally {
      setLoading(false);
    }
  }, [activeFolder, page, search, mbParams, mailboxId]);

  useEffect(() => { loadMessages(); }, [loadMessages]);

  const loadDetail = async (msg) => {
    setSelectedMsg(msg.uid);
    setDetailLoading(true);
    try {
      const r = await api.get(`/inbox/message/${msg.uid}`, { params: { ...mbParams(), folder: activeFolder } });
      setMsgDetail(r.data.data);
      setMessages(prev => prev.map(m => m.uid === msg.uid ? { ...m, seen: true } : m));
    } catch (e) {
      console.error(e);
    } finally {
      setDetailLoading(false);
    }
  };

  const deleteMsg = async (uid) => {
    if (!window.confirm('Delete this message?')) return;
    try {
      await api.delete(`/inbox/message/${uid}`, { params: { ...mbParams(), folder: activeFolder } });
      setMsgDetail(null);
      setSelectedMsg(null);
      loadMessages();
    } catch (e) {
      alert(e.response?.data?.error || 'Delete failed');
    }
  };

  const commonFolders = ['INBOX', 'Sent', 'Drafts', 'Trash', 'Junk', 'INBOX.Sent', 'INBOX.Trash'];
  const activeMb = mailboxes.find(m => String(m.id) === String(mailboxId));
  const filteredMailboxes = customerId
    ? mailboxes.filter(m => m.kind === 'admin' || String(m.customer_id) === String(customerId))
    : mailboxes;

  // Group by customer for sidebar list
  const grouped = {};
  for (const m of filteredMailboxes) {
    const key = m.customer_name || 'Infrastructure';
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(m);
  }

  return (
    <div style={{ display: 'flex', height: 'calc(100vh - 120px)', overflow: 'hidden', gap: 0 }}>

      {/* ---- Mailbox + Folder Sidebar ---- */}
      <div style={{
        width: 240, flexShrink: 0, borderRight: '1px solid var(--border)',
        background: 'var(--bg-secondary)', display: 'flex', flexDirection: 'column', overflow: 'hidden'
      }}>
        <div style={{ padding: '12px', borderBottom: '1px solid var(--border)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: 0.5 }}>Client</div>
          <select
            className="input"
            style={{ fontSize: 12, marginBottom: 8 }}
            value={customerId}
            onChange={e => setCustomerId(e.target.value)}
          >
            <option value="">All clients + admin</option>
            {customers.map(c => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Mailbox · {server === 'campaign' ? 'Campaign' : 'App Mail'}
          </div>
          <select
            className="input"
            style={{ fontSize: 12 }}
            value={mailboxId}
            onChange={e => setMailboxId(e.target.value)}
          >
            {Object.entries(grouped).map(([group, items]) => (
              <optgroup key={group} label={group}>
                {items.map(m => (
                  <option key={m.id} value={m.id}>
                    {m.display_name} ({m.email})
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        </div>

        <div style={{ padding: '12px 12px 8px' }}>
          <button
            className="btn btn-primary btn-sm"
            style={{ width: '100%', justifyContent: 'center' }}
            onClick={() => { setReplyTo(null); setCompose(true); }}
          >
            <Plus size={13} /> Compose
          </button>
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: '4px 0' }}>
          {[
            { name: 'INBOX',       label: 'Inbox',  badge: unread },
            { name: 'INBOX.Sent',  label: 'Sent' },
            { name: 'INBOX.Drafts',label: 'Drafts' },
            { name: 'INBOX.Trash', label: 'Trash' },
            { name: 'INBOX.Junk',  label: 'Junk' },
          ].map(f => (
            <button key={f.name}
              onClick={() => { setActiveFolder(f.name); setPage(1); }}
              style={{
                width: '100%', padding: '9px 16px', border: 'none', cursor: 'pointer',
                background: activeFolder === f.name ? 'rgba(37,99,235,0.15)' : 'transparent',
                color: activeFolder === f.name ? 'var(--accent-blue-light)' : 'var(--text-secondary)',
                fontSize: 13, fontWeight: 500, textAlign: 'left',
                display: 'flex', alignItems: 'center', gap: 10,
                borderLeft: activeFolder === f.name ? '3px solid var(--accent-blue)' : '3px solid transparent',
              }}
            >
              <Mail size={14} />
              <span style={{ flex: 1 }}>{f.label}</span>
              {f.badge > 0 && (
                <span style={{ background: 'var(--accent-blue)', color: '#fff', fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 10 }}>
                  {f.badge}
                </span>
              )}
            </button>
          ))}

          {folders.filter(f => !commonFolders.includes(f.fullName)).map(f => (
            <button key={f.fullName}
              onClick={() => { setActiveFolder(f.fullName); setPage(1); }}
              style={{
                width: '100%', padding: '8px 16px', border: 'none', cursor: 'pointer',
                background: activeFolder === f.fullName ? 'rgba(37,99,235,0.15)' : 'transparent',
                color: activeFolder === f.fullName ? 'var(--accent-blue-light)' : 'var(--text-muted)',
                fontSize: 12, textAlign: 'left',
                display: 'flex', alignItems: 'center', gap: 8,
              }}
            >
              <ChevronRight size={12} />
              {f.name}
            </button>
          ))}
        </div>

        <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', fontSize: 11, color: 'var(--text-muted)' }}>
          {activeMb ? `${activeMb.display_name}` : currentUser?.email}
          <div style={{ opacity: 0.7, marginTop: 2 }}>{activeMb?.host || ''}</div>
        </div>
      </div>

      {/* ---- Message List ---- */}
      <div style={{
        width: 300, flexShrink: 0, borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column', overflow: 'hidden'
      }}>
        <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)' }}>
          <div style={{ position: 'relative' }}>
            <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input
              ref={searchRef}
              className="input"
              style={{ paddingLeft: 30, fontSize: 12 }}
              placeholder="Search messages..."
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1); }}
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6, fontSize: 11, color: 'var(--text-muted)' }}>
            <span>{pagination.total} messages</span>
            <button onClick={loadMessages} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
              <RefreshCw size={12} className={loading ? 'spin' : ''} />
            </button>
          </div>
          {loadError && (
            <div style={{ marginTop: 6, fontSize: 11, color: '#f87171' }}>{loadError}</div>
          )}
        </div>

        <div style={{ flex: 1, overflow: 'auto' }}>
          {loading ? (
            <div className="loading-state"><RefreshCw size={18} className="spin" /></div>
          ) : messages.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)', fontSize: 13 }}>No messages</div>
          ) : (
            messages.map(msg => (
              <MessageItem
                key={msg.uid}
                msg={msg}
                selected={selectedMsg === msg.uid}
                onClick={() => loadDetail(msg)}
              />
            ))
          )}
        </div>

        {pagination.pages > 1 && (
          <div style={{ padding: '8px 12px', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <button className="btn btn-ghost btn-sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>←</button>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{page} / {pagination.pages}</span>
            <button className="btn btn-ghost btn-sm" disabled={page >= pagination.pages} onClick={() => setPage(p => p + 1)}>→</button>
          </div>
        )}
      </div>

      {/* ---- Message Detail ---- */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>
        {!msgDetail && !detailLoading ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', flexDirection: 'column', gap: 12 }}>
            <Inbox size={40} style={{ opacity: 0.3 }} />
            <div style={{ fontSize: 14 }}>Select a message to read</div>
            <div style={{ fontSize: 12, opacity: 0.7 }}>
              {activeMb ? `${activeMb.customer_name} · ${activeMb.email}` : 'Choose a client mailbox above'}
            </div>
          </div>
        ) : detailLoading ? (
          <div className="loading-state"><RefreshCw size={20} className="spin" /></div>
        ) : msgDetail && (
          <>
            <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                <div style={{ fontSize: 18, fontWeight: 700, flex: 1, marginRight: 16 }}>{msgDetail.subject}</div>
                <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
                  <button className="btn btn-ghost btn-sm"
                    onClick={() => { setReplyTo(msgDetail); setCompose(true); }}>
                    <Reply size={13} /> Reply
                  </button>
                  <button className="btn btn-danger btn-sm"
                    onClick={() => deleteMsg(msgDetail.uid)}>
                    <Trash2 size={13} /> Delete
                  </button>
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 12px', fontSize: 13 }}>
                <span style={{ color: 'var(--text-muted)' }}>From:</span>
                <span>{msgDetail.from}</span>
                <span style={{ color: 'var(--text-muted)' }}>To:</span>
                <span>{msgDetail.to}</span>
                {msgDetail.cc && <>
                  <span style={{ color: 'var(--text-muted)' }}>Cc:</span>
                  <span>{msgDetail.cc}</span>
                </>}
                <span style={{ color: 'var(--text-muted)' }}>Date:</span>
                <span>{msgDetail.date ? new Date(msgDetail.date).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', dateStyle: 'full', timeStyle: 'short' }) : '—'}</span>
              </div>
              {msgDetail.attachments?.length > 0 && (
                <div style={{ marginTop: 10, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {msgDetail.attachments.map((a, i) => (
                    <span key={i} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '3px 10px', fontSize: 12, color: 'var(--text-muted)' }}>
                      <Paperclip size={11} /> {a.filename} ({Math.round(a.size / 1024)}KB)
                    </span>
                  ))}
                </div>
              )}
            </div>
            <div style={{ flex: 1, overflow: 'auto', padding: '20px 24px' }}>
              {msgDetail.html ? (
                <iframe
                  srcDoc={msgDetail.html}
                  style={{ width: '100%', height: '100%', border: 'none', borderRadius: 8, background: '#fff' }}
                  sandbox="allow-same-origin"
                  title="email-body"
                />
              ) : (
                <pre style={{ fontFamily: 'var(--font-sans)', fontSize: 14, lineHeight: 1.7, color: 'var(--text-primary)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                  {msgDetail.text || '(empty message)'}
                </pre>
              )}
            </div>
          </>
        )}
      </div>

      {compose && (
        <ComposeModal
          replyTo={replyTo}
          mailboxId={mailboxId}
          server={server}
          onClose={() => { setCompose(false); setReplyTo(null); }}
          onSent={() => {
            loadMessages();
            api.get('/inbox/count', { params: mbParams() }).then(r => setUnread(r.data.unread || 0)).catch(() => {});
          }}
        />
      )}
    </div>
  );
}
