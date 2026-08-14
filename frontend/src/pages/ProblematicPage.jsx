import { useState, useEffect, useCallback, useRef } from 'react';
import { AlertTriangle, Send, RefreshCw, Filter, Download } from 'lucide-react';
import { mailsApi, alertsApi } from '../utils/api';
import StatusBadge from '../components/StatusBadge';

const CATEGORIES = [
  { id: 'all', label: 'All Issues', color: '#6b7280' },
  { id: 'failed', label: 'Failed', color: '#dc2626' },
  { id: 'bounced', label: 'Bounced', color: '#ea580c' },
  { id: 'deferred', label: 'Deferred', color: '#d97706' },
  { id: 'timedout', label: 'Timed Out', color: '#7c3aed' },
  { id: 'invalid', label: 'Invalid Address', color: '#b91c1c' },
  { id: 'spam', label: 'Spam Blocked', color: '#be185d' },
  { id: 'unformatted', label: 'Malformed/Unformatted', color: '#0891b2' },
];

export default function ProblematicPage({ server, range, selectedDate }) {
  const [category, setCategory] = useState('all');
  const [mails, setMails] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(new Set());
  const [notifyModal, setNotifyModal] = useState(false);
  const [notifyForm, setNotifyForm] = useState({ team: 'devops', subject: '', message: '' });
  const [notifySending, setNotifySending] = useState(false);
  const [notifyResult, setNotifyResult] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = { range, server, ...(range === 'today' ? { date: selectedDate } : {}) };
      if (category !== 'all') params.category = category;
      const r = await mailsApi.getProblematic(params);
      setMails(r.data);
      setSelected(new Set());
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [category, range, selectedDate, server]);

  useEffect(() => { load(); }, [load]);

  // Reset when server switches
  const prevServer = useRef(server);
  useEffect(() => {
    if (prevServer.current !== server) {
      prevServer.current = server;
      setCategory('all');
      setMails([]);
      setSelected(new Set());
    }
  }, [server]);


  const toggleSelect = (id) => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    if (selected.size === mails.length) setSelected(new Set());
    else setSelected(new Set(mails.map(m => m.id)));
  };

  const sendNotification = async () => {
    setNotifySending(true);
    setNotifyResult(null);
    try {
      const mail_ids = Array.from(selected);
      const r = await alertsApi.sendNotify({
        team: notifyForm.team,
        subject: notifyForm.subject || `[Email Issue] ${category} mails require attention`,
        issue_type: category.toUpperCase(),
        custom_message: notifyForm.message,
        mail_ids
      });
      setNotifyResult({ success: true, message: r.message });
    } catch (e) {
      setNotifyResult({ success: false, message: e.message });
    } finally {
      setNotifySending(false);
    }
  };

  const exportCSV = () => {
    const rows = mails.filter(m => selected.size === 0 || selected.has(m.id));
    const headers = ['ID', 'Date', 'Time', 'From', 'To', 'Campaign', 'Status', 'Delivery', 'DSN', 'Reason'];
    const csv = [headers, ...rows.map(m => [
      m.id, m.log_date, m.log_time, m.mail_from, m.mail_to, m.campaign_id,
      m.status, m.delivery_status, m.dsn, (m.reason || '').replace(/,/g, ';')
    ])].map(r => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `problematic-${category}-${selectedDate}.csv`;
    a.click();
  };

  return (
    <div>
      <div className="flex-between mb-16">
        <div>
          <div className="section-title">Problematic Mails</div>
          <div className="section-sub">Identify, investigate, and notify teams about delivery issues</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-ghost btn-sm" onClick={exportCSV}><Download size={13} /> Export</button>
          <button className="btn btn-ghost btn-sm" onClick={load}><RefreshCw size={13} className={loading ? 'spin' : ''} /> Refresh</button>
          {selected.size > 0 && (
            <button className="btn btn-primary btn-sm" onClick={() => { setNotifyModal(true); setNotifyResult(null); }}>
              <Send size={13} /> Notify Team ({selected.size} selected)
            </button>
          )}
        </div>
      </div>

      {/* Category tabs */}
      <div className="tab-bar mb-24" style={{ marginBottom: 0 }}>
        {CATEGORIES.map(c => (
          <button key={c.id} className={`tab-item ${category === c.id ? 'active' : ''}`} onClick={() => setCategory(c.id)}>
            <span style={{ color: category === c.id ? c.color : undefined }}>{c.label}</span>
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="card" style={{ marginTop: 16 }}>
        {loading ? (
          <div className="loading-state"><RefreshCw size={20} className="spin" /></div>
        ) : (
          <>
            <div className="flex-between" style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                {mails.length} records{selected.size > 0 ? ` · ${selected.size} selected` : ''}
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-ghost btn-sm" onClick={selectAll}>
                  {selected.size === mails.length ? 'Deselect All' : 'Select All'}
                </button>
              </div>
            </div>

            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 40 }}><input type="checkbox" checked={selected.size === mails.length && mails.length > 0} onChange={selectAll} /></th>
                    <th>Date / Time</th>
                    <th>From</th>
                    <th>To</th>
                    <th>Campaign</th>
                    <th>Status</th>
                    <th>DSN</th>
                    <th>Issue / Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {mails.map(m => (
                    <tr key={m.id} style={{ background: selected.has(m.id) ? 'rgba(37,99,235,0.05)' : undefined }}>
                      <td><input type="checkbox" checked={selected.has(m.id)} onChange={() => toggleSelect(m.id)} /></td>
                      <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
                        {m.log_date}<br /><span style={{ color: 'var(--text-muted)' }}>{String(m.log_time || '').slice(0, 8)}</span>
                      </td>
                      <td style={{ maxWidth: 160 }}><div className="truncate" title={m.mail_from}>{m.mail_from || '—'}</div></td>
                      <td style={{ maxWidth: 160 }}><div className="truncate" title={m.mail_to}>{m.mail_to || '—'}</div></td>
                      <td><span className="mono" style={{ fontSize: 11 }}>{m.campaign_id || '—'}</span></td>
                      <td>
                        <StatusBadge status={m.status || m.delivery_status} />
                      </td>
                      <td>
                        <span className="mono" style={{ fontSize: 11, color: getDsnColor(m.dsn) }}>{m.dsn || '—'}</span>
                      </td>
                      <td>
                        <div style={{ fontSize: 11, color: '#fbbf24', maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={m.reason}>
                          {highlightReason(m.reason)}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {mails.length === 0 && (
                    <tr><td colSpan={8} className="text-center" style={{ padding: 48, color: 'var(--text-muted)' }}>
                      ✅ No {category === 'all' ? 'problematic' : category} mails found
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      {/* Notify Modal */}
      {notifyModal && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, padding: 28, width: 560, maxWidth: '90vw' }}>
            <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>Send Team Notification</div>
            <div style={{ color: 'var(--text-muted)', fontSize: 13, marginBottom: 20 }}>
              {selected.size} emails selected · Category: <strong>{category}</strong>
            </div>

            <div style={{ marginBottom: 14 }}>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>NOTIFY TEAM</label>
              <select className="input" value={notifyForm.team} onChange={e => setNotifyForm(f => ({ ...f, team: e.target.value }))}>
                <option value="devops">DevOps Team — Spam, IP blocking, Deferred, Timeouts</option>
                <option value="backend">Backend/App Team — Failed delivery, Invalid address, Malformed mails</option>
                <option value="email">Email/Campaign Team — Bounces, High bounce rate</option>
              </select>
            </div>
            <div style={{ marginBottom: 14 }}>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>SUBJECT</label>
              <input className="input" placeholder={`[Email Alert] ${category} mails require attention`}
                value={notifyForm.subject} onChange={e => setNotifyForm(f => ({ ...f, subject: e.target.value }))} />
            </div>
            <div style={{ marginBottom: 20 }}>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>ADDITIONAL MESSAGE (optional)</label>
              <textarea className="input" rows={4} placeholder="Add any additional context for the team..."
                value={notifyForm.message} onChange={e => setNotifyForm(f => ({ ...f, message: e.target.value }))}
                style={{ resize: 'vertical' }} />
            </div>

            {notifyResult && (
              <div className={`alert-box ${notifyResult.success ? 'alert-info' : 'alert-critical'}`} style={{ marginBottom: 16 }}>
                {notifyResult.success ? '✅ ' : '❌ '}{notifyResult.message}
              </div>
            )}

            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="btn btn-ghost" onClick={() => setNotifyModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={sendNotification} disabled={notifySending}>
                {notifySending ? <><RefreshCw size={14} className="spin" /> Sending...</> : <><Send size={14} /> Send Notification</>}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function getDsnColor(dsn) {
  if (!dsn) return 'var(--text-muted)';
  if (dsn.startsWith('2')) return '#4ade80';
  if (dsn.startsWith('4')) return '#fbbf24';
  if (dsn.startsWith('5')) return '#f87171';
  return 'var(--text-muted)';
}

function highlightReason(reason) {
  if (!reason) return '—';
  const keywords = ['spam', 'blocked', 'blacklist', 'reject', 'timeout', 'user unknown', 'does not exist', 'dnsbl', 'spamhaus', 'invalid', 'malformed'];
  const lower = reason.toLowerCase();
  const found = keywords.find(k => lower.includes(k));
  return reason.slice(0, 140);
}
