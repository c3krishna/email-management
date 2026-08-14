import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Search, Trash2, CheckCircle, Eye, Download, ShieldCheck, Undo2 } from 'lucide-react';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const REASONS = {
  spam:     { color:'#f97316', bg:'rgba(249,115,22,0.15)',  label:'Spam'      },
  phishing: { color:'#f43f5e', bg:'rgba(244,63,94,0.15)',  label:'Phishing'  },
  malware:  { color:'#a855f7', bg:'rgba(168,85,247,0.15)', label:'Malware'   },
  policy:   { color:'#0891b2', bg:'rgba(8,145,178,0.15)',  label:'Policy'    },
  other:    { color:'#6b7280', bg:'rgba(107,114,128,0.15)',label:'Other'     },
};

export default function QuarantinePage({ server }) {
  const [items,    setItems]    = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [search,   setSearch]   = useState('');
  const [filter,   setFilter]   = useState('quarantined');
  const [selected, setSelected] = useState([]);
  const [preview,  setPreview]  = useState(null);
  const [stats,    setStats]    = useState(null);
  const [busy,     setBusy]     = useState(false);
  const [msg,      setMsg]      = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.get('/quarantine', {
        params: { server, limit: 200, status: filter || 'quarantined', search: search || undefined },
      });
      setItems(r.data.data || []);
      setStats(r.data.stats || null);
      setSelected([]);
    } catch (e) {
      console.error(e);
      setMsg({ ok: false, text: e.response?.data?.error || e.message });
    } finally {
      setLoading(false);
    }
  }, [server, filter, search]);

  useEffect(() => { load(); }, [load]);

  const getReasonKey = (item) => {
    if (item.classification === 'Phishing') return 'phishing';
    if (item.classification === 'Malware')  return 'malware';
    if (item.classification === 'Spam' || parseFloat(item.spam_score||0) > 8) return 'spam';
    if (item.classification === 'Policy' || item.status === 'blocked' || item.status === 'rejected') return 'policy';
    return 'other';
  };

  const toggleSelect = (id) =>
    setSelected(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  const selectAll = () =>
    setSelected(selected.length === items.length ? [] : items.map(i => i.id));

  const runAction = async (action) => {
    if (!selected.length) return;
    const labels = { release: 'release', delete: 'delete', allow: 'allow & whitelist' };
    if (!window.confirm(`${labels[action]} ${selected.length} item(s)?`)) return;
    setBusy(true); setMsg(null);
    try {
      const r = await api.post(`/quarantine/${action}`, { ids: selected, server });
      setMsg({ ok: true, text: r.data.message || 'Done' });
      await load();
    } catch (e) {
      setMsg({ ok: false, text: e.response?.data?.error || e.message });
    } finally {
      setBusy(false);
    }
  };

  const syncFromLogs = async () => {
    setBusy(true); setMsg(null);
    try {
      const r = await api.post('/quarantine/sync', { server });
      setMsg({ ok: true, text: `Synced ${r.data.imported} item(s) from realtime logs` });
      await load();
    } catch (e) {
      setMsg({ ok: false, text: e.response?.data?.error || e.message });
    } finally {
      setBusy(false);
    }
  };

  const exportCSV = () => {
    const headers = ['DateTime','From','To','Subject','Classification','SpamScore','Status','Reason'];
    const rows = items.map(l => [
      l.created_at, l.mail_from, l.mail_to,
      (l.subject||'').replace(/,/g,';'),
      l.classification, l.spam_score, l.status,
      (l.reason||'').replace(/,/g,';').slice(0,100)
    ]);
    const csv = [headers, ...rows].map(r => r.join(',')).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = `quarantine-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  };

  const serverLabel = server === 'campaign' ? 'Campaign' : 'App Mail';

  return (
    <div>
      <div className="flex-between mb-16">
        <div>
          <div className="section-title">Quarantine</div>
          <div className="section-sub">{serverLabel} · Hold, release, delete or allow high-risk mail</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-ghost btn-sm" onClick={syncFromLogs} disabled={busy}>
            <RefreshCw size={13}/> Sync from logs
          </button>
          <button className="btn btn-ghost btn-sm" onClick={load}><RefreshCw size={13}/> Refresh</button>
          <button className="btn btn-ghost btn-sm" onClick={exportCSV}><Download size={13}/> Export</button>
        </div>
      </div>

      {msg && (
        <div style={{
          marginBottom: 12, padding: '10px 14px', borderRadius: 8, fontSize: 13,
          background: msg.ok ? 'rgba(22,163,74,0.12)' : 'rgba(220,38,38,0.12)',
          color: msg.ok ? '#4ade80' : '#f87171',
        }}>{msg.text}</div>
      )}

      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 12, marginBottom: 20 }}>
          {[
            { label: 'Held', value: stats.total, color: '#2563eb' },
            { label: 'Spam', value: stats.spam, color: '#f97316' },
            { label: 'Phishing', value: stats.phishing, color: '#f43f5e' },
            { label: 'Malware', value: stats.malware, color: '#a855f7' },
            { label: 'Released (7d)', value: stats.released, color: '#16a34a' },
          ].map(s => (
            <div key={s.label} className="card" style={{ padding: '14px 16px', borderTop: `3px solid ${s.color}` }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>{s.label}</div>
              <div style={{ fontSize: 24, fontWeight: 800, color: s.color, fontFamily: 'var(--font-mono)' }}>{s.value}</div>
            </div>
          ))}
        </div>
      )}

      <div className="card mb-16" style={{ padding: '12px 16px' }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}/>
            <input className="input" style={{ paddingLeft: 30, fontSize: 12 }}
              placeholder="Search sender, recipient, subject..."
              value={search} onChange={e => setSearch(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && load()}/>
          </div>
          <select className="input" style={{ width: 160, fontSize: 12 }}
            value={filter} onChange={e => setFilter(e.target.value)}>
            <option value="quarantined">Quarantined</option>
            <option value="released">Released</option>
            <option value="allowed">Allowed</option>
            <option value="deleted">Deleted</option>
            <option value="all">All</option>
          </select>
          <button className="btn btn-ghost btn-sm" onClick={() => { setSearch(''); setFilter('quarantined'); }}>Clear</button>
        </div>
      </div>

      {selected.length > 0 && (
        <div style={{
          background: 'rgba(37,99,235,0.1)', border: '1px solid rgba(37,99,235,0.3)',
          borderRadius: 8, padding: '10px 16px', marginBottom: 12,
          display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap'
        }}>
          <span style={{ fontSize: 13, fontWeight: 600 }}>{selected.length} selected</span>
          <button className="btn btn-primary btn-sm" disabled={busy} onClick={() => runAction('release')}>
            <Undo2 size={13}/> Release
          </button>
          <button className="btn btn-ghost btn-sm" disabled={busy} onClick={() => runAction('allow')}>
            <ShieldCheck size={13}/> Allow sender
          </button>
          <button className="btn btn-ghost btn-sm" disabled={busy} onClick={() => runAction('delete')}
            style={{ color: '#f87171' }}>
            <Trash2 size={13}/> Delete
          </button>
          <button className="btn btn-ghost btn-sm" onClick={() => setSelected([])}>Deselect</button>
        </div>
      )}

      <div className="card">
        {loading ? (
          <div className="loading-state"><RefreshCw size={18} className="spin"/></div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 36 }}>
                    <input type="checkbox" checked={selected.length === items.length && items.length > 0}
                      onChange={selectAll}/>
                  </th>
                  <th>Date / Time</th>
                  <th>Reason</th>
                  <th>From</th>
                  <th>To</th>
                  <th>Subject</th>
                  <th>Score</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => {
                  const rk = getReasonKey(item);
                  const rs = REASONS[rk];
                  const isSel = selected.includes(item.id);
                  return (
                    <tr key={item.id} style={{ background: isSel ? 'rgba(37,99,235,0.06)' : undefined }}>
                      <td>
                        <input type="checkbox" checked={isSel} onChange={() => toggleSelect(item.id)}
                          disabled={item.status !== 'quarantined'}/>
                      </td>
                      <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                        {String(item.created_at || '').slice(0, 16)}
                      </td>
                      <td>
                        <span style={{
                          fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 20,
                          background: rs.bg, color: rs.color
                        }}>{rs.label}</span>
                      </td>
                      <td style={{ maxWidth: 160 }}>
                        <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 12 }}
                          title={item.mail_from}>{item.mail_from || '—'}</div>
                      </td>
                      <td style={{ maxWidth: 160 }}>
                        <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 12 }}
                          title={item.mail_to}>{item.mail_to || '—'}</div>
                      </td>
                      <td style={{ maxWidth: 200 }}>
                        <div style={{
                          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 12,
                          color: item.subject ? 'var(--text-primary)' : 'var(--text-muted)'
                        }} title={item.subject}>{item.subject || '—'}</div>
                      </td>
                      <td>
                        {item.spam_score != null ? (
                          <span className="mono" style={{
                            fontSize: 11, fontWeight: 700,
                            color: parseFloat(item.spam_score) > 10 ? '#f87171' : parseFloat(item.spam_score) > 5 ? '#fbbf24' : '#4ade80'
                          }}>
                            {Number(item.spam_score).toFixed(1)}
                          </span>
                        ) : '—'}
                      </td>
                      <td>
                        <span style={{
                          fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 20,
                          background: item.status === 'quarantined' ? 'rgba(220,38,38,0.15)' : 'rgba(22,163,74,0.15)',
                          color: item.status === 'quarantined' ? '#f87171' : '#4ade80'
                        }}>{item.status}</span>
                      </td>
                      <td>
                        <button className="btn btn-ghost btn-sm" style={{ padding: '2px 8px', fontSize: 11 }}
                          onClick={() => setPreview(preview?.id === item.id ? null : item)} title="View details">
                          <Eye size={11}/>
                        </button>
                      </td>
                    </tr>
                  );
                })}
                {items.length === 0 && !loading && (
                  <tr><td colSpan={9} style={{ textAlign: 'center', padding: 48, color: '#4ade80' }}>
                    <CheckCircle size={16} style={{ verticalAlign: 'middle', marginRight: 6 }}/>
                    No quarantine items for this filter
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {preview && (
          <div style={{ margin: '0 16px 16px', background: 'var(--bg-primary)', borderRadius: 8, padding: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
              <div style={{ fontSize: 13, fontWeight: 700 }}>Email Details</div>
              <button onClick={() => setPreview(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 18 }}>×</button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: '8px 16px', fontSize: 12, marginBottom: 12 }}>
              <div><span style={{ color: 'var(--text-muted)' }}>Queue ID:</span><br/><span className="mono">{preview.queue_id || '—'}</span></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Direction:</span><br/><span>{preview.direction || '—'}</span></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Spam Score:</span><br/><span style={{ fontWeight: 700, color: '#fbbf24' }}>{preview.spam_score || '—'}</span></div>
              <div><span style={{ color: 'var(--text-muted)' }}>DKIM:</span><br/><span style={{ color: preview.dkim_result === 'pass' ? '#4ade80' : '#f87171' }}>{preview.dkim_result || '—'}</span></div>
              <div><span style={{ color: 'var(--text-muted)' }}>SPF:</span><br/><span style={{ color: preview.spf_result === 'pass' ? '#4ade80' : '#f87171' }}>{preview.spf_result || '—'}</span></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Relay IP:</span><br/><span className="mono">{preview.relay_ip || '—'}</span></div>
            </div>
            {preview.action_by && (
              <div style={{ fontSize: 12, marginBottom: 8, color: 'var(--text-muted)' }}>
                Action by {preview.action_by} at {preview.action_at} {preview.action_note ? `· ${preview.action_note}` : ''}
              </div>
            )}
            {preview.reason && (
              <div>
                <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>Rejection Reason:</span>
                <div style={{
                  marginTop: 4, padding: '8px 12px', background: 'rgba(220,38,38,0.08)',
                  borderRadius: 6, fontSize: 12, color: '#fbbf24', fontFamily: 'var(--font-mono)'
                }}>{preview.reason}</div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
