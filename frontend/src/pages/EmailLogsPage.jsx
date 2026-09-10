import { useState, useEffect, useCallback, useRef } from 'react';
import { RefreshCw, Search, Filter, Download, Wifi, WifiOff } from 'lucide-react';
import axios from 'axios';
import { decodeEmailSubject } from '../utils/decodeSubject';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const STATUS_STYLE = {
  sent:       { bg:'rgba(22,163,74,0.15)',   color:'#4ade80'  },
  delivered:  { bg:'rgba(22,163,74,0.15)',   color:'#4ade80'  },
  failed:     { bg:'rgba(220,38,38,0.15)',   color:'#f87171'  },
  bounced:    { bg:'rgba(234,88,12,0.15)',   color:'#fb923c'  },
  deferred:   { bg:'rgba(217,119,6,0.15)',   color:'#fbbf24'  },
  rejected:   { bg:'rgba(190,24,93,0.15)',   color:'#f472b6'  },
  blocked:    { bg:'rgba(190,24,93,0.15)',   color:'#f472b6'  },
  ok:         { bg:'rgba(22,163,74,0.15)',   color:'#4ade80'  },
  unknown:    { bg:'rgba(107,114,128,0.15)', color:'#9ca3af'  },
};

const EVENT_STYLE = {
  delivery:            { color:'#4ade80',  label:'Delivery'    },
  queued:              { color:'#60a5fa',  label:'Queued'      },
  amavis:              { color:'#a78bfa',  label:'Amavis'      },
  reject:              { color:'#f87171',  label:'Reject'      },
  connection:          { color:'#67e8f9',  label:'Connection'  },
  delivered_to_mailbox:{ color:'#34d399',  label:'Mailbox'     },
};

const THREAT_STYLE = {
  Spam:        { color:'#f97316', bg:'rgba(249,115,22,0.15)'  },
  Phishing:    { color:'#f43f5e', bg:'rgba(244,63,94,0.15)'   },
  Malware:     { color:'#a855f7', bg:'rgba(168,85,247,0.15)'  },
  Blacklisted: { color:'#ef4444', bg:'rgba(239,68,68,0.15)'   },
  CLEAN:       { color:'#22c55e', bg:'rgba(34,197,94,0.15)'   },
};

function Badge({ text, style }) {
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px',
      borderRadius: 20, fontSize: 11, fontWeight: 600,
      background: style?.bg || 'rgba(107,114,128,0.15)',
      color: style?.color || '#9ca3af',
      whiteSpace: 'nowrap',
    }}>{text}</span>
  );
}

export default function EmailLogsPage({ server }) {
  const [logs,     setLogs]     = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [search,   setSearch]   = useState('');
  const [filters,  setFilters]  = useState({ event_type:'', direction:'', status:'' });
  const [expanded, setExpanded] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);
  const intervalRef = useRef(null);

  const load = useCallback(async () => {
    try {
      const params = {
        server, limit: 200,
        ...(filters.event_type && { event_type: filters.event_type }),
        ...(filters.direction  && { direction:  filters.direction  }),
        ...(filters.status     && { status:     filters.status     }),
      };
      const r = await api.get('/agent/realtime-logs', { params });
      setLogs(r.data.data || []);
      setLastUpdate(new Date());
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [server, filters]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(load, 5000); // refresh every 5s
    } else {
      clearInterval(intervalRef.current);
    }
    return () => clearInterval(intervalRef.current);
  }, [autoRefresh, load]);

  const filtered = search
    ? logs.filter(l =>
        (l.mail_from || '').includes(search) ||
        (l.mail_to   || '').includes(search) ||
        (decodeEmailSubject(l.subject) || '').toLowerCase().includes(search.toLowerCase()) ||
        (l.queue_id  || '').includes(search) ||
        (l.reason    || '').toLowerCase().includes(search.toLowerCase())
      )
    : logs;

  const exportCSV = () => {
    const headers = ['DateTime','EventType','Direction','From','To','Subject','Status','DSN','SpamScore','Reason','QueueID'];
    const rows = filtered.map(l => [
      l.log_datetime, l.event_type, l.direction,
      l.mail_from, l.mail_to,
      (decodeEmailSubject(l.subject) || '').replace(/,/g,';'),
      l.status, l.dsn, l.spam_score,
      (l.reason  || '').replace(/,/g,';').replace(/\n/g,' ').slice(0,200),
      l.queue_id
    ]);
    const csv  = [headers,...rows].map(r => r.join(',')).join('\n');
    const blob = new Blob([csv],{type:'text/csv'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `email-logs-${server}-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  };

  const serverLabel = server === 'campaign' ? '🟠 Campaign' : '🔵 App Mail';

  return (
    <div>
      {/* Header */}
      <div className="flex-between mb-16">
        <div>
          <div className="section-title">Email Logs</div>
          <div className="section-sub">
            {serverLabel} · Real-time parsed log stream · {filtered.length} entries
            {lastUpdate && (
              <span style={{ marginLeft: 10, fontSize: 11, color: 'var(--text-muted)' }}>
                · Updated: {lastUpdate.toLocaleTimeString('en-IN')}
              </span>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button
            className={`btn btn-sm ${autoRefresh ? 'btn-success' : 'btn-ghost'}`}
            onClick={() => setAutoRefresh(a => !a)}
            title={autoRefresh ? 'Auto-refresh ON (every 5s)' : 'Auto-refresh OFF'}
          >
            {autoRefresh ? <Wifi size={13} /> : <WifiOff size={13} />}
            {autoRefresh ? 'Live' : 'Paused'}
          </button>
          <button className="btn btn-ghost btn-sm" onClick={load}>
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
          </button>
          <button className="btn btn-ghost btn-sm" onClick={exportCSV}>
            <Download size={13} /> CSV
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="card mb-16" style={{ padding: '12px 16px' }}>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1, minWidth: 200 }}>
            <Search size={13} style={{ position:'absolute', left:10, top:'50%', transform:'translateY(-50%)', color:'var(--text-muted)' }} />
            <input className="input" style={{ paddingLeft: 30, fontSize: 12 }}
              placeholder="Search email, subject, queue ID, reason..."
              value={search} onChange={e => setSearch(e.target.value)} />
          </div>

          {[
            { key:'event_type', label:'Event', opts:['delivery','queued','amavis','reject','connection','delivered_to_mailbox'] },
            { key:'direction',  label:'Dir',   opts:['inbound','outbound'] },
            { key:'status',     label:'Status',opts:['sent','delivered','failed','bounced','deferred','rejected','blocked'] },
          ].map(f => (
            <select key={f.key} className="input" style={{ width:130, fontSize:12 }}
              value={filters[f.key]}
              onChange={e => setFilters(p => ({ ...p, [f.key]: e.target.value }))}>
              <option value="">All {f.label}</option>
              {f.opts.map(o => <option key={o} value={o}>{o}</option>)}
            </select>
          ))}

          <button className="btn btn-ghost btn-sm" onClick={() => { setFilters({event_type:'',direction:'',status:''}); setSearch(''); }}>
            Clear
          </button>
        </div>
      </div>

      {/* Log table */}
      <div className="card">
        {loading ? (
          <div className="loading-state"><RefreshCw size={18} className="spin" /></div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 130 }}>Date / Time</th>
                  <th style={{ width: 90  }}>Event</th>
                  <th style={{ width: 80  }}>Direction</th>
                  <th>From</th>
                  <th>To</th>
                  <th>Subject</th>
                  <th style={{ width: 80  }}>Status</th>
                  <th style={{ width: 60  }}>DSN</th>
                  <th style={{ width: 60  }}>Score</th>
                  <th style={{ width: 60  }}>Size</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((log, i) => {
                  const evStyle  = EVENT_STYLE[log.event_type]  || { color:'#9ca3af', label: log.event_type };
                  const stStyle  = STATUS_STYLE[log.status]     || STATUS_STYLE.unknown;
                  const isExpand = expanded === i;
                  const isSpam   = log.spam_score > 5;
                  const isThreat = log.classification && !['CLEAN','Passed'].includes(log.classification);

                  return (
                    <>
                      <tr key={i}
                        onClick={() => setExpanded(isExpand ? null : i)}
                        style={{
                          cursor: 'pointer',
                          background: isExpand ? 'rgba(37,99,235,0.06)' :
                                      isThreat ? 'rgba(220,38,38,0.04)' :
                                      isSpam   ? 'rgba(217,119,6,0.04)' : undefined,
                        }}
                      >
                        <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                          {log.log_datetime?.slice(0,19) || '—'}
                        </td>
                        <td>
                          <span style={{ fontSize: 11, fontWeight: 600, color: evStyle.color }}>
                            {evStyle.label}
                          </span>
                        </td>
                        <td>
                          <span style={{
                            fontSize: 11, fontWeight: 600,
                            color: log.direction === 'inbound' ? '#67e8f9' : '#60a5fa',
                          }}>
                            {log.direction === 'inbound' ? '↓ In' : '↑ Out'}
                          </span>
                        </td>
                        <td style={{ maxWidth: 160 }}>
                          <div style={{ overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', fontSize:12 }} title={log.mail_from}>
                            {log.mail_from || '—'}
                          </div>
                        </td>
                        <td style={{ maxWidth: 160 }}>
                          <div style={{ overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', fontSize:12 }} title={log.mail_to}>
                            {log.mail_to || '—'}
                          </div>
                        </td>
                        <td style={{ maxWidth: 200 }}>
                          {log.subject ? (
                            <div style={{ overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', fontSize:12, color:'var(--text-primary)', fontWeight:500 }} title={decodeEmailSubject(log.subject)}>
                              {decodeEmailSubject(log.subject)}
                            </div>
                          ) : (
                            <span style={{ fontSize:11, color:'var(--text-muted)' }}>—</span>
                          )}
                        </td>
                        <td>
                          <Badge text={log.status || '—'} style={stStyle} />
                        </td>
                        <td>
                          <span className="mono" style={{
                            fontSize: 11,
                            color: log.dsn?.startsWith('5') ? '#f87171' :
                                   log.dsn?.startsWith('4') ? '#fbbf24' :
                                   log.dsn?.startsWith('2') ? '#4ade80' : 'var(--text-muted)'
                          }}>
                            {log.dsn || '—'}
                          </span>
                        </td>
                        <td>
                          {log.spam_score !== null && log.spam_score !== undefined ? (
                            <span className="mono" style={{
                              fontSize: 11, fontWeight: 600,
                              color: log.spam_score > 10 ? '#f87171' :
                                     log.spam_score > 5  ? '#fbbf24' : '#4ade80'
                            }}>
                              {Number(log.spam_score).toFixed(1)}
                            </span>
                          ) : <span style={{ color:'var(--text-muted)', fontSize:11 }}>—</span>}
                        </td>
                        <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {log.size_bytes ? `${Math.round(log.size_bytes/1024)}K` : '—'}
                        </td>
                      </tr>

                      {/* Expanded detail row */}
                      {isExpand && (
                        <tr key={`${i}-exp`} style={{ background: 'rgba(37,99,235,0.04)' }}>
                          <td colSpan={10} style={{ padding: '12px 16px' }}>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '8px 16px', fontSize: 12 }}>
                              <div><span style={{ color:'var(--text-muted)' }}>Queue ID:</span><br/><span className="mono">{log.queue_id || '—'}</span></div>
                              <div><span style={{ color:'var(--text-muted)' }}>Message ID:</span><br/><span className="mono" style={{ fontSize:10 }}>{log.message_id || '—'}</span></div>
                              <div><span style={{ color:'var(--text-muted)' }}>Relay IP:</span><br/><span className="mono">{log.relay_ip || '—'}</span></div>
                              <div><span style={{ color:'var(--text-muted)' }}>SASL User:</span><br/><span className="mono">{log.sasl_user || '—'}</span></div>
                              <div><span style={{ color:'var(--text-muted)' }}>Duration:</span><br/><span className="mono">{log.duration_ms ? `${log.duration_ms}ms` : '—'}</span></div>
                              <div><span style={{ color:'var(--text-muted)' }}>Classification:</span><br/>
                                <Badge text={log.classification || '—'} style={THREAT_STYLE[log.classification] || {}} />
                              </div>
                              <div><span style={{ color:'var(--text-muted)' }}>DKIM:</span><br/><span style={{ color: log.dkim_result === 'pass' ? '#4ade80' : '#f87171', fontWeight:600 }}>{log.dkim_result || '—'}</span></div>
                              <div><span style={{ color:'var(--text-muted)' }}>SPF:</span><br/><span style={{ color: log.spf_result === 'pass' ? '#4ade80' : '#f87171', fontWeight:600 }}>{log.spf_result || '—'}</span></div>
                              {log.reason && (
                                <div style={{ gridColumn:'1 / -1' }}>
                                  <span style={{ color:'var(--text-muted)' }}>Reason:</span><br/>
                                  <span style={{ color:'#fbbf24', fontFamily:'var(--font-mono)', fontSize:11 }}>{log.reason}</span>
                                </div>
                              )}
                              {log.subject && (
                                <div style={{ gridColumn:'1 / -1' }}>
                                  <span style={{ color:'var(--text-muted)' }}>Subject:</span><br/>
                                  <span style={{ color:'var(--text-primary)', fontWeight:500 }}>{decodeEmailSubject(log.subject)}</span>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  );
                })}
                {filtered.length === 0 && (
                  <tr><td colSpan={10} style={{ textAlign:'center', padding:48, color:'var(--text-muted)' }}>
                    No log entries found. Send a test mail to generate activity.
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
