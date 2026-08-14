import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Clock, AlertTriangle, CheckCircle, TrendingUp } from 'lucide-react';
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const TT = { background:'#0d1117', border:'1px solid #2d3748', borderRadius:8, fontSize:12 };

export default function DeliveryStatusPage({ server }) {
  const [current,  setCurrent]  = useState(null);
  const [history,  setHistory]  = useState([]);
  const [agentStatus, setAgentStatus] = useState(null);
  const [loading,  setLoading]  = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [q, s] = await Promise.all([
        api.get('/agent/queue-status',  { params: { server } }),
        api.get('/agent/status'),
      ]);
      setCurrent(q.data.current);
      setHistory(q.data.history || []);
      setAgentStatus(s.data.agents);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [server]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);

  const serverLabel = server === 'campaign' ? '🟠 Campaign' : '🔵 App Mail';
  const agentInfo   = agentStatus?.[server];
  const isOnline    = agentInfo?.online;

  // Chart data — queue over time
  const chartData = history.map(h => ({
    time:     h.snapshot_at?.slice(11,16) || '',
    queued:   Number(h.queue_count    || 0),
    deferred: Number(h.deferred_count || 0),
    active:   Number(h.active_count   || 0),
  }));

  return (
    <div>
      <div className="flex-between mb-24">
        <div>
          <div className="section-title">Delivery Status</div>
          <div className="section-sub">{serverLabel} · Postfix queue depth and delivery pipeline</div>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load}>
          <RefreshCw size={13} className={loading ? 'spin' : ''} /> Refresh
        </button>
      </div>

      {/* Agent status cards */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16, marginBottom:20 }} /* both servers shown */>
        {[
          { key:'app',      label:'mail.worktual.tech', vip:'82.113.72.84'  },
          { key:'campaign', label:'mail.worktual.pl',   vip:'82.113.72.80'  },
        ].map(s => {
          const info   = agentStatus?.[s.key];
          const online = info?.online;
          const q      = info?.queue || {};
          const rt     = info?.realtime || {};
          return (
            <div key={s.key} className="card" style={{
              borderTop: `3px solid ${online ? '#16a34a' : '#6b7280'}`,
            }}>
              <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:14 }}>
                <div style={{
                  width:10, height:10, borderRadius:'50%', flexShrink:0,
                  background: online ? '#4ade80' : '#6b7280',
                  boxShadow: online ? '0 0 6px #4ade80' : 'none',
                }} />
                <div style={{ fontWeight:700, fontSize:14 }}>{s.label}</div>
                <span style={{
                  marginLeft:'auto', fontSize:11, fontWeight:600, padding:'2px 8px', borderRadius:20,
                  background: online ? 'rgba(22,163,74,0.15)' : 'rgba(107,114,128,0.15)',
                  color:      online ? '#4ade80' : '#9ca3af',
                }}>
                  {online ? '✓ Online' : '○ Offline'}
                </span>
              </div>

              <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:10 }}>
                {[
                  { label:'Queued',   value: q.queue_count    || 0, color:'#2563eb' },
                  { label:'Deferred', value: q.deferred_count || 0, color:'#d97706' },
                  { label:'Active',   value: q.active_count   || 0, color:'#0891b2' },
                ].map(m => (
                  <div key={m.label} style={{ background:'var(--bg-primary)', borderRadius:8, padding:'10px 12px' }}>
                    <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>{m.label}</div>
                    <div style={{ fontSize:22, fontWeight:800, color: m.value > 0 ? m.color : 'var(--text-muted)', fontFamily:'var(--font-mono)' }}>
                      {m.value}
                    </div>
                  </div>
                ))}
              </div>

              <div style={{ marginTop:12, fontSize:12, color:'var(--text-muted)', display:'flex', justifyContent:'space-between' }}>
                <span>VIP: <span className="mono" style={{ color:'var(--text-primary)' }}>{s.vip}</span></span>
                <span>Today: <span style={{ color:'#4ade80', fontWeight:600 }}>{Number(rt.total_today || 0).toLocaleString()}</span> events</span>
              </div>

              {info?.queue?.snapshot_at && (
                <div style={{ marginTop:6, fontSize:11, color:'var(--text-muted)' }}>
                  Last snapshot: {new Date(info.queue.snapshot_at).toLocaleTimeString('en-IN')}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Queue history chart */}
      <div className="card mb-20">
        <div className="card-header">
          <span className="card-title">Queue depth history (last 48 snapshots)</span>
          <span style={{ fontSize:11, color:'var(--text-muted)' }}>1-minute intervals</span>
        </div>
        {chartData.length === 0 ? (
          <div className="loading-state" style={{ padding:48 }}>
            <Clock size={24} style={{ opacity:0.3, marginBottom:8 }} />
            <div>No queue history yet — snapshots taken every 60 seconds</div>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={chartData} margin={{ top:4, right:8, left:-20, bottom:0 }}>
              <defs>
                <linearGradient id="gq" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#2563eb" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#2563eb" stopOpacity={0}   />
                </linearGradient>
                <linearGradient id="gd" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#d97706" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#d97706" stopOpacity={0}   />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
              <XAxis dataKey="time" tick={{ fill:'#6e7681', fontSize:10 }} interval="preserveStartEnd" />
              <YAxis tick={{ fill:'#6e7681', fontSize:11 }} domain={[0,'auto']} allowDecimals={false} />
              <Tooltip contentStyle={TT} />
              <Legend wrapperStyle={{ fontSize:11 }} />
              <Area type="monotone" dataKey="queued"   stroke="#2563eb" fill="url(#gq)" name="Queued"   strokeWidth={2} />
              <Area type="monotone" dataKey="deferred" stroke="#d97706" fill="url(#gd)" name="Deferred" strokeWidth={1.5} />
              <Area type="monotone" dataKey="active"   stroke="#0891b2" fill="none"     name="Active"   strokeWidth={1} strokeDasharray="4 2" />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Current queue detail */}
      {current && (
        <div className="card">
          <div className="card-header"><span className="card-title">Current queue snapshot</span></div>
          <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:16, marginBottom:16 }}>
            {[
              { label:'Total Queued',  value:current.queue_count,    color:'#2563eb' },
              { label:'Deferred',      value:current.deferred_count, color:'#d97706' },
              { label:'Active',        value:current.active_count,   color:'#0891b2' },
              { label:'Incoming',      value:current.incoming_count, color:'#7c3aed' },
            ].map(m => (
              <div key={m.label} style={{ background:'var(--bg-primary)', borderRadius:8, padding:'14px 16px' }}>
                <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:6 }}>{m.label}</div>
                <div style={{ fontSize:28, fontWeight:800, color:m.value > 0 ? m.color : 'var(--text-muted)', fontFamily:'var(--font-mono)' }}>
                  {Number(m.value || 0).toLocaleString()}
                </div>
              </div>
            ))}
          </div>

          {current.top_senders && (() => {
            let senders = current.top_senders;
            if (typeof senders === 'string') {
              try { senders = JSON.parse(senders); } catch(e) { senders = []; }
            }
            if (!Array.isArray(senders) || senders.length === 0) return null;
            const maxVal = Math.max(...senders.map(s => s[1] || 0), 1);
            return (
              <div>
                <div style={{ fontSize:12, fontWeight:600, color:'var(--text-muted)', marginBottom:10, textTransform:'uppercase', letterSpacing:0.5 }}>
                  Top senders in queue
                </div>
                {senders.slice(0,8).map(([email, count], i) => (
                  <div key={i} style={{ display:'flex', alignItems:'center', gap:10, marginBottom:8 }}>
                    <span style={{ fontSize:11, color:'var(--text-muted)', width:16, textAlign:'right' }}>{i+1}</span>
                    <span style={{ fontSize:12, flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{email}</span>
                    <div style={{ width:120, background:'var(--border)', borderRadius:3, height:4 }}>
                      <div style={{ width:`${(count/maxVal)*100}%`, height:'100%', background:'#2563eb', borderRadius:3 }} />
                    </div>
                    <span className="mono" style={{ fontSize:12, fontWeight:700, color:'#60a5fa', width:30, textAlign:'right' }}>{count}</span>
                  </div>
                ))}
              </div>
            );
          })()}

          <div style={{ marginTop:12, fontSize:11, color:'var(--text-muted)' }}>
            Snapshot at: {current.snapshot_at} · Server: {current.server_name || current.server}
          </div>
        </div>
      )}

      {!current && !loading && (
        <div className="card" style={{ textAlign:'center', padding:48 }}>
          <Clock size={32} style={{ opacity:0.2, marginBottom:12 }} />
          <div style={{ color:'var(--text-muted)' }}>No queue snapshots yet</div>
          <div style={{ fontSize:12, color:'var(--text-muted)', marginTop:4 }}>
            Agent takes a snapshot every 60 seconds. Check that log-agent.mjs is running on the mail server.
          </div>
        </div>
      )}
    </div>
  );
}
