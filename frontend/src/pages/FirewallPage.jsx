import { useState, useEffect, useCallback, useRef } from 'react';
import { RefreshCw, Shield, AlertTriangle, Ban,
         Plus, Download, Globe, Activity, Server, Wifi } from 'lucide-react';
import {
  AreaChart, Area, LineChart, Line, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell, Legend
} from 'recharts';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const TT = { background:'#0d1117', border:'1px solid #30363d', borderRadius:8, fontSize:11 };

const ACTION_COLOR = {
  denied:   '#f87171',
  allowed:  '#4ade80',
  banned:   '#f97316',
  unbanned: '#60a5fa',
};

const EVENT_ICON = {
  ssh_denied:'🔑', smtp_ratelimit:'📧', imap_ratelimit:'📬',
  fail2ban_ban:'🔨', fail2ban_unban:'🔓', smtp_new:'📤',
  imap_new:'📩', denied:'🚫', blacklist:'⛔', ssh_new:'🔐',
};

// ── Animated Waveform component ──────────────────────────────
function Waveform({ data, height = 60 }) {
  if (!data || data.length === 0) {
    return (
      <div style={{ height, display:'flex', alignItems:'center',
        justifyContent:'center', color:'var(--text-muted)', fontSize:11 }}>
        No data yet — waiting for firewall events
      </div>
    );
  }
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top:2, right:0, left:-40, bottom:0 }}>
        <defs>
          <linearGradient id="gDenied"  x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#f87171" stopOpacity={0.4}/>
            <stop offset="95%" stopColor="#f87171" stopOpacity={0}/>
          </linearGradient>
          <linearGradient id="gAllowed" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#4ade80" stopOpacity={0.3}/>
            <stop offset="95%" stopColor="#4ade80" stopOpacity={0}/>
          </linearGradient>
          <linearGradient id="gBanned"  x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#f97316" stopOpacity={0.4}/>
            <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
          </linearGradient>
        </defs>
        <XAxis dataKey="minute" tick={false} axisLine={false} tickLine={false}/>
        <YAxis tick={false} axisLine={false} tickLine={false}/>
        <Tooltip contentStyle={TT} labelFormatter={v => `Time: ${v?.slice(11)||v}`}/>
        <Area type="monotone" dataKey="denied"  stroke="#f87171" fill="url(#gDenied)"  strokeWidth={1.5} dot={false} name="Denied"/>
        <Area type="monotone" dataKey="allowed" stroke="#4ade80" fill="url(#gAllowed)" strokeWidth={1}   dot={false} name="Allowed"/>
        <Area type="monotone" dataKey="banned"  stroke="#f97316" fill="url(#gBanned)"  strokeWidth={2}   dot={false} name="Banned"/>
      </AreaChart>
    </ResponsiveContainer>
  );
}

// ── Server metrics card ───────────────────────────────────────
function ServerMetricCard({ server, data }) {
  if (!data) return null;
  const queue   = data.queue   || {};
  const volume  = data.volume  || {};
  const fw      = data.firewall|| {};
  const delRate = volume.total > 0
    ? Math.round((volume.delivered / volume.total) * 100) : 0;

  return (
    <div className="card" style={{ borderTop:`3px solid ${server==='app'?'#2563eb':'#dc2626'}` }}>
      <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:14 }}>
        <div style={{
          width:36, height:36, borderRadius:8, flexShrink:0,
          background: server==='app' ? 'rgba(37,99,235,0.15)' : 'rgba(220,38,38,0.15)',
          display:'flex', alignItems:'center', justifyContent:'center', fontSize:18
        }}>📧</div>
        <div>
          <div style={{ fontSize:13, fontWeight:700 }}>{data.name}</div>
          <div style={{ fontSize:10, color:'var(--text-muted)' }}>{data.vip} · {data.ip}</div>
        </div>
        <div style={{ marginLeft:'auto', display:'flex', alignItems:'center', gap:5 }}>
          <div style={{ width:8, height:8, borderRadius:'50%', background:'#4ade80',
            boxShadow:'0 0 6px #4ade80', animation:'pulse-dot 2s infinite' }}/>
          <span style={{ fontSize:11, color:'#4ade80' }}>Online</span>
        </div>
      </div>

      {/* Queue metrics */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:8, marginBottom:12 }}>
        {[
          { label:'Queued',   value: queue.queue_count    || 0, color:'#60a5fa' },
          { label:'Deferred', value: queue.deferred_count || 0, color:'#fbbf24' },
          { label:'Active',   value: queue.active_count   || 0, color:'#4ade80' },
          { label:'Incoming', value: queue.incoming_count || 0, color:'#a78bfa' },
        ].map(m => (
          <div key={m.label} style={{ background:'var(--bg-primary)', borderRadius:6,
            padding:'8px 10px', textAlign:'center' }}>
            <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:3 }}>{m.label}</div>
            <div style={{ fontSize:18, fontWeight:800, color:m.color,
              fontFamily:'var(--font-mono)' }}>{Number(m.value).toLocaleString()}</div>
          </div>
        ))}
      </div>

      {/* Email volume */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:8, marginBottom:12 }}>
        {[
          { label:'Total 24h',  value: volume.total     || 0, color:'var(--text-primary)' },
          { label:'Delivered',  value: volume.delivered || 0, color:'#4ade80' },
          { label:'Bounced',    value: volume.bounced   || 0, color:'#fbbf24' },
          { label:'Rejected',   value: volume.rejected  || 0, color:'#f87171' },
        ].map(m => (
          <div key={m.label} style={{ background:'var(--bg-primary)', borderRadius:6,
            padding:'8px 10px', textAlign:'center' }}>
            <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:3 }}>{m.label}</div>
            <div style={{ fontSize:16, fontWeight:700, color:m.color,
              fontFamily:'var(--font-mono)' }}>{Number(m.value).toLocaleString()}</div>
          </div>
        ))}
      </div>

      {/* Delivery rate bar */}
      <div style={{ marginBottom:12 }}>
        <div style={{ display:'flex', justifyContent:'space-between', fontSize:11,
          color:'var(--text-muted)', marginBottom:4 }}>
          <span>Delivery rate</span>
          <span style={{ fontWeight:700, color: delRate>95?'#4ade80':delRate>80?'#fbbf24':'#f87171' }}>
            {delRate}%
          </span>
        </div>
        <div style={{ height:6, background:'var(--border)', borderRadius:3, overflow:'hidden' }}>
          <div style={{ height:'100%', borderRadius:3, transition:'width 0.5s',
            width:`${delRate}%`,
            background: delRate>95?'#4ade80':delRate>80?'#fbbf24':'#f87171' }}/>
        </div>
      </div>

      {/* Firewall stats */}
      <div style={{ background:'rgba(220,38,38,0.06)', border:'1px solid rgba(220,38,38,0.2)',
        borderRadius:6, padding:'8px 12px' }}>
        <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:6,
          textTransform:'uppercase', letterSpacing:0.5 }}>Firewall (last 1h)</div>
        <div style={{ display:'flex', gap:16, fontSize:12 }}>
          <span>🚫 <strong style={{color:'#f87171'}}>{Number(fw.denied||0).toLocaleString()}</strong> denied</span>
          <span>🔨 <strong style={{color:'#f97316'}}>{Number(fw.active_bans||0)}</strong> bans</span>
          <span>🌐 <strong style={{color:'#60a5fa'}}>{Number(fw.unique_ips||0)}</strong> unique IPs</span>
        </div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────
export default function FirewallPage({ server: propServer }) {
  const [server,      setServer]      = useState('all');
  const [activeTab,   setActiveTab]   = useState('overview');
  const [hours,       setHours]       = useState(24);
  const [summary,     setSummary]     = useState(null);
  const [waveform,    setWaveform]    = useState([]);
  const [events,      setEvents]      = useState([]);
  const [bans,        setBans]        = useState([]);
  const [whitelist,   setWhitelist]   = useState([]);
  const [blocked,     setBlocked]     = useState([]);
  const [countries,   setCountries]   = useState([]);
  const [metrics,     setMetrics]     = useState(null);
  const [loading,     setLoading]     = useState(true);
  const [actionFilter,setActionFilter]= useState('');
  const [ipSearch,    setIpSearch]    = useState('');
  const [newWL,       setNewWL]       = useState({ ip_cidr:'', description:'' });
  const [newBlock,    setNewBlock]    = useState({ ip_cidr:'', description:'', expires_hours:'' });
  const [toast,       setToast]       = useState('');
  const waveformRef = useRef(null);

  const showToast = (msg) => { setToast(msg); setTimeout(() => setToast(''), 3000); };

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [s, w, c, m] = await Promise.all([
        api.get('/firewall/summary',       { params:{ server, hours } }),
        api.get('/firewall/waveform',      { params:{ server, hours: Math.min(hours,6) } }),
        api.get('/firewall/countries',     { params:{ server, hours } }),
        api.get('/firewall/server-metrics').catch(() => ({ data:{ data:null } })),
      ]);
      setSummary(s.data.data);
      setWaveform((w.data.data||[]).map(r=>({
        ...r,
        denied:  Number(r.denied||0),
        allowed: Number(r.allowed||0),
        banned:  Number(r.banned||0),
      })));
      setCountries(c.data.data||[]);
      setMetrics(m.data.servers||null);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  }, [server, hours]);

  const loadEvents = useCallback(async () => {
    try {
      const r = await api.get('/firewall/events', {
        params:{ server, hours, action:actionFilter||undefined, ip:ipSearch||undefined, limit:200 }
      });
      setEvents(r.data.data||[]);
    } catch(e) {}
  }, [server, hours, actionFilter, ipSearch]);

  const loadBans = useCallback(async () => {
    try {
      const [b,wl,bl] = await Promise.all([
        api.get('/firewall/bans',    { params:{ server } }),
        api.get('/firewall/whitelist'),
        api.get('/firewall/blocked'),
      ]);
      setBans(b.data.data||[]);
      setWhitelist(wl.data.data||[]);
      setBlocked(bl.data.data||[]);
    } catch(e) {}
  }, [server]);

  useEffect(() => { loadAll(); }, [loadAll]);
  useEffect(() => { if (activeTab==='events') loadEvents(); }, [activeTab, loadEvents]);
  useEffect(() => { if (activeTab==='bans')   loadBans();   }, [activeTab, loadBans]);

  // Auto-refresh waveform every 30s
  useEffect(() => {
    const t = setInterval(() => {
      api.get('/firewall/waveform', { params:{ server, hours:1 } })
        .then(r => setWaveform((r.data.data||[]).map(x=>({
          ...x, denied:Number(x.denied||0), allowed:Number(x.allowed||0), banned:Number(x.banned||0)
        }))))
        .catch(()=>{});
      if (activeTab==='overview') loadAll();
      if (activeTab==='events')   loadEvents();
    }, 30000);
    return () => clearInterval(t);
  }, [server, activeTab, hours, loadAll, loadEvents]);

  const unban = async (ip, jail, srv) => {
    try {
      await api.post('/firewall/unban', { ip, jail, server:srv });
      showToast(`✅ ${ip} unbanned`);
      loadBans();
    } catch(e) { alert(e.message); }
  };

  const addWL = async () => {
    if (!newWL.ip_cidr) return;
    try {
      await api.post('/firewall/whitelist', newWL);
      showToast(`✅ ${newWL.ip_cidr} whitelisted`);
      setNewWL({ ip_cidr:'', description:'' });
      loadBans();
    } catch(e) { alert(e.message); }
  };

  const addBlock = async () => {
    if (!newBlock.ip_cidr) return;
    try {
      await api.post('/firewall/block', newBlock);
      showToast(`✅ ${newBlock.ip_cidr} blocked`);
      setNewBlock({ ip_cidr:'', description:'', expires_hours:'' });
      loadBans();
    } catch(e) { alert(e.message); }
  };

  const exportCSV = () => {
    const csv = ['DateTime,Server,Event,SrcIP,DstPort,Protocol,Action,Country,Jail',
      ...events.map(e=>[e.log_datetime,e.server,e.event_type,e.src_ip,
        e.dst_port,e.protocol,e.action,e.country_name||'',e.jail||''].join(','))
    ].join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
    a.download = `firewall-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  };

  const stats = summary?.stats || {};

  return (
    <div>
      {/* Toast */}
      {toast && (
        <div style={{ position:'fixed', top:16, right:16, zIndex:9999,
          padding:'10px 20px', borderRadius:8, fontSize:13,
          background:'rgba(22,163,74,0.95)', color:'#fff', fontWeight:600 }}>
          {toast}
        </div>
      )}

      {/* Header */}
      <div className="flex-between mb-16">
        <div>
          <div className="section-title">Firewall Security</div>
          <div className="section-sub">
            iptables + Fail2Ban · Live waveform · Server metrics · Ban management
          </div>
        </div>
        <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' }}>
          <select className="input" style={{ width:140, fontSize:12 }}
            value={server} onChange={e=>setServer(e.target.value)}>
            <option value="all">Both Servers</option>
            <option value="app">App Mail (0.84)</option>
            <option value="campaign">Campaign (0.89)</option>
          </select>
          {[1,6,24,48,168].map(h=>(
            <button key={h} className={`btn btn-sm ${hours===h?'btn-primary':'btn-ghost'}`}
              onClick={()=>setHours(h)}>
              {h===1?'1h':h===6?'6h':h===24?'24h':h===48?'2d':'7d'}
            </button>
          ))}
          <button className="btn btn-ghost btn-sm" onClick={loadAll}>
            <RefreshCw size={13} className={loading?'spin':''}/> Refresh
          </button>
        </div>
      </div>

      {/* ── KPI row ── */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(8,1fr)', gap:10, marginBottom:16 }}>
        {[
          { label:'Total Events', value:stats.total_events,  color:'#2563eb' },
          { label:'Denied',       value:stats.total_denied,  color:'#f87171' },
          { label:'Allowed',      value:stats.total_allowed, color:'#4ade80' },
          { label:'Active Bans',  value:stats.active_bans,   color:'#f97316' },
          { label:'SSH Attacks',  value:stats.ssh_attacks,   color:'#dc2626' },
          { label:'Rate Limited', value:stats.smtp_ratelimit,color:'#d97706' },
          { label:'Unique IPs',   value:stats.unique_ips,    color:'#0891b2' },
          { label:'Countries',    value:stats.countries,     color:'#7c3aed' },
        ].map(k=>(
          <div key={k.label} className="card"
            style={{ borderTop:`3px solid ${k.color}`, padding:'10px 12px' }}>
            <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:3,
              textTransform:'uppercase', letterSpacing:0.4 }}>{k.label}</div>
            <div style={{ fontSize:20, fontWeight:800, color:k.color,
              fontFamily:'var(--font-mono)' }}>{Number(k.value||0).toLocaleString()}</div>
          </div>
        ))}
      </div>

      {/* ── Live Waveform ── */}
      <div className="card mb-16">
        <div className="flex-between mb-8">
          <div>
            <span className="card-title">Live connection waveform</span>
            <span style={{ fontSize:11, color:'var(--text-muted)', marginLeft:12 }}>
              Per-minute hit rate · auto-refresh 30s
            </span>
          </div>
          <div style={{ display:'flex', gap:14, fontSize:11 }}>
            {[['#f87171','Denied'],['#4ade80','Allowed'],['#f97316','Banned']].map(([c,l])=>(
              <div key={l} style={{ display:'flex', alignItems:'center', gap:5 }}>
                <div style={{ width:10, height:3, borderRadius:2, background:c }}/>
                <span style={{ color:'var(--text-muted)' }}>{l}</span>
              </div>
            ))}
          </div>
        </div>
        <Waveform data={waveform} height={90}/>
      </div>

      {/* Tabs */}
      <div className="tab-bar" style={{ marginBottom:16 }}>
        {[
          { id:'overview',  label:'Overview'     },
          { id:'servers',   label:'Server Metrics'},
          { id:'events',    label:'Live Events'  },
          { id:'bans',      label:`Bans (${bans.filter(b=>b.active).length||'—'})` },
          { id:'whitelist', label:'Whitelist'    },
          { id:'block',     label:'Manual Block' },
          { id:'geo',       label:'Geo Map'      },
        ].map(t=>(
          <button key={t.id} className={`tab-item ${activeTab===t.id?'active':''}`}
            onClick={()=>setActiveTab(t.id)}>{t.label}</button>
        ))}
      </div>

      {/* ── OVERVIEW ── */}
      {activeTab === 'overview' && (
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>

          {/* Hourly trend */}
          <div className="card">
            <div className="card-header"><span className="card-title">Hourly trend (last {hours}h)</span></div>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={summary?.trend||[]} margin={{ top:4,right:8,left:-20,bottom:0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)"/>
                <XAxis dataKey="hour" tick={{ fill:'#6e7681', fontSize:9 }}/>
                <YAxis tick={{ fill:'#6e7681', fontSize:9 }} allowDecimals={false}/>
                <Tooltip contentStyle={TT}/>
                <Legend wrapperStyle={{ fontSize:10 }}/>
                <Bar dataKey="denied"  fill="#f87171" name="Denied"  radius={[2,2,0,0]}/>
                <Bar dataKey="allowed" fill="#4ade80" name="Allowed" radius={[2,2,0,0]}/>
                <Bar dataKey="banned"  fill="#f97316" name="Banned"  radius={[2,2,0,0]}/>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Top attackers */}
          <div className="card">
            <div className="card-header"><span className="card-title">Top attackers</span></div>
            <div className="table-wrapper">
              <table>
                <thead><tr><th>IP</th><th>Country</th><th>Attempts</th><th>Last Seen</th></tr></thead>
                <tbody>
                  {(summary?.topAttackers||[]).slice(0,8).map((r,i)=>(
                    <tr key={i}>
                      <td className="mono" style={{ fontSize:11, fontWeight:700, color:'#f87171' }}>{r.src_ip}</td>
                      <td style={{ fontSize:11, color:'var(--text-muted)' }}>{r.country_code||'—'} {r.country_name||''}</td>
                      <td className="mono" style={{ fontWeight:700, color:'#fbbf24' }}>{Number(r.attempts).toLocaleString()}</td>
                      <td className="mono" style={{ fontSize:10, color:'var(--text-muted)' }}>{r.last_seen?.slice(11,16)||'—'}</td>
                    </tr>
                  ))}
                  {!(summary?.topAttackers?.length) && (
                    <tr><td colSpan={4} style={{ textAlign:'center', padding:32, color:'#4ade80' }}>
                      ✅ No attacks detected
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Top targeted ports */}
          <div className="card">
            <div className="card-header"><span className="card-title">Top targeted ports</span></div>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={(summary?.topPorts||[]).slice(0,8)} layout="vertical"
                margin={{ top:4,right:20,left:10,bottom:0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" horizontal={false}/>
                <XAxis type="number" tick={{ fill:'#6e7681', fontSize:9 }} allowDecimals={false}/>
                <YAxis dataKey="dst_port" type="category" width={36} tick={{ fill:'#8b949e', fontSize:9 }}/>
                <Tooltip contentStyle={TT}/>
                <Bar dataKey="attempts" name="Attempts" radius={[0,4,4,0]}>
                  {(summary?.topPorts||[]).slice(0,8).map((_,i)=>(
                    <Cell key={i} fill={['#f87171','#fbbf24','#60a5fa','#a78bfa','#34d399','#f97316','#818cf8','#e879f9'][i%8]}/>
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Quick attack breakdown */}
          <div className="card">
            <div className="card-header"><span className="card-title">Attack breakdown</span></div>
            {[
              { label:'Port scans / unknown',  value:stats.port_scans,    color:'#f87171', icon:'🔍' },
              { label:'SSH brute force',        value:stats.ssh_attacks,   color:'#dc2626', icon:'🔑' },
              { label:'SMTP rate-limited',      value:stats.smtp_ratelimit,color:'#d97706', icon:'📧' },
              { label:'IMAP rate-limited',      value:stats.imap_ratelimit,color:'#7c3aed', icon:'📬' },
              { label:'Countries attacking',    value:stats.countries,     color:'#0891b2', icon:'🌍' },
              { label:'Unique attacker IPs',    value:stats.unique_ips,    color:'#6b7280', icon:'🖥' },
            ].map(r=>(
              <div key={r.label} style={{ display:'flex', justifyContent:'space-between',
                alignItems:'center', padding:'9px 0',
                borderBottom:'1px solid var(--border)', fontSize:13 }}>
                <span style={{ color:'var(--text-muted)' }}>{r.icon} {r.label}</span>
                <span style={{ fontFamily:'var(--font-mono)', fontWeight:700, color:r.color }}>
                  {Number(r.value||0).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── SERVER METRICS ── */}
      {activeTab === 'servers' && (
        <div>
          <div style={{ fontSize:12, color:'var(--text-muted)', marginBottom:16 }}>
            Real-time queue depth, email volume and firewall status per server · auto-refresh 30s
          </div>
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
            <ServerMetricCard server="app"      data={metrics?.app}/>
            <ServerMetricCard server="campaign" data={metrics?.campaign}/>
          </div>
          {!metrics && (
            <div className="card" style={{ textAlign:'center', padding:48 }}>
              <Server size={32} style={{ opacity:0.2, marginBottom:12 }}/>
              <div style={{ color:'var(--text-muted)' }}>
                Server metrics loading — firewall agent must be running on both servers
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── LIVE EVENTS ── */}
      {activeTab === 'events' && (
        <div>
          <div className="card mb-12" style={{ padding:'10px 14px' }}>
            <div style={{ display:'flex', gap:10, alignItems:'center', flexWrap:'wrap' }}>
              <input className="input" style={{ flex:1, minWidth:160, fontSize:12 }}
                placeholder="Filter by IP..." value={ipSearch}
                onChange={e=>setIpSearch(e.target.value)}/>
              <select className="input" style={{ width:130, fontSize:12 }}
                value={actionFilter} onChange={e=>setActionFilter(e.target.value)}>
                <option value="">All Actions</option>
                <option value="denied">Denied</option>
                <option value="allowed">Allowed</option>
                <option value="banned">Banned</option>
              </select>
              <button className="btn btn-ghost btn-sm" onClick={loadEvents}><RefreshCw size={13}/></button>
              <button className="btn btn-ghost btn-sm" onClick={exportCSV}><Download size={13}/> CSV</button>
              <span style={{ fontSize:11, color:'var(--text-muted)' }}>
                {events.length} events · auto-refresh 30s
              </span>
            </div>
          </div>
          <div className="card">
            <div className="table-wrapper">
              <table>
                <thead><tr>
                  <th>Time</th><th>Server</th><th>Event</th><th>Src IP</th>
                  <th>Port</th><th>Proto</th><th>Action</th><th>Country</th><th>Jail</th>
                </tr></thead>
                <tbody>
                  {events.map((e,i)=>(
                    <tr key={i}>
                      <td className="mono" style={{ fontSize:10, color:'var(--text-muted)', whiteSpace:'nowrap' }}>
                        {e.log_datetime?.slice(11,16)||'—'}
                      </td>
                      <td>
                        <span style={{ fontSize:10, fontWeight:600, padding:'1px 6px', borderRadius:20,
                          background:e.server==='app'?'rgba(37,99,235,0.15)':'rgba(220,38,38,0.15)',
                          color:e.server==='app'?'#60a5fa':'#f87171' }}>{e.server}</span>
                      </td>
                      <td style={{ fontSize:11 }}>{EVENT_ICON[e.event_type]||'❓'} {e.event_type}</td>
                      <td className="mono" style={{ fontSize:11, fontWeight:600, color:'#fbbf24' }}>{e.src_ip}</td>
                      <td className="mono" style={{ fontSize:11,
                        color:e.dst_port===4204||e.dst_port===22?'#f87171':'var(--text-muted)' }}>
                        {e.dst_port||'—'}
                      </td>
                      <td style={{ fontSize:11, color:'var(--text-muted)' }}>{e.protocol||'—'}</td>
                      <td>
                        <span style={{ fontSize:11, fontWeight:700, padding:'2px 8px', borderRadius:20,
                          background:`${ACTION_COLOR[e.action]||'#6b7280'}22`,
                          color:ACTION_COLOR[e.action]||'#6b7280' }}>{e.action}</span>
                      </td>
                      <td style={{ fontSize:11, color:'var(--text-muted)' }}>{e.country_code||'—'}</td>
                      <td style={{ fontSize:10, color:'#fbbf24' }}>{e.jail||'—'}</td>
                    </tr>
                  ))}
                  {!events.length && (
                    <tr><td colSpan={9} style={{ textAlign:'center', padding:40, color:'#4ade80' }}>
                      ✅ No events — all quiet
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── BANS ── */}
      {activeTab === 'bans' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Active Fail2Ban bans ({bans.filter(b=>b.active).length})</span>
          </div>
          <div className="table-wrapper">
            <table>
              <thead><tr>
                <th>IP</th><th>Server</th><th>Jail</th><th>Banned At</th>
                <th>Count</th><th>Country</th><th>Action</th>
              </tr></thead>
              <tbody>
                {bans.filter(b=>b.active).map((b,i)=>(
                  <tr key={i}>
                    <td className="mono" style={{ fontWeight:700, fontSize:12, color:'#f87171' }}>{b.ip_address}</td>
                    <td><span style={{ fontSize:10, padding:'1px 6px', borderRadius:20,
                      background:'rgba(220,38,38,0.15)', color:'#f87171' }}>{b.server}</span></td>
                    <td style={{ fontSize:11, color:'#fbbf24' }}>{b.jail}</td>
                    <td className="mono" style={{ fontSize:11, color:'var(--text-muted)' }}>{b.banned_at?.slice(0,16)}</td>
                    <td className="mono" style={{ fontWeight:700, color:'#f97316' }}>{b.ban_count}</td>
                    <td style={{ fontSize:11, color:'var(--text-muted)' }}>{b.country_name||b.country_code||'—'}</td>
                    <td>
                      <button className="btn btn-ghost btn-sm" style={{ fontSize:11, padding:'2px 10px' }}
                        onClick={()=>unban(b.ip_address, b.jail, b.server)}>🔓 Unban</button>
                    </td>
                  </tr>
                ))}
                {!bans.filter(b=>b.active).length && (
                  <tr><td colSpan={7} style={{ textAlign:'center', padding:40, color:'#4ade80' }}>
                    ✅ No active bans
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── WHITELIST ── */}
      {activeTab === 'whitelist' && (
        <div>
          <div className="card mb-16">
            <div className="card-header"><span className="card-title">Add to whitelist</span></div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr auto', gap:10, alignItems:'end' }}>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>IP / CIDR *</label>
                <input className="input" style={{ marginTop:4 }} placeholder="1.2.3.4 or 1.2.3.0/24"
                  value={newWL.ip_cidr} onChange={e=>setNewWL(p=>({...p,ip_cidr:e.target.value}))}/>
              </div>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>Description</label>
                <input className="input" style={{ marginTop:4 }} placeholder="Office IP"
                  value={newWL.description} onChange={e=>setNewWL(p=>({...p,description:e.target.value}))}/>
              </div>
              <button className="btn btn-primary btn-sm" onClick={addWL} disabled={!newWL.ip_cidr}>
                <Plus size={13}/> Add
              </button>
            </div>
          </div>
          <div className="card">
            <div className="card-header"><span className="card-title">Whitelisted ({whitelist.length})</span></div>
            <div className="table-wrapper">
              <table>
                <thead><tr><th>IP/CIDR</th><th>Description</th><th>Added By</th><th>Date</th></tr></thead>
                <tbody>
                  {whitelist.map((w,i)=>(
                    <tr key={i}>
                      <td className="mono" style={{ fontWeight:700, color:'#4ade80', fontSize:12 }}>{w.ip_cidr}</td>
                      <td style={{ fontSize:12 }}>{w.description||'—'}</td>
                      <td style={{ fontSize:11, color:'var(--text-muted)' }}>{w.added_by||'admin'}</td>
                      <td style={{ fontSize:11, color:'var(--text-muted)' }}>{w.created_at?.slice(0,10)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── MANUAL BLOCK ── */}
      {activeTab === 'block' && (
        <div>
          <div className="card mb-16">
            <div className="card-header"><span className="card-title">Manually block an IP</span></div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 120px auto', gap:10, alignItems:'end' }}>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>IP / CIDR *</label>
                <input className="input" style={{ marginTop:4 }} placeholder="1.2.3.4"
                  value={newBlock.ip_cidr} onChange={e=>setNewBlock(p=>({...p,ip_cidr:e.target.value}))}/>
              </div>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>Reason</label>
                <input className="input" style={{ marginTop:4 }} placeholder="Spam source"
                  value={newBlock.description} onChange={e=>setNewBlock(p=>({...p,description:e.target.value}))}/>
              </div>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>Expires (hrs)</label>
                <input className="input" style={{ marginTop:4 }} type="number" placeholder="never"
                  value={newBlock.expires_hours} onChange={e=>setNewBlock(p=>({...p,expires_hours:e.target.value}))}/>
              </div>
              <button className="btn btn-danger btn-sm" onClick={addBlock} disabled={!newBlock.ip_cidr}>
                <Ban size={13}/> Block
              </button>
            </div>
          </div>
          <div className="card">
            <div className="card-header"><span className="card-title">Manual blocks ({blocked.length})</span></div>
            <div className="table-wrapper">
              <table>
                <thead><tr><th>IP/CIDR</th><th>Reason</th><th>Added</th><th>Expires</th></tr></thead>
                <tbody>
                  {blocked.map((b,i)=>(
                    <tr key={i}>
                      <td className="mono" style={{ fontWeight:700, color:'#f87171', fontSize:12 }}>{b.ip_cidr}</td>
                      <td style={{ fontSize:12 }}>{b.description||'—'}</td>
                      <td className="mono" style={{ fontSize:11, color:'var(--text-muted)' }}>{b.created_at?.slice(0,10)}</td>
                      <td style={{ fontSize:11, color:b.expires_at?'#fbbf24':'var(--text-muted)' }}>
                        {b.expires_at?.slice(0,16)||'Never'}
                      </td>
                    </tr>
                  ))}
                  {!blocked.length && (
                    <tr><td colSpan={4} style={{ textAlign:'center', padding:32, color:'var(--text-muted)' }}>
                      No manual blocks
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── GEO MAP ── */}
      {activeTab === 'geo' && (
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
          <div className="card">
            <div className="card-header"><span className="card-title">Attacks by country (last {hours}h)</span></div>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={countries.slice(0,15)} layout="vertical"
                margin={{ top:4,right:20,left:10,bottom:0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" horizontal={false}/>
                <XAxis type="number" tick={{ fill:'#6e7681', fontSize:9 }} allowDecimals={false}/>
                <YAxis dataKey="country_code" type="category" width={36} tick={{ fill:'#8b949e', fontSize:9 }}/>
                <Tooltip contentStyle={TT}/>
                <Bar dataKey="attempts" name="Attempts" radius={[0,4,4,0]} fill="#f87171"/>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="card">
            <div className="card-header"><span className="card-title">Country detail</span></div>
            <div className="table-wrapper">
              <table>
                <thead><tr><th>#</th><th>Country</th><th>Attempts</th><th>Unique IPs</th></tr></thead>
                <tbody>
                  {countries.slice(0,20).map((c,i)=>(
                    <tr key={i}>
                      <td className="mono" style={{ fontSize:11, color:'var(--text-muted)', width:30 }}>{i+1}</td>
                      <td style={{ fontSize:12 }}>
                        <span style={{ fontWeight:700, marginRight:6 }}>{c.country_code}</span>
                        <span style={{ color:'var(--text-muted)' }}>{c.country_name}</span>
                      </td>
                      <td className="mono" style={{ fontWeight:700, color:'#f87171' }}>
                        {Number(c.attempts).toLocaleString()}
                      </td>
                      <td className="mono" style={{ color:'#fbbf24' }}>
                        {Number(c.unique_ips).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                  {!countries.length && (
                    <tr><td colSpan={4} style={{ textAlign:'center', padding:32, color:'#4ade80' }}>
                      ✅ No denied connections
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes pulse-dot {
          0%,100% { box-shadow:0 0 0 0 rgba(74,222,128,0.4); }
          50%      { box-shadow:0 0 0 5px rgba(74,222,128,0); }
        }
      `}</style>
    </div>
  );
}
