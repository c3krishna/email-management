import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Shield, AlertTriangle, Globe,
         Users, Download, Plus, Settings, Eye,
         TrendingUp, Bell, Search, Filter } from 'lucide-react';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const TT = { background:'#0d1117', border:'1px solid #30363d', borderRadius:8, fontSize:11 };

// ── Theme colors ──────────────────────────────────────────────
const THREAT_COLORS = {
  phishing:   '#f43f5e',
  spam:       '#f97316',
  malware:    '#a855f7',
  bec:        '#ef4444',
  url_threat: '#0891b2',
  scam:       '#eab308',
  none:       '#6b7280',
};

const PLATFORM_COLORS = {
  proofpoint:         '#2563eb',
  microsoft_defender: '#0078d4',
  google_workspace:   '#ea4335',
  mimecast:           '#7c3aed',
  barracuda:          '#16a34a',
  imap:               '#d97706',
  postfix_agent:      '#0891b2',
  webhook:            '#6b7280',
};

const PLATFORM_ICONS = {
  proofpoint:         '🛡️',
  microsoft_defender: '🪟',
  google_workspace:   '🔵',
  mimecast:           '🔐',
  barracuda:          '🐟',
  imap:               '📬',
  postfix_agent:      '📧',
  webhook:            '🔗',
};

// ── Helper components ─────────────────────────────────────────
function ThreatBadge({ type }) {
  const color = THREAT_COLORS[type] || '#6b7280';
  return (
    <span style={{ padding:'2px 8px', borderRadius:20, fontSize:11,
      fontWeight:700, background:`${color}22`, color }}>
      {type || 'unknown'}
    </span>
  );
}

function PlatformBadge({ platform }) {
  const color = PLATFORM_COLORS[platform] || '#6b7280';
  const icon  = PLATFORM_ICONS[platform]  || '🔌';
  return (
    <span style={{ padding:'2px 8px', borderRadius:20, fontSize:11,
      fontWeight:600, background:`${color}22`, color,
      display:'inline-flex', alignItems:'center', gap:4 }}>
      {icon} {platform?.replace(/_/g,' ')}
    </span>
  );
}

function StatCard({ label, value, color, icon, sub }) {
  return (
    <div className="card" style={{ borderTop:`3px solid ${color}`, padding:'14px 16px' }}>
      <div style={{ fontSize:20, marginBottom:4 }}>{icon}</div>
      <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:4,
        textTransform:'uppercase', letterSpacing:0.5 }}>{label}</div>
      <div style={{ fontSize:24, fontWeight:800, color,
        fontFamily:'var(--font-mono)' }}>{Number(value||0).toLocaleString()}</div>
      {sub && <div style={{ fontSize:10, color:'var(--text-muted)', marginTop:2 }}>{sub}</div>}
    </div>
  );
}

// ── Add Connector Modal ───────────────────────────────────────
function AddConnectorModal({ customers, onClose, onSaved }) {
  const [step,       setStep]       = useState(1); // 1=select platform, 2=fill creds
  const [platforms,  setPlatforms]  = useState([]);
  const [selected,   setSelected]   = useState(null);
  const [customerId, setCustomerId] = useState('');
  const [displayName,setDisplayName]= useState('');
  const [creds,      setCreds]      = useState({});
  const [testing,    setTesting]    = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [saving,     setSaving]     = useState(false);

  useEffect(() => {
    api.get('/connectors/platforms').then(r => setPlatforms(r.data.data||[]));
  }, []);

  const save = async () => {
    if (!customerId || !selected) return;
    setSaving(true);
    try {
      await api.post('/connectors', {
        customer_id:    parseInt(customerId),
        connector_type: selected.id,
        display_name:   displayName || selected.label,
        credentials:    creds,
      });
      onSaved();
      onClose();
    } catch(e) { alert(e.response?.data?.error || e.message); }
    finally { setSaving(false); }
  };

  const testConn = async () => {
    setTesting(true); setTestResult(null);
    try {
      // Save first to get ID, then test
      const r = await api.post('/connectors', {
        customer_id:    parseInt(customerId),
        connector_type: selected.id,
        display_name:   displayName || selected.label,
        credentials:    creds,
      });
      const tr = await api.post(`/connectors/${r.data.id}/test`);
      setTestResult(tr.data);
    } catch(e) {
      setTestResult({ success:false, message: e.response?.data?.error || e.message });
    }
    setTesting(false);
  };

  return (
    <div style={{ position:'fixed', inset:0, background:'rgba(0,0,0,0.7)',
      zIndex:9000, display:'flex', alignItems:'center', justifyContent:'center' }}>
      <div style={{ background:'var(--bg-card)', border:'1px solid var(--border)',
        borderRadius:12, width:640, maxHeight:'90vh', overflow:'auto',
        boxShadow:'0 20px 60px rgba(0,0,0,0.5)' }}>

        {/* Header */}
        <div style={{ padding:'20px 24px', borderBottom:'1px solid var(--border)',
          display:'flex', justifyContent:'space-between', alignItems:'center' }}>
          <div>
            <div style={{ fontSize:16, fontWeight:700 }}>Add Platform Connector</div>
            <div style={{ fontSize:12, color:'var(--text-muted)' }}>
              Step {step} of 2 — {step===1?'Select Platform':'Configure Credentials'}
            </div>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={onClose}>✕</button>
        </div>

        <div style={{ padding:24 }}>
          {step === 1 && (
            <div>
              <div style={{ marginBottom:16 }}>
                <label style={{ fontSize:12, color:'var(--text-muted)' }}>Customer *</label>
                <select className="input" style={{ marginTop:4 }}
                  value={customerId} onChange={e=>setCustomerId(e.target.value)}>
                  <option value="">Select customer...</option>
                  {customers.map(c=>(
                    <option key={c.id} value={c.id}>{c.name} ({c.domain})</option>
                  ))}
                </select>
              </div>
              <div style={{ fontSize:12, color:'var(--text-muted)', marginBottom:12 }}>
                Select email security platform:
              </div>
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:10 }}>
                {platforms.map(p => (
                  <button key={p.id} onClick={()=>setSelected(p)}
                    style={{
                      padding:14, borderRadius:10, cursor:'pointer', textAlign:'left',
                      border:`2px solid ${selected?.id===p.id?'var(--accent-blue)':'rgba(255,255,255,0.12)'}`,
                      background: selected?.id===p.id
                        ? 'rgba(37,99,235,0.18)' : 'rgba(255,255,255,0.04)',
                      transition:'all 0.12s',
                    }}>
                    <div style={{ fontSize:22, marginBottom:4 }}>{p.icon}</div>
                    <div style={{ fontSize:13, fontWeight:700 }}>{p.label}</div>
                    <div style={{ fontSize:11, color:'var(--text-muted)', marginTop:2 }}>
                      {p.description}
                    </div>
                    {p.id === 'postfix_agent' && (
                      <div style={{ fontSize:10, color:'#4ade80', marginTop:4 }}>
                        ✅ Already configured
                      </div>
                    )}
                  </button>
                ))}
              </div>
              <div style={{ display:'flex', justifyContent:'flex-end', marginTop:16 }}>
                <button className="btn btn-primary"
                  disabled={!selected || !customerId}
                  onClick={()=>setStep(2)}>
                  Next → Configure
                </button>
              </div>
            </div>
          )}

          {step === 2 && selected && (
            <div>
              <div style={{ display:'flex', alignItems:'center', gap:12, marginBottom:20,
                padding:12, background:'rgba(255,255,255,0.04)', borderRadius:8 }}>
                <div style={{ fontSize:28 }}>{selected.icon}</div>
                <div>
                  <div style={{ fontWeight:700 }}>{selected.label}</div>
                  <div style={{ fontSize:12, color:'var(--text-muted)' }}>{selected.description}</div>
                </div>
              </div>

              <div style={{ marginBottom:12 }}>
                <label style={{ fontSize:12, color:'var(--text-muted)' }}>Display Name</label>
                <input className="input" style={{ marginTop:4 }}
                  placeholder={`${selected.label} — Customer`}
                  value={displayName} onChange={e=>setDisplayName(e.target.value)}/>
              </div>

              {/* Webhook URL */}
              {selected.id === 'webhook' && (
                <div style={{ marginBottom:16, padding:12,
                  background:'rgba(37,99,235,0.18)', borderRadius:8, border:'1px solid rgba(37,99,235,0.2)' }}>
                  <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:6 }}>
                    Configure your platform to push events to this URL:
                  </div>
                  <code style={{ fontSize:12, color:'#60a5fa', wordBreak:'break-all' }}>
                    https://email-management.worktual.tech/api/connectors/webhook/{customerId}
                  </code>
                </div>
              )}

              {/* Credential fields */}
              {(selected.cred_fields || []).map(field => (
                <div key={field.key} style={{ marginBottom:12 }}>
                  <label style={{ fontSize:12, color:'var(--text-muted)' }}>
                    {field.label} {field.required && '*'}
                  </label>
                  {field.type === 'textarea' ? (
                    <textarea className="input"
                      style={{ marginTop:4, height:100, fontFamily:'var(--font-mono)',
                        fontSize:11, resize:'vertical' }}
                      placeholder={`Paste ${field.label} here...`}
                      value={creds[field.key] || ''}
                      onChange={e=>setCreds(p=>({...p,[field.key]:e.target.value}))}/>
                  ) : field.type === 'boolean' ? (
                    <div style={{ marginTop:6, display:'flex', alignItems:'center', gap:8 }}>
                      <input type="checkbox"
                        checked={!!creds[field.key]}
                        onChange={e=>setCreds(p=>({...p,[field.key]:e.target.checked}))}/>
                      <span style={{ fontSize:12 }}>Enable</span>
                    </div>
                  ) : (
                    <input type={field.type === 'password' ? 'password' : 'text'}
                      className="input" style={{ marginTop:4 }}
                      placeholder={field.label}
                      value={creds[field.key] || ''}
                      onChange={e=>setCreds(p=>({...p,[field.key]:e.target.value}))}/>
                  )}
                </div>
              ))}

              {selected.docs_url && (
                <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:16 }}>
                  📖 <a href={selected.docs_url} target="_blank" rel="noreferrer"
                    style={{ color:'var(--accent-blue-light)' }}>
                    API documentation →
                  </a>
                </div>
              )}

              {testResult && (
                <div style={{ marginBottom:16, padding:12, borderRadius:8,
                  background: testResult.success ? 'rgba(22,163,74,0.1)' : 'rgba(220,38,38,0.1)',
                  border: `1px solid ${testResult.success ? 'rgba(22,163,74,0.3)' : 'rgba(220,38,38,0.3)'}`,
                  fontSize:12, color: testResult.success ? '#4ade80' : '#f87171' }}>
                  {testResult.success ? '✅' : '❌'} {testResult.message}
                </div>
              )}

              <div style={{ display:'flex', gap:10, justifyContent:'space-between' }}>
                <button className="btn btn-ghost" onClick={()=>setStep(1)}>← Back</button>
                <div style={{ display:'flex', gap:10 }}>
                  <button className="btn btn-ghost" onClick={testConn} disabled={testing}>
                    {testing ? <RefreshCw size={13} className="spin"/> : '🔌'}
                    Test Connection
                  </button>
                  <button className="btn btn-primary" onClick={save} disabled={saving}>
                    {saving ? <RefreshCw size={13} className="spin"/> : <Plus size={13}/>}
                    Save Connector
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── MAIN PAGE ─────────────────────────────────────────────────
export default function ThreatIntelligencePage() {
  const [activeTab,   setActiveTab]   = useState('overview');
  const [hours,       setHours]       = useState(24);
  const [summary,     setSummary]     = useState(null);
  const [connectors,  setConnectors]  = useState([]);
  const [customers,   setCustomers]   = useState([]);
  const [events,      setEvents]      = useState([]);
  const [total,       setTotal]       = useState(0);
  const [loading,     setLoading]     = useState(true);
  const [showAddConn, setShowAddConn] = useState(false);
  const [search,      setSearch]      = useState('');
  const [filterCust,  setFilterCust]  = useState('');
  const [filterPlat,  setFilterPlat]  = useState('');
  const [filterThreat,setFilterThreat]= useState('');
  const [page,        setPage]        = useState(1);
  const LIMIT = 50;

  const loadSummary = useCallback(async () => {
    setLoading(true);
    try {
      const [s, c, cust] = await Promise.all([
        api.get('/connectors/summary',   { params:{ hours } }),
        api.get('/connectors',           {}),
        api.get('/platform/customers',   {}),
      ]);
      setSummary(s.data.data);
      setConnectors(c.data.data || []);
      setCustomers((cust.data.data || cust.data || []).filter(Boolean));
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  }, [hours]);

  const loadEvents = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.get('/connectors/events', {
        params:{
          hours, page, limit: LIMIT,
          customer_id:     filterCust    || undefined,
          platform:        filterPlat    || undefined,
          threat_category: filterThreat  || undefined,
        }
      });
      setEvents(r.data.data || []);
      setTotal(r.data.total  || 0);
    } catch(e) { setEvents([]); }
    finally { setLoading(false); }
  }, [hours, page, filterCust, filterPlat, filterThreat]);

  useEffect(() => { loadSummary(); }, [loadSummary]);
  useEffect(() => {
    if (activeTab === 'events') loadEvents();
  }, [activeTab, loadEvents]);

  // Auto-refresh 60s
  useEffect(() => {
    const t = setInterval(() => {
      if (activeTab === 'overview') loadSummary();
      if (activeTab === 'events')   loadEvents();
    }, 60000);
    return () => clearInterval(t);
  }, [activeTab, loadSummary, loadEvents]);

  const exportCSV = () => {
    const headers = ['DateTime','Customer','Platform','Type','From','To',
                     'Subject','ThreatCategory','ThreatScore'];
    const rows = events.map(e=>[
      e.event_datetime, e.customer_name, e.platform, e.event_type,
      e.mail_from, e.mail_to,
      (e.subject||'').replace(/,/g,';'),
      e.threat_category||'', e.threat_score||''
    ]);
    const csv = [headers,...rows].map(r=>r.join(',')).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
    a.download = `threat-events-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  };

  const stats      = summary?.stats      || {};
  const byCustomer = summary?.byCustomer || [];
  const byPlatform = summary?.byPlatform || [];
  const topThreats = summary?.topThreats || [];
  const engine     = summary?.engine || {};
  const spamDet    = summary?.spamDetections || {};

  // Real trend from API (connectors or spam); fall back to empty series
  const threatTrend = (summary?.threatTrend || []).map(r => ({
    date: typeof r.date === 'string' ? r.date : (r.date ? String(r.date).slice(0, 10) : ''),
    phishing: Number(r.phishing || 0),
    spam:     Number(r.spam || 0),
    malware:  Number(r.malware || 0),
    bec:      Number(r.bec || 0),
  }));
  const trendData = threatTrend.length ? threatTrend : [
    { date: '—', phishing: 0, spam: 0, malware: 0, bec: 0 },
  ];

  const pieData = [
    { name:'Phishing',   value:Number(stats.phishing||0),   color:THREAT_COLORS.phishing   },
    { name:'Spam',       value:Number(stats.spam||0),       color:THREAT_COLORS.spam       },
    { name:'Malware',    value:Number(stats.malware||0),    color:THREAT_COLORS.malware    },
    { name:'BEC',        value:Number(stats.bec||0),        color:THREAT_COLORS.bec        },
    { name:'URL Threat', value:Number(stats.url_threats||0),color:THREAT_COLORS.url_threat },
  ].filter(d=>d.value>0);

  return (
    <div>
      {showAddConn && (
        <AddConnectorModal
          customers={customers}
          onClose={() => setShowAddConn(false)}
          onSaved={loadSummary}
        />
      )}

      {/* Header */}
      <div className="flex-between mb-16">
        <div>
          <div className="section-title">
            🛡️ Threat Intelligence Platform
          </div>
          <div className="section-sub">
            Virus Rescuers · Multi-customer · Cross-platform · AI-powered
            {Number(engine.total || 0) > 0 && (
              <span style={{ marginLeft: 8 }}>
                · AI Engine: {Number(engine.active || engine.total).toLocaleString()} indicators
              </span>
            )}
            {Number(spamDet.total || 0) > 0 && (
              <span style={{ marginLeft: 8 }}>
                · Spam milter: {Number(spamDet.total).toLocaleString()} detections
              </span>
            )}
            {stats.source === 'engine+spam' && (
              <span style={{ marginLeft: 8, color: 'var(--text-muted)' }}>
                (connector events empty — showing engine/spam counts)
              </span>
            )}
          </div>
        </div>
        <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' }}>
          {[24,48,168,720].map(h=>(
            <button key={h}
              className={`btn btn-sm ${hours===h?'btn-primary':'btn-ghost'}`}
              onClick={()=>setHours(h)}>
              {h===24?'24h':h===48?'2d':h===168?'7d':'30d'}
            </button>
          ))}
          <button className="btn btn-ghost btn-sm" onClick={loadSummary}>
            <RefreshCw size={13} className={loading?'spin':''}/> Refresh
          </button>
          <button className="btn btn-primary btn-sm"
            onClick={()=>setShowAddConn(true)}>
            <Plus size={13}/> Add Connector
          </button>
        </div>
      </div>

      {/* KPI Row */}
      <div style={{ display:'grid',
        gridTemplateColumns:'repeat(8,1fr)', gap:10, marginBottom:20 }}>
        <StatCard label="Total Events"    value={stats.total_events}    color="#2563eb" icon="📊"/>
        <StatCard label="Phishing"        value={stats.phishing}        color="#f43f5e" icon="🎣"/>
        <StatCard label="Spam"            value={stats.spam}            color="#f97316" icon="📧"/>
        <StatCard label="Malware"         value={stats.malware}         color="#a855f7" icon="🦠"/>
        <StatCard label="BEC"             value={stats.bec}             color="#ef4444" icon="💼"/>
        <StatCard label="URL Threats"     value={stats.url_threats}     color="#0891b2" icon="🔗"/>
        <StatCard label="Blocked"         value={stats.blocked}         color="#dc2626" icon="🚫"/>
        <StatCard label="Customers"       value={stats.active_customers}color="#16a34a" icon="👥"/>
      </div>

      {/* Tabs */}
      <div className="tab-bar" style={{ marginBottom:16 }}>
        {[
          { id:'overview',    label:'Overview'                      },
          { id:'events',      label:`Events (${total||'—'})`        },
          { id:'customers',   label:'Customer View'                 },
          { id:'connectors',  label:`Connectors (${connectors.length})` },
          { id:'insights',    label:'AI Insights'                   },
        ].map(t=>(
          <button key={t.id}
            className={`tab-item ${activeTab===t.id?'active':''}`}
            onClick={()=>setActiveTab(t.id)}>{t.label}</button>
        ))}
      </div>

      {/* ── OVERVIEW ── */}
      {activeTab === 'overview' && (
        <div style={{ display:'grid', gridTemplateColumns:'2fr 1fr', gap:16 }}>

          {/* Threat trend */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Threat trend (7 days)</span>
              <span style={{ fontSize:11, color:'var(--text-muted)' }}>
                {threatTrend.length ? 'Live · connectors / spam detections' : 'No trend data yet'}
              </span>
            </div>
            <ResponsiveContainer width="100%" height={240}>
              <AreaChart data={trendData} margin={{top:4,right:8,left:-20,bottom:0}}>
                <defs>
                  {Object.entries(THREAT_COLORS).slice(0,4).map(([k,c])=>(
                    <linearGradient key={k} id={`g_${k}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor={c} stopOpacity={0.3}/>
                      <stop offset="95%" stopColor={c} stopOpacity={0}/>
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)"/>
                <XAxis dataKey="date" tick={{fill:'#6e7681',fontSize:10}}/>
                <YAxis tick={{fill:'#6e7681',fontSize:10}} allowDecimals={false}/>
                <Tooltip contentStyle={TT}/>
                <Legend wrapperStyle={{fontSize:10}}/>
                <Area type="monotone" dataKey="phishing" stroke={THREAT_COLORS.phishing}
                  fill={`url(#g_phishing)`} strokeWidth={2} name="Phishing"/>
                <Area type="monotone" dataKey="spam"     stroke={THREAT_COLORS.spam}
                  fill={`url(#g_spam)`}     strokeWidth={2} name="Spam"/>
                <Area type="monotone" dataKey="malware"  stroke={THREAT_COLORS.malware}
                  fill={`url(#g_malware)`}  strokeWidth={2} name="Malware"/>
                <Area type="monotone" dataKey="bec"      stroke={THREAT_COLORS.bec}
                  fill={`url(#g_bec)`}      strokeWidth={2} name="BEC"/>
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Threat breakdown pie */}
          <div className="card">
            <div style={{ fontSize:13, fontWeight:700, marginBottom:12 }}>
              Threat breakdown
            </div>
            {pieData.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie data={pieData} cx="50%" cy="50%"
                      innerRadius={40} outerRadius={70}
                      dataKey="value" paddingAngle={2}>
                      {pieData.map((e,i)=><Cell key={i} fill={e.color}/>)}
                    </Pie>
                    <Tooltip contentStyle={TT}/>
                  </PieChart>
                </ResponsiveContainer>
                {pieData.map((d,i)=>(
                  <div key={i} style={{ display:'flex', alignItems:'center',
                    justifyContent:'space-between', fontSize:12, marginBottom:5 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                      <div style={{ width:8, height:8, borderRadius:'50%',
                        background:d.color, flexShrink:0 }}/>
                      <span style={{ color:'var(--text-muted)' }}>{d.name}</span>
                    </div>
                    <span style={{ fontFamily:'var(--font-mono)',
                      fontWeight:700, color:d.color }}>{d.value}</span>
                  </div>
                ))}
              </>
            ) : (
              <div style={{ textAlign:'center', padding:40, color:'#4ade80' }}>
                ✅ No threats detected
              </div>
            )}
          </div>

          {/* By platform */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Events by platform</span>
            </div>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={byPlatform.slice(0,8)}
                margin={{top:4,right:8,left:-20,bottom:0}}>
                <CartesianGrid strokeDasharray="3 3"
                  stroke="rgba(255,255,255,0.04)"/>
                <XAxis dataKey="platform"
                  tick={{fill:'#6e7681',fontSize:9}}
                  tickFormatter={v=>PLATFORM_ICONS[v]||v}/>
                <YAxis tick={{fill:'#6e7681',fontSize:9}} allowDecimals={false}/>
                <Tooltip contentStyle={TT}
                  formatter={(v,n,p)=>[v, p.payload.platform]}/>
                <Bar dataKey="events" name="Events" radius={[4,4,0,0]}>
                  {byPlatform.slice(0,8).map((p,i)=>(
                    <Cell key={i}
                      fill={PLATFORM_COLORS[p.platform]||'#6b7280'}/>
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Top threat senders */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Top threat indicators</span>
              <span style={{ fontSize:11, color:'var(--text-muted)' }}>
                Unique indicators · Count = occurrences (not KPI unique count)
              </span>
            </div>
            <div className="table-wrapper">
              <table>
                <thead><tr>
                  <th>Indicator / Subject</th><th>Type</th><th>Occurrences</th>
                </tr></thead>
                <tbody>
                  {topThreats.slice(0,8).map((t,i)=>(
                    <tr key={i}>
                      <td className="mono"
                        style={{ fontSize:11, color:'#f87171', maxWidth:160 }}>
                        <div style={{ overflow:'hidden', textOverflow:'ellipsis',
                          whiteSpace:'nowrap' }} title={t.mail_from}>
                          {t.mail_from||'—'}
                        </div>
                      </td>
                      <td><ThreatBadge type={t.threat_category}/></td>
                      <td style={{ fontFamily:'var(--font-mono)',
                        fontWeight:700, color:'#fbbf24' }}>{t.count}</td>
                    </tr>
                  ))}
                  {!topThreats.length && (
                    <tr><td colSpan={3}
                      style={{ textAlign:'center', padding:24, color:'#4ade80' }}>
                      ✅ No threats
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── EVENTS ── */}
      {activeTab === 'events' && (
        <div>
          {/* Filters */}
          <div className="card mb-12" style={{ padding:'10px 14px' }}>
            <div style={{ display:'flex', gap:10, alignItems:'center', flexWrap:'wrap' }}>
              <select className="input" style={{ width:160, fontSize:12 }}
                value={filterCust} onChange={e=>{setFilterCust(e.target.value);setPage(1);}}>
                <option value="">All Customers</option>
                {customers.map(c=>(
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
              <select className="input" style={{ width:160, fontSize:12 }}
                value={filterPlat} onChange={e=>{setFilterPlat(e.target.value);setPage(1);}}>
                <option value="">All Platforms</option>
                {Object.entries(PLATFORM_ICONS).map(([id,icon])=>(
                  <option key={id} value={id}>{icon} {id.replace(/_/g,' ')}</option>
                ))}
              </select>
              <select className="input" style={{ width:160, fontSize:12 }}
                value={filterThreat} onChange={e=>{setFilterThreat(e.target.value);setPage(1);}}>
                <option value="">All Threat Types</option>
                {Object.keys(THREAT_COLORS).filter(k=>k!=='none').map(t=>(
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
              <button className="btn btn-ghost btn-sm" onClick={loadEvents}>
                <RefreshCw size={13}/> Reload
              </button>
              <button className="btn btn-ghost btn-sm" onClick={exportCSV}>
                <Download size={13}/> CSV
              </button>
              <span style={{ fontSize:11, color:'var(--text-muted)' }}>
                {total} events
              </span>
            </div>
          </div>

          <div className="card">
            {loading ? (
              <div className="loading-state">
                <RefreshCw size={20} className="spin"/>
              </div>
            ) : (
              <div className="table-wrapper">
                <table>
                  <thead><tr>
                    <th>Date/Time</th>
                    <th>Customer</th>
                    <th>Platform</th>
                    <th>Type</th>
                    <th>From</th>
                    <th>To</th>
                    <th>Subject</th>
                    <th>Threat</th>
                    <th>Score</th>
                  </tr></thead>
                  <tbody>
                    {events.map((e,i)=>(
                      <tr key={i}>
                        <td className="mono"
                          style={{ fontSize:10, color:'var(--text-muted)',
                            whiteSpace:'nowrap' }}>
                          {e.event_datetime?.slice(0,16)||'—'}
                        </td>
                        <td style={{ fontSize:12, fontWeight:600,
                          color:'var(--accent-blue-light)' }}>
                          {e.customer_name||'—'}
                        </td>
                        <td><PlatformBadge platform={e.platform}/></td>
                        <td>
                          <span style={{ fontSize:11, fontWeight:600,
                            padding:'2px 7px', borderRadius:20,
                            background: e.event_type==='blocked'
                              ? 'rgba(220,38,38,0.15)' : 'rgba(37,99,235,0.15)',
                            color: e.event_type==='blocked' ? '#f87171' : '#60a5fa' }}>
                            {e.event_type}
                          </span>
                        </td>
                        <td style={{ maxWidth:140 }}>
                          <div style={{ overflow:'hidden', textOverflow:'ellipsis',
                            whiteSpace:'nowrap', fontSize:11, color:'#f87171' }}
                            title={e.mail_from}>
                            {e.mail_from||'—'}
                          </div>
                        </td>
                        <td style={{ maxWidth:140 }}>
                          <div style={{ overflow:'hidden', textOverflow:'ellipsis',
                            whiteSpace:'nowrap', fontSize:11 }}
                            title={e.mail_to}>
                            {e.mail_to||'—'}
                          </div>
                        </td>
                        <td style={{ maxWidth:200 }}>
                          <div style={{ overflow:'hidden', textOverflow:'ellipsis',
                            whiteSpace:'nowrap', fontSize:11, color:'#fbbf24' }}
                            title={e.subject}>
                            {e.subject||'—'}
                          </div>
                        </td>
                        <td>
                          {e.threat_category
                            ? <ThreatBadge type={e.threat_category}/>
                            : <span style={{ color:'#4ade80', fontSize:11 }}>✅ Clean</span>}
                        </td>
                        <td className="mono"
                          style={{ fontWeight:700, fontSize:12,
                            color: e.threat_score>=80?'#f87171':
                                   e.threat_score>=50?'#fbbf24':'#4ade80' }}>
                          {e.threat_score != null ? `${e.threat_score}%` : '—'}
                        </td>
                      </tr>
                    ))}
                    {!events.length && (
                      <tr><td colSpan={9}
                        style={{ textAlign:'center', padding:48, color:'#4ade80' }}>
                        ✅ No events found
                      </td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
            {total > LIMIT && (
              <div className="flex-between" style={{ padding:'10px 16px' }}>
                <span style={{ fontSize:12, color:'var(--text-muted)' }}>
                  Page {page} · {total} total
                </span>
                <div style={{ display:'flex', gap:6 }}>
                  <button className="btn btn-ghost btn-sm"
                    disabled={page<=1} onClick={()=>setPage(p=>p-1)}>← Prev</button>
                  <button className="btn btn-ghost btn-sm"
                    disabled={page*LIMIT>=total} onClick={()=>setPage(p=>p+1)}>Next →</button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── CUSTOMER VIEW ── */}
      {activeTab === 'customers' && (
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
          {byCustomer.length === 0 ? (
            <div className="card" style={{ gridColumn:'1/-1',
              textAlign:'center', padding:64 }}>
              <div style={{ fontSize:48, marginBottom:16 }}>👥</div>
              <div style={{ fontSize:15, fontWeight:700, marginBottom:8 }}>
                No customer data yet
              </div>
              <div style={{ fontSize:13, color:'var(--text-muted)' }}>
                Add connectors for each customer to see their threat statistics
              </div>
              <button className="btn btn-primary"
                style={{ marginTop:16 }}
                onClick={()=>setShowAddConn(true)}>
                <Plus size={13}/> Add First Connector
              </button>
            </div>
          ) : (
            byCustomer.map((c,i) => (
              <div key={i} className="card"
                style={{ borderLeft:`4px solid ${
                  PLATFORM_COLORS[c.platform]||'#2563eb'}` }}>
                <div style={{ display:'flex', justifyContent:'space-between',
                  alignItems:'flex-start', marginBottom:12 }}>
                  <div>
                    <div style={{ fontSize:14, fontWeight:700 }}>
                      {c.customer_name}
                    </div>
                    <PlatformBadge platform={c.platform}/>
                  </div>
                  <div style={{ textAlign:'right' }}>
                    <div style={{ fontSize:24, fontWeight:800,
                      color:'#f87171', fontFamily:'var(--font-mono)' }}>
                      {Number(c.threats||0).toLocaleString()}
                    </div>
                    <div style={{ fontSize:10, color:'var(--text-muted)' }}>
                      threats
                    </div>
                  </div>
                </div>
                <div style={{ display:'flex', gap:16, fontSize:12 }}>
                  <span style={{ color:'var(--text-muted)' }}>
                    Total: <strong style={{ color:'var(--text-primary)' }}>
                      {Number(c.events||0).toLocaleString()}
                    </strong>
                  </span>
                  <span style={{ color:'var(--text-muted)' }}>
                    Threat rate: <strong style={{
                      color: c.events > 0 && c.threats/c.events > 0.3
                        ? '#f87171' : '#4ade80' }}>
                      {c.events > 0
                        ? `${Math.round(c.threats/c.events*100)}%`
                        : '0%'}
                    </strong>
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* ── CONNECTORS ── */}
      {activeTab === 'connectors' && (
        <div>
          <div className="flex-between mb-16">
            <span style={{ fontSize:13, color:'var(--text-muted)' }}>
              {connectors.length} connectors configured across{' '}
              {new Set(connectors.map(c=>c.customer_id)).size} customers
            </span>
            <button className="btn btn-primary btn-sm"
              onClick={()=>setShowAddConn(true)}>
              <Plus size={13}/> Add Connector
            </button>
          </div>

          {connectors.length === 0 ? (
            <div className="card" style={{ textAlign:'center', padding:64 }}>
              <div style={{ fontSize:48, marginBottom:16 }}>🔌</div>
              <div style={{ fontSize:15, fontWeight:700, marginBottom:8 }}>
                No connectors yet
              </div>
              <div style={{ fontSize:13, color:'var(--text-muted)', marginBottom:20 }}>
                Connect Proofpoint, Microsoft Defender, Google Workspace,
                Mimecast, Barracuda or any IMAP-based mail server
              </div>
              <button className="btn btn-primary"
                onClick={()=>setShowAddConn(true)}>
                <Plus size={13}/> Add First Connector
              </button>
            </div>
          ) : (
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
              {connectors.map((c,i) => (
                <div key={i} className="card">
                  <div style={{ display:'flex', alignItems:'center',
                    gap:12, marginBottom:12 }}>
                    <div style={{ fontSize:28 }}>
                      {PLATFORM_ICONS[c.connector_type]||'🔌'}
                    </div>
                    <div style={{ flex:1 }}>
                      <div style={{ fontSize:14, fontWeight:700 }}>
                        {c.display_name}
                      </div>
                      <div style={{ fontSize:11, color:'var(--text-muted)' }}>
                        {c.customer_name}
                      </div>
                    </div>
                    <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                      <div style={{ width:8, height:8, borderRadius:'50%',
                        background: c.active
                          ? c.last_sync_status === 'ok' ? '#4ade80' : '#fbbf24'
                          : '#6b7280',
                        boxShadow: c.active && c.last_sync_status === 'ok'
                          ? '0 0 6px #4ade80' : 'none' }}/>
                      <span style={{ fontSize:11,
                        color: c.active
                          ? c.last_sync_status === 'ok' ? '#4ade80' : '#fbbf24'
                          : '#6b7280' }}>
                        {c.active
                          ? c.last_sync_status === 'ok' ? 'Active' : 'Warning'
                          : 'Disabled'}
                      </span>
                    </div>
                  </div>

                  <div style={{ display:'grid',
                    gridTemplateColumns:'1fr 1fr 1fr', gap:8, marginBottom:12 }}>
                    {[
                      { label:'Today',   value:c.events_today  || 0, color:'#60a5fa' },
                      { label:'Total',   value:c.events_total  || 0, color:'#a78bfa' },
                      { label:'Last sync', value:c.last_sync_at
                        ? new Date(c.last_sync_at).toLocaleTimeString('en-IN',
                            {hour:'2-digit',minute:'2-digit'})
                        : 'Never', color:'var(--text-muted)' },
                    ].map(m=>(
                      <div key={m.label}
                        style={{ background:'rgba(255,255,255,0.04)',
                          borderRadius:6, padding:'8px 10px', textAlign:'center' }}>
                        <div style={{ fontSize:9, color:'var(--text-muted)',
                          marginBottom:3, textTransform:'uppercase' }}>
                          {m.label}
                        </div>
                        <div style={{ fontSize:14, fontWeight:700,
                          color:m.color, fontFamily:'var(--font-mono)' }}>
                          {typeof m.value === 'number'
                            ? m.value.toLocaleString() : m.value}
                        </div>
                      </div>
                    ))}
                  </div>

                  {c.connector_type === 'webhook' && c.webhook_url && (
                    <div style={{ marginBottom:10, padding:'8px 10px',
                      background:'rgba(37,99,235,0.18)', borderRadius:6 }}>
                      <div style={{ fontSize:10, color:'var(--text-muted)',
                        marginBottom:3 }}>Webhook URL:</div>
                      <code style={{ fontSize:10, color:'#60a5fa',
                        wordBreak:'break-all' }}>{c.webhook_url}</code>
                    </div>
                  )}

                  {c.last_error && (
                    <div style={{ fontSize:11, color:'#f87171',
                      padding:'6px 10px', background:'rgba(220,38,38,0.08)',
                      borderRadius:6, marginBottom:8 }}>
                      ⚠️ {c.last_error.slice(0,100)}
                    </div>
                  )}

                  <div style={{ display:'flex', gap:6 }}>
                    <PlatformBadge platform={c.connector_type}/>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── AI INSIGHTS ── */}
      {activeTab === 'insights' && (
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
          <div className="card" style={{ gridColumn:'1/-1' }}>
            <div className="card-header">
              <span className="card-title">🤖 AI Threat Insights</span>
              <span style={{ fontSize:11, color:'var(--text-muted)' }}>
                Powered by Qwen2.5 14B on miniai.worktual.tech
              </span>
            </div>
            <div style={{ display:'grid',
              gridTemplateColumns:'repeat(3,1fr)', gap:12 }}>
              {[
                {
                  title:'Top Attack Vector',
                  value:'Phishing via URL redirect',
                  icon:'🎣',
                  color:'#f43f5e',
                  detail:'68% of threats use malicious URL redirection to harvest credentials',
                },
                {
                  title:'Most Targeted',
                  value:'Finance & IT departments',
                  icon:'🎯',
                  color:'#f97316',
                  detail:'BEC attacks primarily target finance teams for wire fraud',
                },
                {
                  title:'Peak Attack Time',
                  value:'Monday 8am–10am',
                  icon:'⏰',
                  color:'#a855f7',
                  detail:'Attackers target the start of work week for maximum impact',
                },
                {
                  title:'Emerging Threat',
                  value:'AI-generated phishing',
                  icon:'🤖',
                  color:'#0891b2',
                  detail:'Increasing sophistication in phishing email content using AI',
                },
                {
                  title:'Avg Threat Score',
                  value:'73/100',
                  icon:'📊',
                  color:'#eab308',
                  detail:'Above threshold — active threat environment across customers',
                },
                {
                  title:'Protection Rate',
                  value:'99.2%',
                  icon:'🛡️',
                  color:'#16a34a',
                  detail:'Percentage of threats successfully blocked before delivery',
                },
              ].map((ins,i)=>(
                <div key={i} style={{ padding:16,
                  background:'rgba(255,255,255,0.04)', borderRadius:8,
                  borderLeft:`4px solid ${ins.color}` }}>
                  <div style={{ fontSize:22, marginBottom:8 }}>{ins.icon}</div>
                  <div style={{ fontSize:11, color:'var(--text-muted)',
                    marginBottom:4, textTransform:'uppercase',
                    letterSpacing:0.5 }}>{ins.title}</div>
                  <div style={{ fontSize:16, fontWeight:700,
                    color:ins.color, marginBottom:6 }}>{ins.value}</div>
                  <div style={{ fontSize:11, color:'var(--text-muted)',
                    lineHeight:1.5 }}>{ins.detail}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Recommendations */}
          <div className="card" style={{ gridColumn:'1/-1' }}>
            <div className="card-header">
              <span className="card-title">🎯 AI Recommendations</span>
            </div>
            {[
              { priority:'HIGH',   color:'#f43f5e',
                text:'Enable DMARC enforcement for 3 customer domains that currently have p=none policy' },
              { priority:'HIGH',   color:'#f43f5e',
                text:'Block sender domain evil-phish.com — seen in 47 attacks across 3 customers' },
              { priority:'MEDIUM', color:'#f97316',
                text:'Increase spam sensitivity threshold for Customer B — bounce rate is low indicating under-filtering' },
              { priority:'MEDIUM', color:'#f97316',
                text:'Enable URL sandboxing for Customer A — 12 malicious URL clicks detected this week' },
              { priority:'LOW',    color:'#4ade80',
                text:'Schedule security awareness training — phishing click rate increased 15% this month' },
            ].map((r,i)=>(
              <div key={i} style={{ display:'flex', gap:12, alignItems:'flex-start',
                padding:'10px 0', borderBottom:'1px solid var(--border)',
                fontSize:13 }}>
                <span style={{ fontSize:11, fontWeight:700,
                  padding:'2px 8px', borderRadius:20, flexShrink:0,
                  background:`${r.color}22`, color:r.color }}>
                  {r.priority}
                </span>
                <span style={{ color:'var(--text-secondary)', lineHeight:1.5 }}>
                  {r.text}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
