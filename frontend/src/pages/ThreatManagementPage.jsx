import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Shield, AlertTriangle, Ban, Search,
         Download, CheckCircle, XCircle, Filter, Eye } from 'lucide-react';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const TT = { background:'#0d1117', border:'1px solid #2d3748', borderRadius:8, fontSize:12 };

const SEVERITY_STYLE = {
  critical: { bg:'rgba(220,38,38,0.15)',  color:'#f87171',  label:'Critical' },
  high:     { bg:'rgba(234,88,12,0.15)',  color:'#fb923c',  label:'High'     },
  medium:   { bg:'rgba(217,119,6,0.15)', color:'#fbbf24',  label:'Medium'   },
  low:      { bg:'rgba(22,163,74,0.15)', color:'#4ade80',  label:'Low'      },
};

const THREAT_COLORS = {
  spam:          '#f97316',
  phishing:      '#f43f5e',
  malware:       '#a855f7',
  bec:           '#ef4444',
  url_threat:    '#0891b2',
  impersonation: '#be185d',
  unknown:       '#6b7280',
};

const TYPE_ICONS = {
  email:           '✉',
  domain:          '🌐',
  ip:              '🖧',
  url:             '🔗',
  subject_pattern: '📋',
  hash:            '#',
};

function SeverityBadge({ severity }) {
  const s = SEVERITY_STYLE[severity] || SEVERITY_STYLE.low;
  return (
    <span style={{ padding:'2px 8px', borderRadius:20, fontSize:11, fontWeight:700,
      background:s.bg, color:s.color }}>{s.label}</span>
  );
}

function ThreatBadge({ type }) {
  const color = THREAT_COLORS[type] || '#6b7280';
  return (
    <span style={{ padding:'2px 8px', borderRadius:20, fontSize:11, fontWeight:700,
      background:`${color}22`, color }}>{type}</span>
  );
}

export default function ThreatManagementPage({ server }) {
  const [summary,    setSummary]    = useState(null);
  const [indicators, setIndicators] = useState([]);
  const [trend,      setTrend]      = useState([]);
  const [top,        setTop]        = useState([]);
  const [engineStatus, setEngineStatus] = useState(null);
  const [loading,    setLoading]    = useState(true);
  const [activeTab,  setActiveTab]  = useState('overview');
  const [filters,    setFilters]    = useState({ type:'', threat_type:'', severity:'', search:'' });
  const [page,       setPage]       = useState(1);
  const [total,      setTotal]      = useState(0);
  const [selected,   setSelected]   = useState(null);
  const LIMIT = 50;

  const loadSummary = useCallback(async () => {
    try {
      const [s, tr, tp, es] = await Promise.all([
        api.get('/threats/summary', { params: { server: server || 'all' } }),
        api.get('/threats/trend', { params:{ days:30, server: server || 'all' } }),
        api.get('/threats/top',   { params:{ limit:10, server: server || 'all' } }),
        api.get('/threats/engine-status'),
      ]);
      setSummary(s.data.data);
      setTrend((tr.data.data||[]).map(r => ({
        ...r,
        spam: Number(r.spam||0), phishing: Number(r.phishing||0),
        malware: Number(r.malware||0), bec: Number(r.bec||0),
        url_threat: Number(r.url_threat||0), total: Number(r.total||0),
      })));
      setTop(tp.data.data||[]);
      setEngineStatus(es.data);
    } catch(e) { console.error(e); }
  }, [server]);

  const loadIndicators = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.get('/threats/indicators', { params:{
        ...filters, page, limit: LIMIT,
        server: server || 'all',
        search: filters.search || undefined,
        type: filters.type || undefined,
        threat_type: filters.threat_type || undefined,
        severity: filters.severity || undefined,
      }});
      setIndicators(r.data.data||[]);
      setTotal(r.data.total||0);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  }, [filters, page, server]);

  useEffect(() => { loadSummary(); }, [loadSummary]);
  useEffect(() => { if (activeTab === 'indicators') loadIndicators(); }, [activeTab, loadIndicators]);

  const updateStatus = async (id, status, notes='') => {
    try {
      await api.put(`/threats/indicators/${id}`, { status, notes });
      loadIndicators();
      loadSummary();
      setSelected(null);
    } catch(e) { alert(e.message); }
  };

  const exportCSV = () => {
    const headers = ['type','value','threat_type','confidence','severity','occurrences','first_seen','last_seen','explanation'];
    const rows = indicators.map(i => [
      i.indicator_type, i.indicator_value, i.threat_type,
      i.confidence, i.severity, i.occurrence_count,
      i.first_seen_at, i.last_seen_at,
      (i.ai_explanation||'').replace(/,/g,';')
    ]);
    const csv = [headers,...rows].map(r=>r.join(',')).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
    a.download = `threat-indicators-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  };

  const ind = summary?.indicators || {};
  const pieData = [
    { name:'Spam',          value:Number(ind.spam||0),          color:THREAT_COLORS.spam },
    { name:'Phishing',      value:Number(ind.phishing||0),      color:THREAT_COLORS.phishing },
    { name:'Malware',       value:Number(ind.malware||0),       color:THREAT_COLORS.malware },
    { name:'BEC',           value:Number(ind.bec||0),           color:THREAT_COLORS.bec },
    { name:'URL Threat',    value:Number(ind.url_threat||0),    color:THREAT_COLORS.url_threat },
  ].filter(d => d.value > 0);

  const lastRun = summary?.last_run;

  return (
    <div>
      {/* Header */}
      <div className="flex-between mb-16">
        <div>
          <div className="section-title">Threat Management</div>
          <div className="section-sub">
            AI-powered threat intelligence · {Number(ind.total||0).toLocaleString()} total indicators
            {lastRun && <span style={{marginLeft:10}}>· Last scan: {new Date(lastRun.started_at).toLocaleTimeString('en-IN')}</span>}
          </div>
        </div>
        <div style={{display:'flex',gap:8}}>
          <button className="btn btn-ghost btn-sm" onClick={loadSummary}>
            <RefreshCw size={13}/> Refresh
          </button>
        </div>
      </div>

      {/* KPI row */}
      <div style={{display:'grid',gridTemplateColumns:'repeat(6,1fr)',gap:12,marginBottom:20}}>
        {[
          { label:'Total Indicators', value:ind.total,    color:'#2563eb' },
          { label:'Active',           value:ind.active,   color:'#dc2626' },
          { label:'Critical',         value:ind.critical, color:'#f87171' },
          { label:'High',             value:ind.high,     color:'#fb923c' },
          { label:'Last 24h',         value:ind.last_24h, color:'#a855f7' },
          { label:'Blocklisted',      value:summary?.blocklist?.total, color:'#ef4444' },
        ].map(k => (
          <div key={k.label} className="card" style={{borderTop:`3px solid ${k.color}`,padding:'14px 16px'}}>
            <div style={{fontSize:11,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:0.5,marginBottom:6}}>{k.label}</div>
            <div style={{fontSize:24,fontWeight:800,color:k.color,fontFamily:'var(--font-mono)'}}>{Number(k.value||0).toLocaleString()}</div>
          </div>
        ))}
      </div>

      {/* Engine status */}
      {engineStatus && (
        <div style={{
          background: lastRun?.status==='done' ? 'rgba(22,163,74,0.08)' : 'rgba(217,119,6,0.08)',
          border: `1px solid ${lastRun?.status==='done' ? 'rgba(22,163,74,0.25)' : 'rgba(217,119,6,0.25)'}`,
          borderRadius:8, padding:'10px 16px', marginBottom:16,
          display:'flex', alignItems:'center', gap:16, fontSize:13
        }}>
          <div style={{display:'flex',alignItems:'center',gap:6}}>
            <div style={{width:8,height:8,borderRadius:'50%',
              background:lastRun?.status==='done'?'#4ade80':'#fbbf24',
              boxShadow:lastRun?.status==='done'?'0 0 6px #4ade80':'none'}}/>
            <strong>AI Engine</strong>
          </div>
          {lastRun && <>
            <span style={{color:'var(--text-muted)'}}>Last run: {new Date(lastRun.started_at).toLocaleString('en-IN')}</span>
            <span style={{color:'var(--text-muted)'}}>Scanned: <strong style={{color:'var(--text-primary)'}}>{lastRun.logs_scanned}</strong></span>
            <span style={{color:'var(--text-muted)'}}>New indicators: <strong style={{color:'#4ade80'}}>{lastRun.new_indicators}</strong></span>
          </>}
          <span style={{marginLeft:'auto',fontSize:11,color:'var(--text-muted)'}}>
            Running on miniai.worktual.tech · llama3.1:8b
          </span>
        </div>
      )}

      {/* Tabs */}
      <div className="tab-bar" style={{marginBottom:16}}>
        {[
          {id:'overview',    label:'Overview'},
          {id:'indicators',  label:`Indicators (${Number(ind.total||0).toLocaleString()})`},
          {id:'blocklist',   label:`Blocklist (${Number(summary?.blocklist?.total||0)})`},
          {id:'engine',      label:'Engine Runs'},
        ].map(t => (
          <button key={t.id} className={`tab-item ${activeTab===t.id?'active':''}`}
            onClick={()=>setActiveTab(t.id)}>{t.label}</button>
        ))}
      </div>

      {/* ── OVERVIEW ── */}
      {activeTab === 'overview' && (
        <div style={{display:'grid',gridTemplateColumns:'1fr 300px',gap:16}}>
          <div className="card">
            <div className="card-header"><span className="card-title">Threat trend (30 days)</span></div>
            <ResponsiveContainer width="100%" height={260}>
              <LineChart data={trend} margin={{top:4,right:8,left:-20,bottom:0}}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)"/>
                <XAxis dataKey="date" tick={{fill:'#6e7681',fontSize:10}}
                  tickFormatter={v=>v?.slice(5)||''}/>
                <YAxis tick={{fill:'#6e7681',fontSize:10}} domain={[0,'auto']} allowDecimals={false}/>
                <Tooltip contentStyle={TT}/>
                <Legend wrapperStyle={{fontSize:11}}/>
                {Object.entries(THREAT_COLORS).slice(0,5).map(([k,c])=>(
                  <Line key={k} type="monotone" dataKey={k} stroke={c}
                    strokeWidth={1.5} dot={false} name={k}/>
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>

          <div className="card">
            <div style={{fontSize:13,fontWeight:700,marginBottom:12}}>Threat breakdown</div>
            {pieData.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70}
                      dataKey="value" paddingAngle={2}>
                      {pieData.map((e,i)=><Cell key={i} fill={e.color}/>)}
                    </Pie>
                    <Tooltip contentStyle={TT}/>
                  </PieChart>
                </ResponsiveContainer>
                {pieData.map((d,i)=>(
                  <div key={i} style={{display:'flex',alignItems:'center',justifyContent:'space-between',fontSize:12,marginBottom:4}}>
                    <div style={{display:'flex',alignItems:'center',gap:6}}>
                      <div style={{width:8,height:8,borderRadius:'50%',background:d.color}}/>
                      <span style={{color:'var(--text-muted)'}}>{d.name}</span>
                    </div>
                    <span style={{fontFamily:'var(--font-mono)',fontWeight:700,color:d.color}}>{d.value}</span>
                  </div>
                ))}
              </>
            ) : (
              <div style={{textAlign:'center',padding:40,color:'var(--text-muted)'}}>
                No threat data yet — engine is learning
              </div>
            )}
          </div>

          {/* Top threats */}
          <div className="card" style={{gridColumn:'1/-1'}}>
            <div className="card-header"><span className="card-title">Top threat indicators</span></div>
            <div className="table-wrapper">
              <table>
                <thead><tr>
                  <th>Type</th><th>Indicator</th><th>Threat</th>
                  <th>Confidence</th><th>Severity</th><th>Occurrences</th>
                  <th>Last Seen</th><th>Explanation</th>
                </tr></thead>
                <tbody>
                  {top.map((r,i)=>(
                    <tr key={i}>
                      <td><span style={{fontSize:16}}>{TYPE_ICONS[r.indicator_type]||'?'}</span>
                        <span style={{fontSize:11,marginLeft:4,color:'var(--text-muted)'}}>{r.indicator_type}</span></td>
                      <td style={{maxWidth:200}}><div className="truncate" style={{fontSize:12,fontFamily:'var(--font-mono)'}} title={r.indicator_value}>{r.indicator_value}</div></td>
                      <td><ThreatBadge type={r.threat_type}/></td>
                      <td><span style={{fontFamily:'var(--font-mono)',fontWeight:700,
                        color:r.confidence>=80?'#f87171':r.confidence>=60?'#fbbf24':'#4ade80'}}>
                        {r.confidence}%</span></td>
                      <td><SeverityBadge severity={r.severity}/></td>
                      <td style={{fontFamily:'var(--font-mono)',fontSize:12}}>{Number(r.occurrence_count).toLocaleString()}</td>
                      <td style={{fontSize:11,color:'var(--text-muted)'}}>{r.last_seen_at?.slice(0,16)}</td>
                      <td style={{fontSize:11,color:'var(--text-muted)',maxWidth:200}}><div className="truncate" title={r.ai_explanation}>{r.ai_explanation||'—'}</div></td>
                    </tr>
                  ))}
                  {top.length===0&&<tr><td colSpan={8} style={{textAlign:'center',padding:32,color:'var(--text-muted)'}}>No indicators yet — engine processing logs</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── INDICATORS ── */}
      {activeTab === 'indicators' && (
        <div>
          <div className="card mb-16" style={{padding:'12px 16px'}}>
            <div style={{display:'flex',gap:10,flexWrap:'wrap',alignItems:'center'}}>
              <div style={{position:'relative',flex:1,minWidth:200}}>
                <Search size={13} style={{position:'absolute',left:10,top:'50%',transform:'translateY(-50%)',color:'var(--text-muted)'}}/>
                <input className="input" style={{paddingLeft:30,fontSize:12}}
                  placeholder="Search indicator value..."
                  value={filters.search}
                  onChange={e=>setFilters(f=>({...f,search:e.target.value}))}/>
              </div>
              {[
                {key:'type',       label:'Type',       opts:['email','domain','ip','url','subject_pattern']},
                {key:'threat_type',label:'Threat',     opts:['spam','phishing','malware','bec','url_threat','impersonation','unknown']},
                {key:'severity',   label:'Severity',   opts:['low','medium','high','critical']},
              ].map(f=>(
                <select key={f.key} className="input" style={{width:130,fontSize:12}}
                  value={filters[f.key]}
                  onChange={e=>setFilters(p=>({...p,[f.key]:e.target.value}))}>
                  <option value="">All {f.label}</option>
                  {f.opts.map(o=><option key={o} value={o}>{o}</option>)}
                </select>
              ))}
              <button className="btn btn-ghost btn-sm" onClick={()=>setFilters({type:'',threat_type:'',severity:'',search:''})}>Clear</button>
              <button className="btn btn-ghost btn-sm" onClick={exportCSV}><Download size={13}/> CSV</button>
            </div>
          </div>

          <div className="card">
            {loading ? <div className="loading-state"><RefreshCw size={18} className="spin"/></div> : (
              <div className="table-wrapper">
                <table>
                  <thead><tr>
                    <th>Type</th><th>Indicator</th><th>Threat</th>
                    <th>Confidence</th><th>Severity</th><th>Occurrences</th>
                    <th>Status</th><th>Last Seen</th><th>Action</th>
                  </tr></thead>
                  <tbody>
                    {indicators.map((r,i)=>(
                      <tr key={i} style={{cursor:'pointer',background:selected?.id===r.id?'rgba(37,99,235,0.06)':undefined}}
                        onClick={()=>setSelected(selected?.id===r.id?null:r)}>
                        <td>
                          <span style={{fontSize:16}}>{TYPE_ICONS[r.indicator_type]||'?'}</span>
                          <span style={{fontSize:11,marginLeft:4,color:'var(--text-muted)'}}>{r.indicator_type}</span>
                        </td>
                        <td style={{maxWidth:220}}>
                          <div className="truncate" style={{fontSize:12,fontFamily:'var(--font-mono)'}} title={r.indicator_value}>
                            {r.indicator_value}
                          </div>
                        </td>
                        <td><ThreatBadge type={r.threat_type}/></td>
                        <td><span style={{fontFamily:'var(--font-mono)',fontWeight:700,fontSize:13,
                          color:r.confidence>=80?'#f87171':r.confidence>=60?'#fbbf24':'#4ade80'}}>
                          {r.confidence}%</span></td>
                        <td><SeverityBadge severity={r.severity}/></td>
                        <td style={{fontFamily:'var(--font-mono)',fontSize:12}}>{Number(r.occurrence_count).toLocaleString()}</td>
                        <td>
                          <span style={{fontSize:11,fontWeight:600,padding:'2px 8px',borderRadius:20,
                            background:r.status==='active'?'rgba(220,38,38,0.15)':
                                       r.status==='false_positive'?'rgba(22,163,74,0.15)':'rgba(107,114,128,0.15)',
                            color:r.status==='active'?'#f87171':r.status==='false_positive'?'#4ade80':'#9ca3af'}}>
                            {r.status}
                          </span>
                        </td>
                        <td style={{fontSize:11,color:'var(--text-muted)'}}>{r.last_seen_at?.slice(0,16)}</td>
                        <td onClick={e=>e.stopPropagation()}>
                          <div style={{display:'flex',gap:4}}>
                            <button className="btn btn-ghost btn-sm" style={{padding:'2px 8px',fontSize:11}}
                              onClick={()=>updateStatus(r.id,'false_positive','Marked by admin')}
                              title="Mark false positive">FP</button>
                            <button className="btn btn-danger btn-sm" style={{padding:'2px 8px',fontSize:11}}
                              onClick={()=>updateStatus(r.id,'retired')}
                              title="Retire">✕</button>
                          </div>
                        </td>
                      </tr>
                    ))}
                    {indicators.length===0&&!loading&&(
                      <tr><td colSpan={9} style={{textAlign:'center',padding:40,color:'var(--text-muted)'}}>
                        No indicators found
                      </td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
            {/* Expanded detail */}
            {selected && (
              <div style={{margin:'0 16px 16px',background:'var(--bg-primary)',borderRadius:8,padding:16}}>
                <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:'8px 16px',fontSize:12}}>
                  <div><span style={{color:'var(--text-muted)'}}>Full value:</span><br/>
                    <span style={{fontFamily:'var(--font-mono)',wordBreak:'break-all'}}>{selected.indicator_value}</span></div>
                  <div><span style={{color:'var(--text-muted)'}}>Customers affected:</span><br/>
                    <strong>{selected.customer_count}</strong></div>
                  <div><span style={{color:'var(--text-muted)'}}>First seen:</span><br/>
                    <span className="mono">{selected.first_seen_at?.slice(0,16)}</span></div>
                  <div><span style={{color:'var(--text-muted)'}}>AI explanation:</span><br/>
                    <span style={{color:'#fbbf24'}}>{selected.ai_explanation||'—'}</span></div>
                </div>
              </div>
            )}
            {/* Pagination */}
            {total > LIMIT && (
              <div className="flex-between" style={{padding:'10px 16px'}}>
                <span style={{fontSize:12,color:'var(--text-muted)'}}>Page {page} · {total.toLocaleString()} total</span>
                <div style={{display:'flex',gap:6}}>
                  <button className="btn btn-ghost btn-sm" disabled={page<=1} onClick={()=>setPage(p=>p-1)}>← Prev</button>
                  <button className="btn btn-ghost btn-sm" disabled={page*LIMIT>=total} onClick={()=>setPage(p=>p+1)}>Next →</button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── BLOCKLIST ── */}
      {activeTab === 'blocklist' && (
        <BlocklistTab/>
      )}

      {/* ── ENGINE RUNS ── */}
      {activeTab === 'engine' && (
        <EngineRunsTab status={engineStatus}/>
      )}
    </div>
  );
}

function BlocklistTab() {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(()=>{
    api.get('/threats/v1/blocklist').then(r=>setData(r.data.data||[])).catch(()=>{}).finally(()=>setLoading(false));
  },[]);

  const exportPostfix = async () => {
    const r = await api.get('/threats/v1/blocklist', { params:{ format:'postfix' } });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([r.data],{type:'text/plain'}));
    a.download = 'worktual-threat-blocklist.txt';
    a.click();
  };

  return (
    <div>
      <div className="flex-between mb-16">
        <div style={{fontSize:13,color:'var(--text-muted)'}}>{data.length} active blocklist entries</div>
        <button className="btn btn-ghost btn-sm" onClick={exportPostfix}>
          <Download size={13}/> Export for Postfix
        </button>
      </div>
      <div className="card">
        {loading ? <div className="loading-state"><RefreshCw size={16} className="spin"/></div> : (
          <div className="table-wrapper">
            <table>
              <thead><tr>
                <th>Block Type</th><th>Value</th><th>Threat Type</th><th>Confidence</th>
              </tr></thead>
              <tbody>
                {data.map((r,i)=>(
                  <tr key={i}>
                    <td><span style={{fontSize:11,fontWeight:600,padding:'2px 8px',borderRadius:20,
                      background:'rgba(220,38,38,0.15)',color:'#f87171'}}>{r.block_type}</span></td>
                    <td style={{fontFamily:'var(--font-mono)',fontSize:12}}>{r.block_value}</td>
                    <td><ThreatBadge type={r.threat_type}/></td>
                    <td><span style={{fontFamily:'var(--font-mono)',fontWeight:700,
                      color:r.confidence>=80?'#f87171':'#fbbf24'}}>{r.confidence}%</span></td>
                  </tr>
                ))}
                {data.length===0&&<tr><td colSpan={4} style={{textAlign:'center',padding:40,color:'#4ade80'}}>✅ No active blocklist entries yet</td></tr>}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function EngineRunsTab({ status }) {
  const runs = status?.recent_runs || [];
  const q    = status?.queue || {};
  return (
    <div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12,marginBottom:20}}>
        {[
          {label:'Queue Total',  value:q.total,      color:'#2563eb'},
          {label:'Pending',      value:q.pending,    color:'#d97706'},
          {label:'Processed',    value:q.done,       color:'#16a34a'},
          {label:'Failed',       value:q.failed,     color:'#dc2626'},
        ].map(k=>(
          <div key={k.label} className="card" style={{padding:'14px 16px',borderTop:`3px solid ${k.color}`}}>
            <div style={{fontSize:11,color:'var(--text-muted)',marginBottom:6}}>{k.label}</div>
            <div style={{fontSize:22,fontWeight:800,color:k.color,fontFamily:'var(--font-mono)'}}>{Number(k.value||0).toLocaleString()}</div>
          </div>
        ))}
      </div>
      <div className="card">
        <div className="card-header"><span className="card-title">Recent engine runs</span></div>
        <div className="table-wrapper">
          <table>
            <thead><tr>
              <th>Started</th><th>Duration</th><th>Scanned</th>
              <th>Threats</th><th>New</th><th>Updated</th><th>Errors</th><th>Status</th>
            </tr></thead>
            <tbody>
              {runs.map((r,i)=>{
                const dur = r.completed_at
                  ? Math.round((new Date(r.completed_at)-new Date(r.started_at))/1000)
                  : null;
                return (
                  <tr key={i}>
                    <td className="mono" style={{fontSize:11}}>{r.started_at?.slice(0,19)}</td>
                    <td className="mono" style={{fontSize:11}}>{dur!=null?`${dur}s`:'—'}</td>
                    <td style={{fontFamily:'var(--font-mono)',fontSize:12}}>{r.logs_scanned||0}</td>
                    <td style={{fontFamily:'var(--font-mono)',fontSize:12,color:'#fbbf24'}}>{r.threats_found||0}</td>
                    <td style={{fontFamily:'var(--font-mono)',fontSize:12,color:'#4ade80'}}>{r.new_indicators||0}</td>
                    <td style={{fontFamily:'var(--font-mono)',fontSize:12,color:'#60a5fa'}}>{r.updated_indicators||0}</td>
                    <td style={{fontFamily:'var(--font-mono)',fontSize:12,color:'#f87171'}}>{r.errors||0}</td>
                    <td><span style={{fontSize:11,fontWeight:600,padding:'2px 8px',borderRadius:20,
                      background:r.status==='done'?'rgba(22,163,74,0.15)':'rgba(220,38,38,0.15)',
                      color:r.status==='done'?'#4ade80':'#f87171'}}>{r.status}</span></td>
                  </tr>
                );
              })}
              {runs.length===0&&<tr><td colSpan={8} style={{textAlign:'center',padding:32,color:'var(--text-muted)'}}>No runs yet</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
