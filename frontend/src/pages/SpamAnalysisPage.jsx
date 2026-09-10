import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Shield, AlertTriangle, CheckCircle,
         Plus, Trash2, Download, Eye, X } from 'lucide-react';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  AreaChart, Area,
  XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend
} from 'recharts';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const TT = { background:'#0d1117', border:'1px solid #30363d', borderRadius:8, fontSize:11 };

const SPAM_COLORS = {
  phishing:    '#f43f5e',
  spam:        '#f97316',
  malware:     '#a855f7',
  bec:         '#ef4444',
  scam:        '#eab308',
  crypto_scam: '#06b6d4',
  adult:       '#ec4899',
  unknown:     '#6b7280',
};

const SPAM_ICONS = {
  phishing:    '🎣',
  spam:        '📧',
  malware:     '🦠',
  bec:         '💼',
  scam:        '💰',
  crypto_scam: '₿',
  adult:       '🔞',
  unknown:     '❓',
};

const METHOD_BADGE = {
  subject_pattern: { color:'#f97316', label:'Subject Pattern' },
  body_pattern:    { color:'#a855f7', label:'Body Pattern'    },
  'ai+pattern':    { color:'#2563eb', label:'AI + Pattern'    },
  ai_only:         { color:'#06b6d4', label:'AI Only'         },
  pattern:         { color:'#d97706', label:'Pattern'         },
};

function SpamTypeBadge({ type }) {
  const color = SPAM_COLORS[type] || '#6b7280';
  const icon  = SPAM_ICONS[type]  || '❓';
  return (
    <span style={{ display:'inline-flex', alignItems:'center', gap:4,
      padding:'2px 8px', borderRadius:20, fontSize:11, fontWeight:700,
      background:`${color}22`, color }}>
      {icon} {type}
    </span>
  );
}

function ConfidenceBadge({ value }) {
  const color = value >= 85 ? '#f87171' : value >= 70 ? '#fbbf24' : '#4ade80';
  return (
    <span style={{ fontFamily:'var(--font-mono)', fontWeight:800,
      fontSize:13, color }}>{value}%</span>
  );
}

export default function SpamAnalysisPage({ server }) {
  const [activeTab,   setActiveTab]   = useState('overview');
  const [hours,       setHours]       = useState(168);
  const [summary,     setSummary]     = useState(null);
  const [detections,  setDetections]  = useState([]);
  const [rules,       setRules]       = useState([]);
  const [total,       setTotal]       = useState(0);
  const [page,        setPage]        = useState(1);
  const [loading,     setLoading]     = useState(true);
  const [selected,    setSelected]    = useState(null);
  const [typeFilter,  setTypeFilter]  = useState('');
  const [toast,       setToast]       = useState('');
  const [testInput,   setTestInput]   = useState({ subject:'', body:'', mail_from:'' });
  const [testResult,  setTestResult]  = useState(null);
  const [testLoading, setTestLoading] = useState(false);
  const [whitelist2,  setWhitelist2]  = useState([]);
  const [newWL2,      setNewWL2]      = useState({ type:'domain', value:'', description:'' });
  const [newRule,     setNewRule]     = useState({
    rule_name:'', rule_type:'subject', pattern:'', spam_type:'spam', confidence:75
  });
  const LIMIT = 50;

  const showToast = (msg) => { setToast(msg); setTimeout(()=>setToast(''), 3000); };

  const loadSummary = useCallback(async () => {
    setLoading(true);
    try {
      // Prefer Topbar server; if empty, retry with all so App filter doesn't hide Campaign detections
      let r = await api.get('/spam/summary', { params:{ hours, server: server || 'all' } });
      let data = r.data.data;
      if (server && server !== 'all' && Number(data?.stats?.total || 0) === 0) {
        r = await api.get('/spam/summary', { params:{ hours, server: 'all' } });
        data = r.data.data;
        if (data?.stats) data.stats.filterNote = `No ${server} rows — showing all servers`;
      }
      setSummary(data);
    } catch(e) {
      setSummary(null);
    } finally { setLoading(false); }
  }, [hours, server]);

  const loadDetections = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.get('/spam/detections', {
        params:{ hours, spam_type: typeFilter||undefined, page, limit: LIMIT, server: server || 'all' }
      });
      setDetections(r.data.data || []);
      setTotal(r.data.total || 0);
    } catch(e) { setDetections([]); }
    finally { setLoading(false); }
  }, [hours, typeFilter, page, server]);

  const loadRules = useCallback(async () => {
    try {
      const r = await api.get('/spam/rules');
      setRules(r.data.data || []);
    } catch(e) { setRules([]); }
  }, []);

  useEffect(() => { loadSummary(); }, [loadSummary]);
  useEffect(() => {
    if (activeTab === 'detections') loadDetections();
    if (activeTab === 'rules')      loadRules();
    if (activeTab === 'whitelist') {
      api.get('/spam/whitelist').then(r=>setWhitelist2(r.data.data||[])).catch(()=>{});
    }
  }, [activeTab, loadDetections, loadRules]);

  const markReviewed = async (id, fp = false) => {
    try {
      await api.put(`/spam/detections/${id}`, { reviewed: true, false_positive: fp });
      showToast(fp ? '✅ Marked as false positive' : '✅ Marked as reviewed');
      loadDetections();
    } catch(e) { alert(e.message); }
  };

  const addRule = async () => {
    if (!newRule.rule_name || !newRule.pattern) return;
    try {
      await api.post('/spam/rules', newRule);
      showToast(`✅ Rule "${newRule.rule_name}" added`);
      setNewRule({ rule_name:'', rule_type:'subject', pattern:'', spam_type:'spam', confidence:75 });
      loadRules();
    } catch(e) { alert(e.message); }
  };

  const testMessage = async () => {
    if (!testInput.subject && !testInput.body) return;
    setTestLoading(true); setTestResult(null);
    try {
      const r = await api.post('/spam/test', testInput);
      setTestResult(r.data);
    } catch(e) { alert(e.message); }
    finally { setTestLoading(false); }
  };

  const exportCSV = () => {
    const headers = ['DateTime','From','To','Subject','Type','Confidence','Method','Action','AI Explanation'];
    const rows = detections.map(d => [
      d.detected_at, d.mail_from, d.mail_to,
      (d.subject||'').replace(/,/g,';'),
      d.spam_type, d.confidence, d.detection_method,
      d.action_taken,
      (d.ai_explanation||'').replace(/,/g,';').slice(0,100)
    ]);
    const csv = [headers,...rows].map(r=>r.join(',')).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
    a.download = `spam-detections-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  };

  const stats = summary?.stats || {};
  const trend  = (summary?.trend || []).map(r=>({
    ...r,
    phishing: Number(r.phishing||0),
    spam:     Number(r.spam||0),
    malware:  Number(r.malware||0),
    bec:      Number(r.bec||0),
    total:    Number(r.total||0),
  }));

  const pieData = [
    { name:'Phishing',    value:Number(stats.phishing||0), color:SPAM_COLORS.phishing  },
    { name:'Spam',        value:Number(stats.spam||0),     color:SPAM_COLORS.spam      },
    { name:'Malware',     value:Number(stats.malware||0),  color:SPAM_COLORS.malware   },
    { name:'BEC',         value:Number(stats.bec||0),      color:SPAM_COLORS.bec       },
    { name:'Scam',        value:Number(stats.scam||0),     color:SPAM_COLORS.scam      },
  ].filter(d => d.value > 0);

  const noData = !summary || Number(stats.total||0) === 0;
  const fromEngine = stats.source === 'threat_indicators';

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
          <div className="section-title">Spam Analysis</div>
          <div className="section-sub">
            AI-powered spam detection · Pattern matching + Ollama (Qwen2.5 14B / 7B milter) · Real-time alerts
            {fromEngine && ' · Counts from AI Threat Engine indicators (milter empty)'}
            {stats.filterNote && ` · ${stats.filterNote}`}
          </div>
        </div>
        <div style={{ display:'flex', gap:8, alignItems:'center' }}>
          {[24,48,168,720].map(h=>(
            <button key={h} className={`btn btn-sm ${hours===h?'btn-primary':'btn-ghost'}`}
              onClick={()=>setHours(h)}>
              {h===24?'24h':h===48?'2d':h===168?'7d':'30d'}
            </button>
          ))}
          <button className="btn btn-ghost btn-sm" onClick={loadSummary}>
            <RefreshCw size={13} className={loading?'spin':''}/> Refresh
          </button>
        </div>
      </div>

      {/* KPI row */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(7,1fr)', gap:10, marginBottom:20 }}>
        {[
          { label:'Total Detected', value:stats.total,          color:'#2563eb', icon:'🛡️' },
          { label:'Phishing',       value:stats.phishing,       color:'#f43f5e', icon:'🎣' },
          { label:'Spam',           value:stats.spam,           color:'#f97316', icon:'📧' },
          { label:'Malware',        value:stats.malware,        color:'#a855f7', icon:'🦠' },
          { label:'BEC',            value:stats.bec,            color:'#ef4444', icon:'💼' },
          { label:'Alerts Sent',    value:stats.alerts_sent,    color:'#0891b2', icon:'🔔' },
          { label:'Unreviewed',     value:stats.unreviewed,     color:'#d97706', icon:'⏳' },
        ].map(k=>(
          <div key={k.label} className="card"
            style={{ borderTop:`3px solid ${k.color}`, padding:'12px 14px' }}>
            <div style={{ fontSize:18, marginBottom:4 }}>{k.icon}</div>
            <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:4,
              textTransform:'uppercase', letterSpacing:0.5 }}>{k.label}</div>
            <div style={{ fontSize:22, fontWeight:800, color:k.color,
              fontFamily:'var(--font-mono)' }}>{Number(k.value||0).toLocaleString()}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="tab-bar" style={{ marginBottom:16 }}>
        {[
          { id:'overview',    label:'Overview'              },
          { id:'detections',  label:`Detections (${total})` },
          { id:'test',        label:'Test Message'          },
          { id:'rules',       label:`Custom Rules (${rules.length})` },
          { id:'whitelist',   label:'Whitelist' },
        ].map(t=>(
          <button key={t.id} className={`tab-item ${activeTab===t.id?'active':''}`}
            onClick={()=>setActiveTab(t.id)}>{t.label}</button>
        ))}
      </div>

      {/* ── OVERVIEW ── */}
      {activeTab === 'overview' && (
        <div>
          {noData ? (
            <div className="card" style={{ textAlign:'center', padding:64 }}>
              <div style={{ fontSize:48, marginBottom:16 }}>🛡️</div>
              <div style={{ fontSize:16, fontWeight:700, marginBottom:8 }}>
                Spam Detection Engine
              </div>
              <div style={{ fontSize:13, color:'var(--text-muted)', marginBottom:20 }}>
                No detections in this window. Deploy / restart the spam milter on App &amp; Campaign mail hosts, or widen the time range.
              </div>
              <div style={{ background:'var(--bg-primary)', borderRadius:8,
                padding:16, textAlign:'left', maxWidth:560, margin:'0 auto' }}>
                <div style={{ fontSize:12, fontWeight:600, marginBottom:8,
                  color:'var(--text-muted)' }}>Deploy from agents-app / agents-campaign:</div>
                <pre style={{ fontSize:11, color:'#4ade80', fontFamily:'var(--font-mono)',
                  margin:0, lineHeight:1.8 }}>{
`cd agents-app && ./pm2-migrate.sh
cd agents-campaign && ./pm2-migrate.sh
# Ensure Postfix smtpd_milters includes inet:127.0.0.1:8891`}
                </pre>
              </div>
            </div>
          ) : (
            <div style={{ display:'grid', gridTemplateColumns:'2fr 1fr', gap:16 }}>
              {/* Trend */}
              <div className="card">
                <div className="card-header">
                  <span className="card-title">Spam detection trend (30 days)</span>
                </div>
                <ResponsiveContainer width="100%" height={240}>
                  <AreaChart data={trend.length ? trend : [{ date:'—', phishing:0, spam:0, malware:0, bec:0 }]}
                    margin={{ top:4,right:8,left:-20,bottom:0 }}>
                    <defs>
                      <linearGradient id="spPh" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={SPAM_COLORS.phishing} stopOpacity={0.3}/>
                        <stop offset="95%" stopColor={SPAM_COLORS.phishing} stopOpacity={0}/>
                      </linearGradient>
                      <linearGradient id="spSp" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={SPAM_COLORS.spam} stopOpacity={0.3}/>
                        <stop offset="95%" stopColor={SPAM_COLORS.spam} stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)"/>
                    <XAxis dataKey="date" tick={{ fill:'#6e7681', fontSize:9 }}
                      tickFormatter={v=>String(v||'').slice(5)}/>
                    <YAxis tick={{ fill:'#6e7681', fontSize:9 }} allowDecimals={false}/>
                    <Tooltip contentStyle={TT}/>
                    <Legend wrapperStyle={{ fontSize:10 }}/>
                    <Area type="monotone" dataKey="phishing" stroke={SPAM_COLORS.phishing} fill="url(#spPh)" strokeWidth={2} name="Phishing"/>
                    <Area type="monotone" dataKey="spam"     stroke={SPAM_COLORS.spam}     fill="url(#spSp)" strokeWidth={2} name="Spam"/>
                    <Line type="monotone" dataKey="malware"  stroke={SPAM_COLORS.malware}  strokeWidth={2} dot={false} name="Malware"/>
                    <Line type="monotone" dataKey="bec"      stroke={SPAM_COLORS.bec}      strokeWidth={2} dot={false} name="BEC"/>
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              {/* Pie */}
              <div className="card">
                <div style={{ fontSize:13, fontWeight:700, marginBottom:12 }}>Breakdown</div>
                {pieData.length > 0 ? (
                  <>
                    <ResponsiveContainer width="100%" height={160}>
                      <PieChart>
                        <Pie data={pieData} cx="50%" cy="50%"
                          innerRadius={45} outerRadius={70}
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
                          <div style={{ width:8,height:8,borderRadius:'50%',background:d.color }}/>
                          <span style={{ color:'var(--text-muted)' }}>{d.name}</span>
                        </div>
                        <span style={{ fontFamily:'var(--font-mono)',
                          fontWeight:700, color:d.color }}>{d.value}</span>
                      </div>
                    ))}
                  </>
                ) : (
                  <div style={{ textAlign:'center', padding:40, color:'#4ade80' }}>
                    ✅ No spam detected
                  </div>
                )}
              </div>

              {/* Top spam senders */}
              <div className="card" style={{ gridColumn:'1/-1' }}>
                <div className="card-header">
                  <span className="card-title">Top spam senders</span>
                </div>
                <div className="table-wrapper">
                  <table>
                    <thead><tr>
                      <th>Sender</th><th>Count</th><th>Type</th>
                    </tr></thead>
                    <tbody>
                      {(summary?.topSenders||[]).map((r,i)=>(
                        <tr key={i}>
                          <td className="mono" style={{ fontSize:12,color:'#f87171' }}>{r.mail_from}</td>
                          <td style={{ fontFamily:'var(--font-mono)',fontWeight:700 }}>{r.count}</td>
                          <td><SpamTypeBadge type={r.type}/></td>
                        </tr>
                      ))}
                      {!(summary?.topSenders?.length)&&(
                        <tr><td colSpan={3} style={{ textAlign:'center',padding:32,color:'#4ade80' }}>
                          ✅ No spam senders detected
                        </td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── DETECTIONS ── */}
      {activeTab === 'detections' && (
        <div>
          <div className="card mb-12" style={{ padding:'10px 14px' }}>
            <div style={{ display:'flex', gap:10, alignItems:'center', flexWrap:'wrap' }}>
              <select className="input" style={{ width:160, fontSize:12 }}
                value={typeFilter} onChange={e=>{setTypeFilter(e.target.value);setPage(1);}}>
                <option value="">All Types</option>
                {Object.keys(SPAM_COLORS).map(t=>(
                  <option key={t} value={t}>{SPAM_ICONS[t]} {t}</option>
                ))}
              </select>
              <button className="btn btn-ghost btn-sm" onClick={exportCSV}>
                <Download size={13}/> CSV
              </button>
              <span style={{ fontSize:11, color:'var(--text-muted)' }}>
                {total} detections
              </span>
            </div>
          </div>

          <div className="card">
            {loading ? (
              <div className="loading-state"><RefreshCw size={18} className="spin"/></div>
            ) : (
              <div className="table-wrapper">
                <table>
                  <thead><tr>
                    <th>Date/Time</th><th>From</th><th>Subject</th>
                    <th>Type</th><th>Confidence</th><th>Method</th>
                    <th>Action</th><th>Status</th><th></th>
                  </tr></thead>
                  <tbody>
                    {detections.map((d,i)=>(
                      <>
                        <tr key={i}
                          style={{ cursor:'pointer',
                            background:selected?.id===d.id?'rgba(37,99,235,0.06)':undefined }}
                          onClick={()=>setSelected(selected?.id===d.id?null:d)}>
                          <td className="mono" style={{ fontSize:10, whiteSpace:'nowrap',
                            color:'var(--text-muted)' }}>{d.detected_at?.slice(0,16)}</td>
                          <td style={{ maxWidth:180 }}>
                            <div style={{ overflow:'hidden', textOverflow:'ellipsis',
                              whiteSpace:'nowrap', fontSize:12, color:'#f87171' }}
                              title={d.mail_from}>{d.mail_from||'—'}</div>
                          </td>
                          <td style={{ maxWidth:220 }}>
                            <div style={{ overflow:'hidden', textOverflow:'ellipsis',
                              whiteSpace:'nowrap', fontSize:12, color:'#fbbf24' }}
                              title={d.subject}>{d.subject||'—'}</div>
                          </td>
                          <td><SpamTypeBadge type={d.spam_type}/></td>
                          <td><ConfidenceBadge value={d.confidence}/></td>
                          <td>
                            {(() => {
                              const m = METHOD_BADGE[d.detection_method] || { color:'#6b7280', label:d.detection_method };
                              return (
                                <span style={{ fontSize:10, fontWeight:600,
                                  padding:'2px 7px', borderRadius:20,
                                  background:`${m.color}22`, color:m.color }}>
                                  {m.label}
                                </span>
                              );
                            })()}
                          </td>
                          <td>
                            <span style={{ fontSize:11, fontWeight:600,
                              padding:'2px 8px', borderRadius:20,
                              background: d.action_taken==='rejected'?'rgba(220,38,38,0.15)':
                                          d.action_taken==='quarantined'?'rgba(217,119,6,0.15)':
                                          'rgba(37,99,235,0.15)',
                              color: d.action_taken==='rejected'?'#f87171':
                                     d.action_taken==='quarantined'?'#fbbf24':'#60a5fa' }}>
                              {d.action_taken}
                            </span>
                          </td>
                          <td>
                            <span style={{ fontSize:10,
                              color: d.false_positive?'#4ade80':d.reviewed?'#60a5fa':'#fbbf24' }}>
                              {d.false_positive?'✅ FP':d.reviewed?'✓ Reviewed':'⏳ New'}
                            </span>
                          </td>
                          <td onClick={e=>e.stopPropagation()}>
                            <div style={{ display:'flex', gap:4 }}>
                              <button className="btn btn-ghost btn-sm"
                                style={{ fontSize:10, padding:'2px 8px' }}
                                onClick={()=>markReviewed(d.id, false)}>✓</button>
                              <button className="btn btn-ghost btn-sm"
                                style={{ fontSize:10, padding:'2px 8px', color:'#4ade80' }}
                                onClick={()=>markReviewed(d.id, true)} title="False positive">FP</button>
                            </div>
                          </td>
                        </tr>
                        {/* Expanded detail */}
                        {selected?.id === d.id && (
                          <tr key={`${i}-detail`}>
                            <td colSpan={9} style={{ padding:0 }}>
                              <div style={{ margin:'0 12px 12px',
                                background:'var(--bg-primary)', borderRadius:8, padding:16 }}>
                                <div style={{ display:'grid',
                                  gridTemplateColumns:'repeat(3,1fr)', gap:12,
                                  fontSize:12, marginBottom:12 }}>
                                  <div>
                                    <span style={{ color:'var(--text-muted)' }}>To:</span><br/>
                                    <span>{d.mail_to||'—'}</span>
                                  </div>
                                  <div>
                                    <span style={{ color:'var(--text-muted)' }}>Server:</span><br/>
                                    <span>{d.server}</span>
                                  </div>
                                  <div>
                                    <span style={{ color:'var(--text-muted)' }}>Alert sent:</span><br/>
                                    <span style={{ color:d.alert_sent?'#4ade80':'#6b7280' }}>
                                      {d.alert_sent?'✅ Yes':'No'}
                                    </span>
                                  </div>
                                </div>
                                {d.pattern_matched && (
                                  <div style={{ marginBottom:10 }}>
                                    <span style={{ fontSize:11, color:'var(--text-muted)' }}>
                                      Pattern matched:
                                    </span>
                                    <div style={{ marginTop:4, padding:'6px 10px',
                                      background:'rgba(37,99,235,0.08)', borderRadius:6,
                                      fontSize:11, fontFamily:'var(--font-mono)',
                                      color:'#60a5fa' }}>{d.pattern_matched}</div>
                                  </div>
                                )}
                                {d.ai_explanation && (
                                  <div style={{ marginBottom:10 }}>
                                    <span style={{ fontSize:11, color:'var(--text-muted)' }}>
                                      🤖 AI explanation:
                                    </span>
                                    <div style={{ marginTop:4, padding:'6px 10px',
                                      background:'rgba(168,85,247,0.08)', borderRadius:6,
                                      fontSize:12, color:'#c4b5fd' }}>{d.ai_explanation}</div>
                                  </div>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </>
                    ))}
                    {!detections.length && !loading && (
                      <tr><td colSpan={9} style={{ textAlign:'center',
                        padding:48, color:'#4ade80' }}>
                        ✅ No spam detected in this period
                      </td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
            {/* Pagination */}
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

      {/* ── TEST MESSAGE ── */}
      {activeTab === 'test' && (
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
          <div className="card">
            <div className="card-header">
              <span className="card-title">🧪 Test email against spam rules</span>
            </div>
            <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
              <div>
                <label style={{ fontSize:12, color:'var(--text-muted)' }}>Sender Email</label>
                <input className="input" style={{ marginTop:4 }}
                  placeholder="sender@example.com"
                  value={testInput.mail_from}
                  onChange={e=>setTestInput(p=>({...p,mail_from:e.target.value}))}/>
              </div>
              <div>
                <label style={{ fontSize:12, color:'var(--text-muted)' }}>Subject *</label>
                <input className="input" style={{ marginTop:4 }}
                  placeholder="e.g. Urgent: Verify your account immediately"
                  value={testInput.subject}
                  onChange={e=>setTestInput(p=>({...p,subject:e.target.value}))}/>
              </div>
              <div>
                <label style={{ fontSize:12, color:'var(--text-muted)' }}>Body</label>
                <textarea className="input" style={{ marginTop:4, height:120, resize:'vertical' }}
                  placeholder="Paste email body here..."
                  value={testInput.body}
                  onChange={e=>setTestInput(p=>({...p,body:e.target.value}))}/>
              </div>
              <button className="btn btn-primary" onClick={testMessage}
                disabled={testLoading || (!testInput.subject && !testInput.body)}>
                {testLoading
                  ? <><RefreshCw size={13} className="spin"/> Analysing...</>
                  : '🔍 Analyse for Spam'
                }
              </button>

              {/* Quick test examples */}
              <div style={{ borderTop:'1px solid var(--border)', paddingTop:12 }}>
                <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:8 }}>
                  Quick test examples:
                </div>
                {[
                  { label:'Phishing',  subject:'URGENT: Verify your PayPal account immediately', body:'Your account has been suspended. Click here to verify.' },
                  { label:'Scam',      subject:'You have won $5,000,000 lottery prize!', body:'Dear beneficiary, contact us to claim your prize.' },
                  { label:'BEC',       subject:'Urgent wire transfer needed', body:'Please process a wire transfer of $50,000 immediately.' },
                  { label:'Clean',     subject:'Meeting tomorrow at 10am', body:'Hi team, reminder about the standup tomorrow.' },
                ].map(ex=>(
                  <button key={ex.label} className="btn btn-ghost btn-sm"
                    style={{ marginRight:6, marginBottom:6, fontSize:11 }}
                    onClick={()=>setTestInput({mail_from:'test@example.com',
                      subject:ex.subject, body:ex.body})}>
                    {ex.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Result */}
          <div className="card">
            <div style={{ fontSize:13, fontWeight:700, marginBottom:16 }}>Result</div>
            {!testResult && !testLoading && (
              <div style={{ textAlign:'center', padding:48, color:'var(--text-muted)' }}>
                Enter subject/body and click Analyse
              </div>
            )}
            {testLoading && (
              <div style={{ textAlign:'center', padding:48 }}>
                <RefreshCw size={24} className="spin" style={{ marginBottom:12 }}/>
                <div style={{ color:'var(--text-muted)' }}>Analysing with pattern rules...</div>
              </div>
            )}
            {testResult && (
              <div>
                {/* Verdict */}
                <div style={{
                  padding:16, borderRadius:10, marginBottom:16, textAlign:'center',
                  background: testResult.verdict==='SPAM'
                    ? 'rgba(220,38,38,0.1)' : 'rgba(22,163,74,0.1)',
                  border: `2px solid ${testResult.verdict==='SPAM'?'rgba(220,38,38,0.4)':'rgba(22,163,74,0.4)'}`,
                }}>
                  <div style={{ fontSize:36, marginBottom:8 }}>
                    {testResult.verdict==='SPAM' ? '🚨' : '✅'}
                  </div>
                  <div style={{ fontSize:20, fontWeight:800,
                    color: testResult.verdict==='SPAM' ? '#f87171' : '#4ade80' }}>
                    {testResult.verdict}
                  </div>
                  {testResult.max_confidence > 0 && (
                    <div style={{ fontSize:14, color:'var(--text-muted)', marginTop:4 }}>
                      Confidence: <strong style={{ color:'#fbbf24' }}>
                        {testResult.max_confidence}%
                      </strong>
                    </div>
                  )}
                </div>

                {/* Matches */}
                {testResult.matches?.length > 0 && (
                  <div>
                    <div style={{ fontSize:12, fontWeight:600,
                      color:'var(--text-muted)', marginBottom:8 }}>
                      Patterns matched ({testResult.matches.length}):
                    </div>
                    {testResult.matches.map((m,i)=>(
                      <div key={i} style={{ background:'var(--bg-primary)',
                        borderRadius:8, padding:12, marginBottom:8 }}>
                        <div style={{ display:'flex', justifyContent:'space-between',
                          alignItems:'center', marginBottom:6 }}>
                          <SpamTypeBadge type={m.type}/>
                          <ConfidenceBadge value={m.confidence}/>
                        </div>
                        <div style={{ fontSize:11, fontFamily:'var(--font-mono)',
                          color:'#60a5fa', wordBreak:'break-all' }}>{m.pattern}</div>
                      </div>
                    ))}
                  </div>
                )}

                {testResult.verdict === 'CLEAN' && (
                  <div style={{ textAlign:'center', padding:24,
                    color:'var(--text-muted)', fontSize:13 }}>
                    No spam patterns detected in subject or body
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── CUSTOM RULES ── */}
      {activeTab === 'rules' && (
        <div>
          <div className="card mb-16">
            <div className="card-header">
              <span className="card-title">Add custom rule</span>
            </div>
            <div style={{ display:'grid',
              gridTemplateColumns:'1fr 100px 1fr 100px 80px auto', gap:10, alignItems:'end' }}>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>Rule Name *</label>
                <input className="input" style={{ marginTop:4 }}
                  placeholder="e.g. Crypto scam subject"
                  value={newRule.rule_name}
                  onChange={e=>setNewRule(p=>({...p,rule_name:e.target.value}))}/>
              </div>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>Scan</label>
                <select className="input" style={{ marginTop:4 }} value={newRule.rule_type}
                  onChange={e=>setNewRule(p=>({...p,rule_type:e.target.value}))}>
                  <option value="subject">Subject</option>
                  <option value="body">Body</option>
                  <option value="sender">Sender</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>Pattern (regex) *</label>
                <input className="input" style={{ marginTop:4, fontFamily:'var(--font-mono)', fontSize:12 }}
                  placeholder="(?i)(crypto|bitcoin).{0,20}profit"
                  value={newRule.pattern}
                  onChange={e=>setNewRule(p=>({...p,pattern:e.target.value}))}/>
              </div>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>Type</label>
                <select className="input" style={{ marginTop:4 }} value={newRule.spam_type}
                  onChange={e=>setNewRule(p=>({...p,spam_type:e.target.value}))}>
                  {Object.keys(SPAM_COLORS).map(t=>(
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>Confidence</label>
                <input type="number" className="input" style={{ marginTop:4 }}
                  min={50} max={100} value={newRule.confidence}
                  onChange={e=>setNewRule(p=>({...p,confidence:parseInt(e.target.value)}))}/>
              </div>
              <button className="btn btn-primary btn-sm" onClick={addRule}
                disabled={!newRule.rule_name||!newRule.pattern}>
                <Plus size={13}/> Add
              </button>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <span className="card-title">Active rules ({rules.length})</span>
            </div>
            <div className="table-wrapper">
              <table>
                <thead><tr>
                  <th>Rule Name</th><th>Scan</th><th>Pattern</th>
                  <th>Type</th><th>Confidence</th><th>Hits</th><th>Status</th>
                </tr></thead>
                <tbody>
                  {rules.map((r,i)=>(
                    <tr key={i}>
                      <td style={{ fontSize:13, fontWeight:600 }}>{r.rule_name}</td>
                      <td><span style={{ fontSize:11, padding:'2px 8px', borderRadius:20,
                        background:'rgba(37,99,235,0.15)', color:'#60a5fa' }}>{r.rule_type}</span></td>
                      <td style={{ maxWidth:250 }}>
                        <div style={{ overflow:'hidden', textOverflow:'ellipsis',
                          whiteSpace:'nowrap', fontSize:11,
                          fontFamily:'var(--font-mono)', color:'#60a5fa' }}
                          title={r.pattern}>{r.pattern}</div>
                      </td>
                      <td><SpamTypeBadge type={r.spam_type}/></td>
                      <td><ConfidenceBadge value={r.confidence}/></td>
                      <td style={{ fontFamily:'var(--font-mono)', fontWeight:700,
                        color:'#fbbf24' }}>{r.hit_count||0}</td>
                      <td><span style={{ fontSize:11, fontWeight:600,
                        color: r.active?'#4ade80':'#6b7280' }}>
                        {r.active?'● Active':'○ Disabled'}
                      </span></td>
                    </tr>
                  ))}
                  {!rules.length && (
                    <tr><td colSpan={7} style={{ textAlign:'center',
                      padding:40, color:'var(--text-muted)' }}>
                      No custom rules yet — built-in patterns are active
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── WHITELIST ── */}
      {activeTab === 'whitelist' && (
        <div>
          <div className="card mb-16">
            <div className="card-header">
              <span className="card-title">Add to spam whitelist</span>
              <span style={{fontSize:11,color:'var(--text-muted)'}}>
                Whitelisted senders bypass all spam checks
              </span>
            </div>
            <div style={{display:'grid',gridTemplateColumns:'100px 1fr 1fr auto',gap:10,alignItems:'end'}}>
              <div>
                <label style={{fontSize:11,color:'var(--text-muted)'}}>Type</label>
                <select className="input" style={{marginTop:4}} value={newWL2.type}
                  onChange={e=>setNewWL2(p=>({...p,type:e.target.value}))}>
                  <option value="domain">Domain</option>
                  <option value="email">Email</option>
                </select>
              </div>
              <div>
                <label style={{fontSize:11,color:'var(--text-muted)'}}>Value *</label>
                <input className="input" style={{marginTop:4}}
                  placeholder="customer.com or user@customer.com"
                  value={newWL2.value}
                  onChange={e=>setNewWL2(p=>({...p,value:e.target.value}))}/>
              </div>
              <div>
                <label style={{fontSize:11,color:'var(--text-muted)'}}>Description</label>
                <input className="input" style={{marginTop:4}}
                  placeholder="Trusted customer"
                  value={newWL2.description}
                  onChange={e=>setNewWL2(p=>({...p,description:e.target.value}))}/>
              </div>
              <button className="btn btn-primary btn-sm"
                disabled={!newWL2.value}
                onClick={async()=>{
                  try {
                    await api.post('/spam/whitelist', newWL2);
                    showToast('✅ Added to whitelist');
                    setNewWL2({type:'domain',value:'',description:''});
                    api.get('/spam/whitelist').then(r=>setWhitelist2(r.data.data||[]));
                  } catch(e){ alert(e.message); }
                }}>
                <Plus size={13}/> Add
              </button>
            </div>
          </div>
          <div className="card">
            <div className="card-header">
              <span className="card-title">Whitelisted senders ({whitelist2.length})</span>
            </div>
            <div className="table-wrapper">
              <table>
                <thead><tr><th>Type</th><th>Value</th><th>Description</th><th>Added</th><th></th></tr></thead>
                <tbody>
                  {whitelist2.map((w,i)=>(
                    <tr key={i}>
                      <td><span style={{fontSize:11,fontWeight:600,padding:'2px 8px',
                        borderRadius:20,background:'rgba(22,163,74,0.15)',color:'#4ade80'}}>
                        {w.type}</span></td>
                      <td className="mono" style={{fontWeight:700,color:'#4ade80',fontSize:12}}>{w.value}</td>
                      <td style={{fontSize:12,color:'var(--text-muted)'}}>{w.description||'—'}</td>
                      <td className="mono" style={{fontSize:11,color:'var(--text-muted)'}}>{w.created_at?.slice(0,10)}</td>
                      <td>
                        <button className="btn btn-danger btn-sm" style={{padding:'2px 8px',fontSize:11}}
                          onClick={async()=>{
                            await api.delete('/spam/whitelist/'+w.id);
                            showToast('Removed from whitelist');
                            api.get('/spam/whitelist').then(r=>setWhitelist2(r.data.data||[]));
                          }}>Remove</button>
                      </td>
                    </tr>
                  ))}
                  {!whitelist2.length&&<tr><td colSpan={5} style={{textAlign:'center',padding:32,color:'var(--text-muted)'}}>No whitelist entries</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
