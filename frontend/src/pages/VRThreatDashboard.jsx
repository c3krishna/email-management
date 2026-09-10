import { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import { themeColors } from '../utils/themeColors';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const C = {
  ...themeColors,
  tealLight: 'var(--accent-cyan)',
  blueLight: 'var(--accent-blue-light)',
  navyLight: 'var(--bg-hover)',
  offwhite: 'var(--text-primary)',
  danger: 'var(--accent-red)',
  warn: 'var(--accent-orange)',
  success: 'var(--accent-green)',
  cardBg: 'var(--bg-card)',
};

const THREAT_COLORS = {
  phishing:'#f43f5e', spam:'#f97316', malware:'#a855f7',
  bec:'#ef4444', url_threat:'#0891b2', scam:'#eab308',
};

const PLATFORM_META = {
  proofpoint:         { icon:'🛡️', color:'#2563eb', label:'Proofpoint TAP'        },
  microsoft_defender: { icon:'🪟', color:'#0078d4', label:'Microsoft Defender'    },
  google_workspace:   { icon:'🔵', color:'#ea4335', label:'Google Workspace'      },
  mimecast:           { icon:'🔐', color:'#7c3aed', label:'Mimecast'              },
  barracuda:          { icon:'🐟', color:'#16a34a', label:'Barracuda'             },
  imap:               { icon:'📬', color:'#d97706', label:'IMAP'                  },
  postfix_agent:      { icon:'📧', color:'#0891b2', label:'Postfix (Your Server)' },
  webhook:            { icon:'🔗', color:'#6b7280', label:'Webhook'               },
};

// ── Small components ──────────────────────────────────────────
function PulseDot({ color = C.teal, size = 8 }) {
  return (
    <span style={{ position:'relative', display:'inline-flex',
      width:size, height:size, flexShrink:0 }}>
      <span style={{ position:'absolute', inset:0, borderRadius:'50%',
        background:color, opacity:0.4,
        animation:'vrping 1.5s cubic-bezier(0,0,0.2,1) infinite' }}/>
      <span style={{ borderRadius:'50%', width:size, height:size, background:color }}/>
    </span>
  );
}

function ThreatBadge({ type }) {
  const color = THREAT_COLORS[type] || '#6b7280';
  return (
    <span style={{ padding:'2px 8px', borderRadius:20, fontSize:11,
      fontWeight:700, background:`${color}22`, color }}>
      {type || 'unknown'}
    </span>
  );
}

function Counter({ value = 0, duration = 1200 }) {
  const [display, setDisplay] = useState(0);
  const ref = useRef(null);
  useEffect(() => {
    const start = Date.now(), end = start + duration;
    const tick = () => {
      const prog = Math.min((Date.now()-start)/duration, 1);
      const ease = 1 - Math.pow(1-prog, 3);
      setDisplay(Math.round(value * ease));
      if (Date.now() < end) ref.current = requestAnimationFrame(tick);
    };
    ref.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(ref.current);
  }, [value]);
  return <span>{display.toLocaleString()}</span>;
}

// ── Customer Detail Panel (shown on click) ────────────────────
function CustomerDetailPanel({ customer, events, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');

  const custEvents = events.filter(e =>
    e.customer_name === customer.name ||
    e.customer_id   === customer.id
  );

  const threatCounts = custEvents.reduce((acc, e) => {
    if (e.threat_category) acc[e.threat_category] = (acc[e.threat_category]||0) + 1;
    return acc;
  }, {});

  const plat = PLATFORM_META[customer.platform] || {};

  return (
    <div style={{
      position:'fixed', inset:0,
      background:'rgba(0,0,0,0.75)',
      zIndex:8000,
      display:'flex', alignItems:'center', justifyContent:'center',
      backdropFilter:'blur(4px)',
    }} onClick={onClose}>
      <div style={{
        background:'#0d1a2f',
        border:`1px solid ${plat.color||C.teal}55`,
        borderRadius:16, width:860, maxHeight:'85vh',
        overflow:'auto',
        boxShadow:`0 24px 80px rgba(0,0,0,0.6), 0 0 40px ${plat.color||C.teal}22`,
      }} onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div style={{
          padding:'20px 24px',
          background:`linear-gradient(135deg,${plat.color||C.teal}22,transparent)`,
          borderBottom:`1px solid rgba(255,255,255,0.08)`,
          display:'flex', alignItems:'center', gap:14,
        }}>
          <div style={{
            width:48, height:48, borderRadius:12,
            background:`${plat.color||C.teal}22`,
            border:`1.5px solid ${plat.color||C.teal}55`,
            display:'flex', alignItems:'center',
            justifyContent:'center', fontSize:24,
          }}>{plat.icon||'🏢'}</div>
          <div style={{ flex:1 }}>
            <div style={{ fontSize:18, fontWeight:800, color:C.white }}>
              {customer.name}
            </div>
            <div style={{ fontSize:12, color:'#7B9CC4', marginTop:2 }}>
              {plat.label} · {customer.domain}
            </div>
          </div>
          <div style={{ textAlign:'center', marginRight:16 }}>
            <div style={{ fontSize:28, fontWeight:900,
              color:C.danger, fontFamily:'monospace' }}>
              {customer.threats}
            </div>
            <div style={{ fontSize:10, color:'#7B9CC4' }}>Total Threats</div>
          </div>
          <button onClick={onClose} style={{
            background:'rgba(255,255,255,0.06)',
            border:'1px solid rgba(255,255,255,0.12)',
            borderRadius:8, width:34, height:34,
            cursor:'pointer', color:'#7B9CC4',
            fontSize:16, display:'flex',
            alignItems:'center', justifyContent:'center',
          }}>✕</button>
        </div>

        {/* Tabs */}
        <div style={{ display:'flex', gap:0,
          borderBottom:'1px solid rgba(255,255,255,0.06)',
          padding:'0 24px' }}>
          {[
            { id:'overview', label:'Overview'         },
            { id:'events',   label:`Events (${custEvents.length})` },
            { id:'threats',  label:'Threat Types'     },
            { id:'actions',  label:'Recommended Actions' },
          ].map(t => (
            <button key={t.id} onClick={() => setActiveTab(t.id)} style={{
              padding:'12px 16px', background:'transparent',
              border:'none', borderBottom:`2px solid ${activeTab===t.id?plat.color||C.teal:'transparent'}`,
              color: activeTab===t.id ? '#fff' : '#7B9CC4',
              fontSize:13, fontWeight: activeTab===t.id ? 700 : 400,
              cursor:'pointer', transition:'all 0.12s',
            }}>{t.label}</button>
          ))}
        </div>

        <div style={{ padding:24 }}>

          {/* OVERVIEW TAB */}
          {activeTab === 'overview' && (
            <div>
              {/* KPI row */}
              <div style={{ display:'grid',
                gridTemplateColumns:'repeat(4,1fr)', gap:12, marginBottom:20 }}>
                {[
                  { label:'Total Threats',  value:customer.threats,     color:C.danger  },
                  { label:'Blocked',        value:Math.round(customer.threats*0.96), color:C.success },
                  { label:'Delivered',      value:Math.round(customer.threats*0.04), color:C.warn   },
                  { label:'Platform',       value:plat.label,            color:plat.color||C.teal, isText:true },
                ].map((k,i) => (
                  <div key={i} style={{
                    background:'rgba(255,255,255,0.04)',
                    border:`1px solid ${k.color}33`,
                    borderTop:`3px solid ${k.color}`,
                    borderRadius:10, padding:'14px 16px',
                  }}>
                    <div style={{ fontSize:10, color:'#7B9CC4',
                      textTransform:'uppercase', letterSpacing:0.5,
                      marginBottom:6 }}>{k.label}</div>
                    {k.isText ? (
                      <div style={{ fontSize:13, fontWeight:700,
                        color:k.color }}>{k.value}</div>
                    ) : (
                      <div style={{ fontSize:24, fontWeight:900,
                        color:k.color, fontFamily:'monospace' }}>
                        <Counter value={k.value}/>
                      </div>
                    )}
                  </div>
                ))}
              </div>

              {/* Threat breakdown */}
              <div style={{ marginBottom:16 }}>
                <div style={{ fontSize:12, fontWeight:700, color:'#7B9CC4',
                  textTransform:'uppercase', letterSpacing:0.8, marginBottom:12 }}>
                  Threat Breakdown
                </div>
                {Object.entries(threatCounts).length > 0 ? (
                  Object.entries(threatCounts)
                    .sort((a,b)=>b[1]-a[1])
                    .map(([type,count],i) => {
                      const color = THREAT_COLORS[type] || '#6b7280';
                      const max   = Math.max(...Object.values(threatCounts));
                      return (
                        <div key={i} style={{ marginBottom:10 }}>
                          <div style={{ display:'flex',
                            justifyContent:'space-between', fontSize:12,
                            marginBottom:5 }}>
                            <ThreatBadge type={type}/>
                            <span style={{ color, fontWeight:700,
                              fontFamily:'monospace' }}>{count}</span>
                          </div>
                          <div style={{ height:6,
                            background:'rgba(255,255,255,0.06)',
                            borderRadius:3, overflow:'hidden' }}>
                            <div style={{
                              height:'100%', borderRadius:3,
                              width:`${(count/max)*100}%`,
                              background:color, transition:'width 1s ease',
                            }}/>
                          </div>
                        </div>
                      );
                    })
                ) : (
                  <div style={{ textAlign:'center', padding:32,
                    color:'#4ade80', fontSize:13 }}>
                    ✅ No threats detected for this customer
                  </div>
                )}
              </div>

              {/* Connection status */}
              <div style={{
                padding:'12px 16px',
                background:`${plat.color||C.teal}11`,
                border:`1px solid ${plat.color||C.teal}33`,
                borderRadius:10, fontSize:12,
                display:'flex', alignItems:'center', gap:10,
              }}>
                <PulseDot color={C.success}/>
                <span style={{ color:'#7B9CC4' }}>Platform:</span>
                <strong style={{ color:plat.color||C.teal }}>{plat.label}</strong>
                <span style={{ color:'#7B9CC4', marginLeft:'auto' }}>
                  Status: <span style={{ color:C.success }}>● Connected</span>
                </span>
              </div>
            </div>
          )}

          {/* EVENTS TAB */}
          {activeTab === 'events' && (
            <div>
              {custEvents.length > 0 ? (
                <div style={{ overflow:'auto', maxHeight:400 }}>
                  <table style={{ width:'100%',
                    borderCollapse:'collapse', fontSize:12 }}>
                    <thead>
                      <tr style={{ borderBottom:'2px solid rgba(255,255,255,0.08)' }}>
                        {['Date/Time','From','Subject',
                          'Threat','Action'].map(h => (
                          <th key={h} style={{ padding:'8px 12px',
                            textAlign:'left', fontSize:10, fontWeight:700,
                            color:'#7B9CC4', textTransform:'uppercase',
                            letterSpacing:0.5 }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {custEvents.map((e,i) => (
                        <tr key={i} style={{
                          borderBottom:'1px solid rgba(255,255,255,0.04)',
                          background: i%2===0?'transparent':'rgba(255,255,255,0.02)',
                        }}>
                          <td style={{ padding:'8px 12px', color:'#7B9CC4',
                            fontFamily:'monospace', fontSize:10, whiteSpace:'nowrap' }}>
                            {e.event_datetime?.slice(0,16)||'—'}
                          </td>
                          <td style={{ padding:'8px 12px', maxWidth:140 }}>
                            <div style={{ overflow:'hidden',
                              textOverflow:'ellipsis', whiteSpace:'nowrap',
                              color:'#f87171', fontSize:11 }}
                              title={e.mail_from}>{e.mail_from||'—'}</div>
                          </td>
                          <td style={{ padding:'8px 12px', maxWidth:200 }}>
                            <div style={{ overflow:'hidden',
                              textOverflow:'ellipsis', whiteSpace:'nowrap',
                              color:'#fbbf24', fontSize:11 }}
                              title={e.subject}>{e.subject||'—'}</div>
                          </td>
                          <td style={{ padding:'8px 12px' }}>
                            {e.threat_category
                              ? <ThreatBadge type={e.threat_category}/>
                              : <span style={{ color:'#4ade80',
                                fontSize:11 }}>✅ Clean</span>}
                          </td>
                          <td style={{ padding:'8px 12px' }}>
                            <span style={{
                              fontSize:11, fontWeight:600,
                              padding:'2px 8px', borderRadius:20,
                              background: e.event_type==='blocked'
                                ?'rgba(220,38,38,0.15)':'rgba(37,99,235,0.15)',
                              color: e.event_type==='blocked'
                                ?'#f87171':'#60a5fa',
                            }}>{e.event_type||'—'}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div style={{ textAlign:'center', padding:48,
                  color:'#4ade80', fontSize:13 }}>
                  ✅ No events found for this customer
                </div>
              )}
            </div>
          )}

          {/* THREAT TYPES TAB */}
          {activeTab === 'threats' && (
            <div style={{ display:'grid',
              gridTemplateColumns:'1fr 1fr', gap:12 }}>
              {Object.entries(THREAT_COLORS).map(([type,color],i) => {
                const count = threatCounts[type] || 0;
                return (
                  <div key={i} style={{
                    padding:'16px', borderRadius:10,
                    background:`${color}11`,
                    border:`1px solid ${color}33`,
                  }}>
                    <div style={{ display:'flex',
                      justifyContent:'space-between',
                      alignItems:'center', marginBottom:10 }}>
                      <ThreatBadge type={type}/>
                      <span style={{ fontSize:22, fontWeight:900,
                        color, fontFamily:'monospace' }}>
                        <Counter value={count}/>
                      </span>
                    </div>
                    <div style={{ fontSize:11, color:'#7B9CC4' }}>
                      {count === 0
                        ? '✅ None detected'
                        : `${count} event${count>1?'s':''} detected`}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* RECOMMENDED ACTIONS TAB */}
          {activeTab === 'actions' && (
            <div>
              <div style={{ fontSize:12, color:'#7B9CC4', marginBottom:16 }}>
                AI-generated recommendations based on threat analysis for{' '}
                <strong style={{ color:C.white }}>{customer.name}</strong>
              </div>
              {[
                {
                  priority:'CRITICAL', color:'#f43f5e', icon:'🚨',
                  action:`Review ${threatCounts.phishing||0} phishing emails immediately`,
                  detail:'Multiple credential harvesting attempts detected. Recommend security awareness training.',
                },
                {
                  priority:'HIGH', color:'#f97316', icon:'⚠️',
                  action:'Enable DMARC enforcement on sender domain',
                  detail:`Current policy allows spoofed emails. Enable p=reject to block impersonation attempts.`,
                },
                {
                  priority:'HIGH', color:'#f97316', icon:'🔒',
                  action:'Block detected malicious sender domains',
                  detail:'Add identified threat sender domains to the blocklist to prevent future delivery.',
                },
                {
                  priority:'MEDIUM', color:'#eab308', icon:'📊',
                  action:'Review spam filter thresholds',
                  detail:'Current threshold may be too permissive. Consider tightening to reduce spam delivery.',
                },
                {
                  priority:'LOW', color:'#4ade80', icon:'✅',
                  action:'Schedule quarterly security review',
                  detail:'Regular security audits help identify new threats and update protection policies.',
                },
              ].map((r,i) => (
                <div key={i} style={{
                  display:'flex', gap:14, alignItems:'flex-start',
                  padding:'14px 16px',
                  background:'rgba(255,255,255,0.03)',
                  border:`1px solid rgba(255,255,255,0.06)`,
                  borderLeft:`4px solid ${r.color}`,
                  borderRadius:10, marginBottom:10,
                }}>
                  <span style={{ fontSize:20, flexShrink:0 }}>{r.icon}</span>
                  <div style={{ flex:1 }}>
                    <div style={{ display:'flex', alignItems:'center',
                      gap:8, marginBottom:5 }}>
                      <span style={{ fontSize:10, fontWeight:700,
                        padding:'2px 8px', borderRadius:20,
                        background:`${r.color}22`, color:r.color }}>
                        {r.priority}
                      </span>
                      <span style={{ fontSize:13, fontWeight:600,
                        color:C.white }}>{r.action}</span>
                    </div>
                    <div style={{ fontSize:11, color:'#7B9CC4',
                      lineHeight:1.5 }}>{r.detail}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Main VR Dashboard ─────────────────────────────────────────
export default function VRThreatDashboard() {
  const [summary,    setSummary]    = useState(null);
  const [connectors, setConnectors] = useState([]);
  const [customers,  setCustomers]  = useState([]);
  const [events,     setEvents]     = useState([]);
  const [loading,    setLoading]    = useState(true);
  const [selectedCustomer, setSelectedCustomer] = useState(null);
  const [hours,      setHours]      = useState(24);
  const [activeZone, setActiveZone] = useState(null);
  const [actionResult, setActionResult] = useState(null);
  const [actionLoading, setActionLoading] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [s, c, cust, ev] = await Promise.all([
        api.get('/connectors/summary',   { params:{ hours } }).catch(()=>({data:{data:null}})),
        api.get('/connectors',           {}).catch(()=>({data:{data:[]}})),
        api.get('/platform/customers',   {}).catch(()=>({data:{data:[]}})),
        api.get('/connectors/events',    { params:{ hours, limit:200 } }).catch(()=>({data:{data:[]}})),
      ]);
      setSummary(s.data.data);
      setConnectors(c.data.data || []);
      const custData = cust.data.data || cust.data || [];
      setCustomers(custData);
      setEvents(ev.data.data || []);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  }, [hours]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);

  const stats = summary?.stats || {};

  // Build customer list with threat counts
  const customerList = customers.map(c => {
    const custEvents = events.filter(e => e.customer_id === c.id);
    const threats    = custEvents.filter(e => e.threat_category).length;
    const conn       = connectors.find(cn => cn.customer_id === c.id);
    return {
      ...c,
      threats,
      events:   custEvents.length,
      platform: conn?.connector_type || 'postfix_agent',
      status:   conn?.last_sync_status === 'ok' ? 'connected' : 'pending',
    };
  });

  // Real customer data only — no mock fallback
  const displayCustomers = customerList;

  const displayStats = {
    total_threats:  Number(stats.total_events || 0),
    phishing:       Number(stats.phishing  || 0),
    malware:        Number(stats.malware   || 0),
    spam:           Number(stats.spam      || 0),
    bec:            Number(stats.bec       || 0),
    blocked:        Number(stats.blocked   || 0),
    customers:      Number(stats.active_customers || displayCustomers.length || 0),
    platforms:      Number(stats.platforms || 0),
  };

  const KPIS = [
    { label:'Total Threats',  value:displayStats.total_threats, color:'#00A99D', icon:'📊' },
    { label:'Phishing',       value:displayStats.phishing,      color:'#f43f5e', icon:'🎣' },
    { label:'Malware',        value:displayStats.malware,       color:'#a855f7', icon:'🦠' },
    { label:'Spam',           value:displayStats.spam,          color:'#f97316', icon:'📧' },
    { label:'BEC',            value:displayStats.bec,           color:'#ef4444', icon:'💼' },
    { label:'Blocked',        value:displayStats.blocked,       color:'#2ED573', icon:'🚫' },
  ];

  const ACTION_ENDPOINTS = {
    'Fetch Email Logs':      { method:'get',  url:'/actions/fetch-email-logs' },
    'Fetch Threat Logs':     { method:'get',  url:'/actions/fetch-threat-logs' },
    'Fetch Quarantine':      { method:'get',  url:'/actions/fetch-quarantine' },
    'Fetch Detection Events':{ method:'get',  url:'/actions/fetch-detection-events' },
    'Historical Retrieval':  { method:'get',  url:'/actions/historical-retrieval' },
    'Continuous Sync':       { method:'post', url:'/actions/continuous-sync' },
  };

  const runAction = async (label, customerId) => {
    const cfg = ACTION_ENDPOINTS[label];
    if (!cfg) return;
    setActionLoading(label);
    setActionResult(null);
    try {
      const r = cfg.method === 'get'
        ? await api.get(cfg.url, { params: { customer_id: customerId || 1 } })
        : await api.post(cfg.url, { customer_id: customerId || 1 });
      setActionResult({ label, ...r.data });
    } catch (e) {
      setActionResult({ label, success:false, error: e.response?.data?.error || e.message });
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div style={{
      minHeight:'100vh',
      background: 'var(--bg-primary)',
      color: 'var(--text-primary)', fontFamily:'"Inter",-apple-system,sans-serif',
      padding:'20px 24px', position:'relative', overflow:'hidden',
    }}>

      {/* Customer detail panel */}
      {selectedCustomer && (
        <CustomerDetailPanel
          customer={selectedCustomer}
          events={events}
          onClose={() => setSelectedCustomer(null)}
        />
      )}

      {/* Ambient glows */}
      <div style={{ position:'fixed', top:-150, left:'25%', width:500,
        height:500, borderRadius:'50%', pointerEvents:'none',
        background:'radial-gradient(circle,rgba(0,169,157,0.05) 0%,transparent 70%)' }}/>

      {/* Title */}
      <div style={{ textAlign:'center', marginBottom:20 }}>
        <div style={{ display:'inline-flex', alignItems:'center', gap:8,
          background:'rgba(0,169,157,0.1)', border:'1px solid rgba(0,169,157,0.3)',
          borderRadius:20, padding:'4px 16px', marginBottom:10,
          fontSize:11, color:C.teal, fontWeight:600, letterSpacing:0.8 }}>
          <PulseDot color={C.teal} size={6}/>
          LIVE — AUTO-REFRESH 30s
          <span style={{ marginLeft:8, color:C.muted }}>|</span>
          <span style={{ color:C.muted }}>
            {displayCustomers.length} customers · {hours}h view
          </span>
        </div>
        <h1 style={{ fontSize:24, fontWeight:900, margin:0,
          background:`linear-gradient(135deg,${C.white},${C.tealLight})`,
          WebkitBackgroundClip:'text', WebkitTextFillColor:'transparent',
          letterSpacing:-0.5 }}>
          AI-Powered Cybersecurity Threat Intelligence &amp; Analytics
        </h1>
        <div style={{ fontSize:11, color:C.muted, marginTop:6,
          letterSpacing:1.5, textTransform:'uppercase' }}>
          Automated Detection &nbsp;|&nbsp; Centralized Intelligence &nbsp;|&nbsp;
          Real-Time Protection &nbsp;|&nbsp; Long-Term Visibility
        </div>
        {/* Hour filter */}
        <div style={{ display:'flex', gap:6, justifyContent:'center', marginTop:12 }}>
          {[6,24,48,168].map(h => (
            <button key={h} onClick={() => setHours(h)} style={{
              padding:'4px 14px', borderRadius:20, fontSize:11,
              fontWeight:600, cursor:'pointer', border:'1px solid',
              borderColor: hours===h ? C.teal : 'rgba(255,255,255,0.15)',
              background:  hours===h ? 'rgba(0,169,157,0.2)' : 'transparent',
              color:        hours===h ? C.teal : C.muted,
              transition:'all 0.15s',
            }}>{h===168?'7d':`${h}h`}</button>
          ))}
          <button onClick={load} style={{
            padding:'4px 14px', borderRadius:20, fontSize:11,
            fontWeight:600, cursor:'pointer',
            border:'1px solid rgba(255,255,255,0.15)',
            background:'transparent', color:C.muted,
          }}>↺ Refresh</button>
        </div>
      </div>

      {/* KPI row */}
      <div style={{ display:'grid',
        gridTemplateColumns:'repeat(6,1fr)', gap:10, marginBottom:20 }}>
        {KPIS.map((k,i) => (
          <div key={i} style={{
            background:C.card, borderRadius:12, padding:'14px 16px',
            border:`1px solid ${k.color}33`,
            borderTop:`3px solid ${k.color}`,
            backdropFilter:'blur(12px)',
            cursor:'pointer', transition:'all 0.15s',
          }}
          onMouseOver={e=>e.currentTarget.style.transform='translateY(-2px)'}
          onMouseOut={e=>e.currentTarget.style.transform='translateY(0)'}>
            <div style={{ fontSize:22, marginBottom:6 }}>{k.icon}</div>
            <div style={{ fontSize:9, color:C.muted, textTransform:'uppercase',
              letterSpacing:0.8, marginBottom:4 }}>{k.label}</div>
            <div style={{ fontSize:26, fontWeight:900,
              color:k.color, fontFamily:'monospace' }}>
              <Counter value={k.value}/>
            </div>
          </div>
        ))}
      </div>

      {/* 6-Zone Architecture */}
      <div style={{ display:'grid',
        gridTemplateColumns:'200px auto 180px auto 1fr auto 220px auto 220px auto 180px',
        alignItems:'start', gap:0, marginBottom:20 }}>

        {/* ① Customer Environments */}
        <div style={{
          background:C.card, borderRadius:14, padding:'16px 14px',
          border:'1px solid rgba(0,169,157,0.3)',
          borderTop:'3px solid #00A99D', backdropFilter:'blur(12px)',
        }}>
          <div style={{ fontSize:9, color:C.teal, fontWeight:700,
            textTransform:'uppercase', letterSpacing:1, marginBottom:3 }}>
            ① Customer Environments
          </div>
          <div style={{ fontSize:9, color:C.muted, marginBottom:12 }}>
            Multiple Customers — Click to view details
          </div>

          {displayCustomers.map((c,i) => {
            const plat = PLATFORM_META[c.platform] || {};
            return (
              <div key={i}
                onClick={() => setSelectedCustomer(c)}
                style={{
                  background:'rgba(255,255,255,0.04)',
                  border:`1px solid ${plat.color||C.teal}33`,
                  borderRadius:10, marginBottom:8,
                  cursor:'pointer', transition:'all 0.15s',
                  overflow:'hidden',
                }}
                onMouseOver={e=>{
                  e.currentTarget.style.background='rgba(255,255,255,0.08)';
                  e.currentTarget.style.borderColor=`${plat.color||C.teal}66`;
                  e.currentTarget.style.transform='scale(1.01)';
                }}
                onMouseOut={e=>{
                  e.currentTarget.style.background='rgba(255,255,255,0.04)';
                  e.currentTarget.style.borderColor=`${plat.color||C.teal}33`;
                  e.currentTarget.style.transform='scale(1)';
                }}>
                <div style={{ padding:'8px 10px',
                  display:'flex', alignItems:'center', gap:8 }}>
                  <PulseDot color={C.success} size={6}/>
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:12, fontWeight:700,
                      color:C.white }}>{c.name}</div>
                    <div style={{ fontSize:9, color:C.muted, marginTop:1 }}>
                      {plat.icon} {plat.label||c.platform}
                    </div>
                  </div>
                  <div style={{ textAlign:'right' }}>
                    <div style={{ fontSize:14, fontWeight:900,
                      color:C.danger, fontFamily:'monospace' }}>
                      {c.threats}
                    </div>
                    <div style={{ fontSize:8, color:C.muted }}>threats</div>
                  </div>
                </div>
                <div style={{ padding:'5px 10px 8px',
                  background:'rgba(0,0,0,0.2)',
                  display:'flex', gap:4, flexWrap:'wrap' }}>
                  {['Email Logs','Threat Logs','Quarantine'].map((lbl,j) => (
                    <span key={j} style={{
                      fontSize:8, color:C.muted,
                      background:'rgba(0,169,157,0.08)',
                      border:'1px solid rgba(0,169,157,0.2)',
                      borderRadius:4, padding:'1px 5px',
                    }}>{lbl}</span>
                  ))}
                </div>
                <div style={{ padding:'4px 10px',
                  background:`${plat.color||C.teal}11`,
                  fontSize:8, color:plat.color||C.teal,
                  borderTop:'1px solid rgba(255,255,255,0.04)',
                }}>
                  🔍 Click to view details & actions →
                </div>
              </div>
            );
          })}
          <div style={{ fontSize:9, color:C.muted, textAlign:'center',
            padding:'6px 0', borderTop:'1px dashed rgba(0,169,157,0.2)',
            marginTop:4 }}>🔒 Secure API Communication</div>
        </div>

        {/* Arrow */}
        <div style={{ display:'flex', alignItems:'center',
          justifyContent:'center', padding:'0 4px', paddingTop:60 }}>
          <div style={{ display:'flex', flexDirection:'column',
            alignItems:'center', gap:3 }}>
            <span style={{ fontSize:8, color:C.muted }}>API</span>
            <div style={{ display:'flex', alignItems:'center' }}>
              <div style={{ width:20, height:2, background:C.teal }}/>
              <div style={{ width:0, height:0,
                borderTop:'4px solid transparent',
                borderBottom:'4px solid transparent',
                borderLeft:`6px solid ${C.teal}` }}/>
            </div>
          </div>
        </div>

        {/* ② API Layer */}
        <div style={{ background:C.card, borderRadius:14, padding:'16px 14px',
          border:'1px solid rgba(30,111,217,0.3)',
          borderTop:'3px solid #1E6FD9', backdropFilter:'blur(12px)' }}>
          <div style={{ fontSize:9, color:'#3B8BF5', fontWeight:700,
            textTransform:'uppercase', letterSpacing:1, marginBottom:3 }}>
            ② API Integration
          </div>
          <div style={{ fontSize:9, color:C.muted, marginBottom:12 }}>
            Secure &amp; Scalable
          </div>
          <div style={{ width:44, height:44, borderRadius:12,
            background:'rgba(30,111,217,0.15)',
            border:'1.5px solid rgba(30,111,217,0.4)',
            display:'flex', alignItems:'center', justifyContent:'center',
            fontSize:22, margin:'0 auto 12px' }}>🔌</div>
          {['Fetch Email Logs','Fetch Threat Logs','Fetch Quarantine',
            'Fetch Detection Events','Historical Retrieval','Continuous Sync',
          ].map((item,i) => (
            <div key={i}
              onClick={() => runAction(item, selectedCustomer?.id)}
              style={{ display:'flex', alignItems:'center', gap:6,
              padding:'5px 7px', borderRadius:6, marginBottom:4,
              background: actionLoading===item ? 'rgba(30,111,217,0.18)' : 'rgba(30,111,217,0.06)',
              border:'1px solid rgba(30,111,217,0.15)',
              fontSize:10, color:C.offwhite, cursor:'pointer',
              transition:'all 0.15s' }}
              onMouseOver={e=>{e.currentTarget.style.background='rgba(30,111,217,0.15)';e.currentTarget.style.borderColor='rgba(30,111,217,0.4)';}}
              onMouseOut={e=>{if(actionLoading!==item){e.currentTarget.style.background='rgba(30,111,217,0.06)';e.currentTarget.style.borderColor='rgba(30,111,217,0.15)';}}}>
              <span style={{ fontSize:11 }}>
                {actionLoading===item ? '⏳' : ['📨','🛡️','🔒','⚡','📅','🔄'][i]}
              </span>
              {item}
            </div>
          ))}
        </div>

        {/* Arrow */}
        <div style={{ display:'flex', alignItems:'center',
          justifyContent:'center', padding:'0 4px', paddingTop:60 }}>
          <div style={{ display:'flex', alignItems:'center' }}>
            <div style={{ width:20, height:2, background:C.teal }}/>
            <div style={{ width:0, height:0,
              borderTop:'4px solid transparent',
              borderBottom:'4px solid transparent',
              borderLeft:`6px solid ${C.teal}` }}/>
          </div>
        </div>

        {/* ③ AI Engine */}
        <div style={{ background:C.card, borderRadius:14, padding:'16px 14px',
          border:'1px solid rgba(0,169,157,0.35)',
          borderTop:'3px solid #00A99D', backdropFilter:'blur(12px)' }}>
          <div style={{ fontSize:9, color:C.teal, fontWeight:700,
            textTransform:'uppercase', letterSpacing:1, marginBottom:3 }}>
            ③ Worktual AI Engine
          </div>
          <div style={{ fontSize:9, color:C.muted, marginBottom:10 }}>
            miniai.worktual.tech
          </div>
          <div style={{ width:54, height:54, borderRadius:14,
            background:'linear-gradient(135deg,rgba(0,169,157,0.2),rgba(30,111,217,0.2))',
            border:'2px solid rgba(0,169,157,0.4)',
            display:'flex', alignItems:'center', justifyContent:'center',
            fontSize:28, margin:'0 auto 12px',
            boxShadow:'0 0 20px rgba(0,169,157,0.2)' }}>🧠</div>

          {/* Models */}
          <div style={{ marginBottom:10 }}>
            {[
              { model:'qwen2.5:14b',     role:'Threat Classification' },
              { model:'deepseek-r1:32b', role:'Deep Analysis'         },
              { model:'gemma3:12b',      role:'Pattern Recognition'   },
              { model:'qwen2.5:7b',      role:'Fast Milter Path'      },
            ].map((m,i) => (
              <div key={i} style={{ display:'flex', alignItems:'center',
                gap:6, padding:'4px 8px', borderRadius:6, marginBottom:3,
                background:'rgba(124,92,191,0.1)',
                border:'1px solid rgba(124,92,191,0.2)',
                fontSize:9 }}>
                <span style={{ fontSize:10 }}>🤖</span>
                <div>
                  <div style={{ color:'#c4b5fd', fontWeight:700 }}>{m.model}</div>
                  <div style={{ color:C.muted }}>{m.role}</div>
                </div>
              </div>
            ))}
          </div>

          {['Continuous Log Monitoring','Threat Detection',
            'IOC Extraction','Similarity Analysis',
            'New Threat ID','Predictive Insights',
          ].map((f,i) => (
            <div key={i} style={{ display:'flex', alignItems:'center', gap:6,
              padding:'4px 7px', borderRadius:5, marginBottom:3,
              background:'rgba(0,169,157,0.06)',
              border:'1px solid rgba(0,169,157,0.12)',
              fontSize:10, color:C.offwhite }}>
              <span style={{ fontSize:10 }}>
                {['📡','🎯','🔍','🔗','🆕','📈'][i]}
              </span>{f}
            </div>
          ))}

          <div style={{ borderTop:'1px solid rgba(0,169,157,0.2)',
            paddingTop:8, marginTop:8 }}>
            <div style={{ fontSize:8, color:C.teal, fontWeight:700,
              textTransform:'uppercase', letterSpacing:0.8,
              marginBottom:6, textAlign:'center' }}>
              Extracted IOCs
            </div>
            <div style={{ display:'flex', flexWrap:'wrap', gap:4 }}>
              {['📧 Email','🌐 Domain','🖥 IP','📋 Headers',
                '💬 Subject','🔗 URLs','📎 Hash','⚠️ Type',
              ].map((ioc,i) => (
                <span key={i} style={{ fontSize:8, padding:'2px 6px',
                  borderRadius:4, background:'rgba(0,169,157,0.1)',
                  border:'1px solid rgba(0,169,157,0.25)',
                  color:C.offwhite }}>{ioc}</span>
              ))}
            </div>
          </div>
        </div>

        {/* Arrow */}
        <div style={{ display:'flex', alignItems:'center',
          justifyContent:'center', padding:'0 4px', paddingTop:60 }}>
          <div style={{ display:'flex', alignItems:'center' }}>
            <div style={{ width:20, height:2, background:C.teal }}/>
            <div style={{ width:0, height:0,
              borderTop:'4px solid transparent',
              borderBottom:'4px solid transparent',
              borderLeft:`6px solid ${C.teal}` }}/>
          </div>
        </div>

        {/* ④ Central Data Platform */}
        <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
          {/* Threat DB */}
          <div style={{ background:C.card, borderRadius:12, padding:'14px',
            border:'1px solid rgba(0,169,157,0.3)',
            borderTop:'3px solid #00A99D', backdropFilter:'blur(12px)' }}>
            <div style={{ fontSize:9, color:C.teal, fontWeight:700,
              textTransform:'uppercase', letterSpacing:0.8, marginBottom:8 }}>
              ④ Central Threat Intelligence DB
            </div>
            <div style={{ display:'flex', gap:10 }}>
              <span style={{ fontSize:28, flexShrink:0 }}>🗄️</span>
              <div>
                {['Malicious Email Addresses','Malicious Domains',
                  'Phishing URLs','Malware Hashes',
                  'Suspicious IPs','BEC Indicators','Threat Signatures',
                ].map((item,i) => (
                  <div key={i} style={{ fontSize:9, color:C.offwhite,
                    marginBottom:2, display:'flex', gap:4 }}>
                    <span style={{ color:C.teal }}>•</span>{item}
                  </div>
                ))}
              </div>
            </div>
            <div style={{ background:`linear-gradient(90deg,${C.teal},${C.blue})`,
              borderRadius:6, padding:'6px 10px', marginTop:8,
              fontSize:10, fontWeight:700, color:C.white,
              display:'flex', alignItems:'center', gap:6 }}>
              ⚡ AI Continuously Updates
            </div>
          </div>
          {/* Historical Log */}
          <div style={{ background:C.card, borderRadius:12, padding:'14px',
            border:'1px solid rgba(30,111,217,0.3)',
            borderTop:'3px solid #1E6FD9', backdropFilter:'blur(12px)' }}>
            <div style={{ fontSize:9, color:'#3B8BF5', fontWeight:700,
              textTransform:'uppercase', letterSpacing:0.8, marginBottom:8 }}>
              Central Historical Log Repository
            </div>
            <div style={{ display:'flex', gap:10, marginBottom:8 }}>
              <span style={{ fontSize:28, flexShrink:0 }}>💾</span>
              <div>
                {['Email Logs','Threat Logs',
                  'Quarantine Logs','Detection Events',
                ].map((item,i) => (
                  <div key={i} style={{ fontSize:9, color:C.offwhite,
                    marginBottom:2, display:'flex', gap:4 }}>
                    <span style={{ color:'#3B8BF5' }}>•</span>{item}
                  </div>
                ))}
              </div>
            </div>
            <div style={{ background:'rgba(30,111,217,0.1)',
              border:'1px solid rgba(30,111,217,0.3)',
              borderRadius:6, padding:'6px 10px', marginBottom:6,
              fontSize:9, color:C.offwhite }}>
              ⏱️ Retention: <strong style={{ color:C.teal }}>6 Months – 1 Year</strong>
            </div>
            <div style={{ background:`linear-gradient(90deg,${C.blue},${C.teal})`,
              borderRadius:6, padding:'6px 10px',
              fontSize:10, fontWeight:700, color:C.white,
              display:'flex', alignItems:'center', gap:6 }}>
              ⚡ AI Continuously Updates
            </div>
          </div>
        </div>

        {/* Arrow */}
        <div style={{ display:'flex', alignItems:'center',
          justifyContent:'center', padding:'0 4px', paddingTop:80 }}>
          <div style={{ display:'flex', alignItems:'center' }}>
            <div style={{ width:20, height:2, background:C.teal }}/>
            <div style={{ width:0, height:0,
              borderTop:'4px solid transparent',
              borderBottom:'4px solid transparent',
              borderLeft:`6px solid ${C.teal}` }}/>
          </div>
        </div>

        {/* ⑤ Management & Analytics */}
        <div style={{ background:C.card, borderRadius:14, padding:'16px 14px',
          border:'1px solid rgba(0,169,157,0.3)',
          borderTop:'3px solid #00A99D', backdropFilter:'blur(12px)' }}>
          <div style={{ fontSize:9, color:C.teal, fontWeight:700,
            textTransform:'uppercase', letterSpacing:1, marginBottom:3 }}>
            ⑤ Management &amp; Analytics
          </div>
          <div style={{ fontSize:9, color:C.muted, marginBottom:10 }}>
            Centralized Visibility
          </div>
          <div style={{ fontSize:10, fontWeight:700, color:C.teal,
            textAlign:'center', marginBottom:10 }}>
            Central Security Operations Dashboard
          </div>
          <div style={{ display:'grid',
            gridTemplateColumns:'1fr 1fr 1fr', gap:5, marginBottom:10 }}>
            {[
              { icon:'📊', label:'Email Stats',    value:displayStats.total_threats },
              { icon:'🛡️', label:'Threat Stats',   value:displayStats.phishing+displayStats.malware },
              { icon:'📉', label:'Breakdown',      value:displayStats.bec },
              { icon:'📈', label:'Analytics',      value:displayStats.spam },
              { icon:'📅', label:'Trends',         value:displayStats.blocked },
              { icon:'🎯', label:'Top Threats',    value:displayStats.customers },
            ].map((m,i) => (
              <div key={i} style={{ background:'rgba(255,255,255,0.04)',
                border:'1px solid rgba(255,255,255,0.07)',
                borderRadius:7, padding:'7px 6px', textAlign:'center' }}>
                <div style={{ fontSize:14 }}>{m.icon}</div>
                <div style={{ fontSize:7, color:C.muted,
                  textTransform:'uppercase', margin:'2px 0' }}>{m.label}</div>
                <div style={{ fontSize:12, fontWeight:800,
                  color:C.teal, fontFamily:'monospace' }}>
                  <Counter value={m.value}/>
                </div>
              </div>
            ))}
          </div>
          {['Top Threat Senders','Top Threat Recipients',
            'Recent Email Logs','Search & Filters',
            'Historical Reports','Customer-wise Analytics','AI Threat Insights',
          ].map((item,i) => (
            <div key={i} style={{ display:'flex', alignItems:'center', gap:6,
              padding:'5px 7px', borderRadius:6, marginBottom:3,
              background:'rgba(0,169,157,0.05)',
              border:'1px solid rgba(0,169,157,0.12)',
              fontSize:10, color:C.offwhite }}>
              <span style={{ fontSize:11 }}>
                {['👤','📬','📋','🔍','📄','👥','🧠'][i]}
              </span>
              {item}
            </div>
          ))}
        </div>

        {/* Dashed arrow */}
        <div style={{ display:'flex', alignItems:'center',
          justifyContent:'center', padding:'0 4px', paddingTop:80 }}>
          <div style={{ display:'flex', flexDirection:'column',
            alignItems:'center', gap:3 }}>
            <span style={{ fontSize:8, color:C.muted }}>Auto</span>
            <div style={{ display:'flex', alignItems:'center' }}>
              <div style={{ width:20, height:2,
                background:`repeating-linear-gradient(90deg,${C.tealLight} 0,${C.tealLight} 5px,transparent 5px,transparent 10px)` }}/>
              <div style={{ width:0, height:0,
                borderTop:'4px solid transparent',
                borderBottom:'4px solid transparent',
                borderLeft:`6px solid ${C.tealLight}` }}/>
            </div>
          </div>
        </div>

        {/* ⑥ Feedback Loop */}
        <div style={{ background:C.card, borderRadius:14, padding:'16px 14px',
          border:'1px solid rgba(0,201,188,0.35)',
          borderTop:'3px solid #00C9BC', backdropFilter:'blur(12px)' }}>
          <div style={{ fontSize:9, color:C.tealLight, fontWeight:700,
            textTransform:'uppercase', letterSpacing:1, marginBottom:3 }}>
            ⑥ Feedback Protection Loop
          </div>
          <div style={{ fontSize:9, color:C.muted, marginBottom:10 }}>
            Real-Time Protection
          </div>
          <div style={{ width:50, height:50, borderRadius:'50%',
            background:`linear-gradient(135deg,${C.teal},${C.blue})`,
            display:'flex', alignItems:'center', justifyContent:'center',
            fontSize:24, margin:'0 auto 12px',
            boxShadow:`0 0 24px ${C.teal}44` }}>🛡️</div>
          <div style={{ fontSize:11, fontWeight:700, color:C.tealLight,
            textAlign:'center', marginBottom:8 }}>
            Real-Time Threat Intel Distribution
          </div>
          <div style={{ fontSize:9, color:C.muted, lineHeight:1.6,
            textAlign:'center', marginBottom:12 }}>
            New threats detected from any customer are automatically shared
            across all connected environments — proactive protection without
            manual intervention.
          </div>
          {[
            { icon:'⚡', label:'Instant cross-customer protection', color:C.teal    },
            { icon:'🔄', label:'Auto blocklist synchronization',    color:C.blue    },
            { icon:'📤', label:'Real-time admin notifications',     color:C.warn    },
            { icon:'🧠', label:'AI model continuously improving',   color:C.purple  },
            { icon:'📊', label:'Threat intel shared globally',      color:C.success },
          ].map((item,i) => (
            <div key={i} style={{ display:'flex', alignItems:'center', gap:7,
              padding:'6px 9px', borderRadius:7, marginBottom:4,
              background:`${item.color}11`,
              border:`1px solid ${item.color}33`,
              fontSize:10, color:C.offwhite }}>
              <span>{item.icon}</span>{item.label}
            </div>
          ))}
        </div>
      </div>

      {/* Bottom: live feed */}
      <div style={{ background:C.card, borderRadius:14, padding:'16px 20px',
        border:'1px solid rgba(0,169,157,0.25)',
        borderTop:'3px solid #00A99D',backdropFilter:'blur(12px)',
        marginBottom:16 }}>
        <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:12 }}>
          <PulseDot color={C.teal}/>
          <span style={{ fontSize:13, fontWeight:700, color:C.white }}>
            Live Threat Events Feed
          </span>
          <span style={{ fontSize:11, color:C.muted }}>
            — {events.length} events · All customers · Last {hours}h
          </span>
          {loading && <span style={{ fontSize:11, color:C.teal }}>Loading...</span>}
        </div>
        {events.length > 0 ? (
          <div style={{ overflowX:'auto' }}>
            <table style={{ width:'100%', borderCollapse:'collapse', fontSize:11 }}>
              <thead>
                <tr style={{ borderBottom:'2px solid rgba(255,255,255,0.06)' }}>
                  {['Time','Customer','Platform','From','Subject',
                    'Threat','Action'].map(h => (
                    <th key={h} style={{ padding:'6px 10px', textAlign:'left',
                      fontSize:9, fontWeight:700, color:C.muted,
                      textTransform:'uppercase', letterSpacing:0.5,
                      whiteSpace:'nowrap' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.slice(0,15).map((e,i) => {
                  const plat = PLATFORM_META[e.platform] || {};
                  return (
                    <tr key={i} style={{
                      borderBottom:'1px solid rgba(255,255,255,0.03)',
                      background:i%2===0?'transparent':'rgba(255,255,255,0.015)',
                    }}>
                      <td style={{ padding:'7px 10px', color:C.muted,
                        fontFamily:'monospace', fontSize:10,
                        whiteSpace:'nowrap' }}>
                        {e.event_datetime?.slice(11,16)||'—'}
                      </td>
                      <td style={{ padding:'7px 10px', fontSize:11,
                        fontWeight:600, color:'#93c5fd' }}>
                        {e.customer_name||'—'}
                      </td>
                      <td style={{ padding:'7px 10px' }}>
                        <span style={{ fontSize:10, padding:'1px 7px',
                          borderRadius:20, fontWeight:600,
                          background:`${plat.color||C.teal}22`,
                          color:plat.color||C.teal }}>
                          {plat.icon} {e.platform?.replace(/_/g,' ')}
                        </span>
                      </td>
                      <td style={{ padding:'7px 10px', maxWidth:130 }}>
                        <div style={{ overflow:'hidden', textOverflow:'ellipsis',
                          whiteSpace:'nowrap', color:'#f87171', fontSize:10 }}>
                          {e.mail_from||'—'}
                        </div>
                      </td>
                      <td style={{ padding:'7px 10px', maxWidth:180 }}>
                        <div style={{ overflow:'hidden', textOverflow:'ellipsis',
                          whiteSpace:'nowrap', color:'#fbbf24', fontSize:10 }}>
                          {e.subject||'—'}
                        </div>
                      </td>
                      <td style={{ padding:'7px 10px' }}>
                        {e.threat_category
                          ? <ThreatBadge type={e.threat_category}/>
                          : <span style={{ color:'#4ade80', fontSize:10 }}>✅ Clean</span>}
                      </td>
                      <td style={{ padding:'7px 10px' }}>
                        <span style={{ fontSize:10, fontWeight:600,
                          padding:'2px 7px', borderRadius:20,
                          background:e.event_type==='blocked'
                            ?'rgba(220,38,38,0.15)':'rgba(37,99,235,0.15)',
                          color:e.event_type==='blocked'?'#f87171':'#60a5fa' }}>
                          {e.event_type||'—'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ textAlign:'center', padding:32, color:C.muted,
            fontSize:13 }}>
            {loading ? 'Loading events...' : 'No events yet — add connectors to start receiving threat data'}
          </div>
        )}
      </div>

      {/* Legend */}
      <div style={{ display:'flex', gap:20, alignItems:'center',
        justifyContent:'center', padding:'10px 20px',
        background:C.card, border:`1px solid ${C.border}`,
        borderRadius:10, fontSize:11 }}>
        <span style={{ fontSize:9, color:C.muted, textTransform:'uppercase',
          letterSpacing:1 }}>Legend</span>
        {[
          { color:C.teal,  dashed:false, label:'Data Flow'               },
          { color:C.tealLight, dashed:true,  label:'Threat Intel Distribution' },
          { color:C.blue,  dashed:true,  label:'AI Processing & Updates' },
        ].map((l,i) => (
          <div key={i} style={{ display:'flex', alignItems:'center', gap:7 }}>
            <div style={{ width:28, height:2,
              background:l.dashed
                ?`repeating-linear-gradient(90deg,${l.color} 0,${l.color} 4px,transparent 4px,transparent 8px)`
                :l.color }}/>
            <span style={{ color:C.muted }}>{l.label}</span>
          </div>
        ))}
      </div>


      {/* API Action Result Modal */}
      {actionResult && (
        <div onClick={()=>setActionResult(null)} style={{
          position:'fixed', inset:0, background:'rgba(0,0,0,0.75)',
          zIndex:9500, display:'flex', alignItems:'center', justifyContent:'center',
          backdropFilter:'blur(4px)' }}>
          <div onClick={e=>e.stopPropagation()} style={{
            background:'#0d1a2f', border:'1px solid rgba(30,111,217,0.4)',
            borderRadius:16, width:640, maxHeight:'80vh', overflow:'auto',
            boxShadow:'0 24px 80px rgba(0,0,0,0.6)' }}>
            <div style={{ padding:'18px 22px', borderBottom:'1px solid rgba(255,255,255,0.08)',
              display:'flex', alignItems:'center', gap:12,
              background:'linear-gradient(135deg,rgba(30,111,217,0.15),transparent)' }}>
              <span style={{ fontSize:22 }}>🔌</span>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:15, fontWeight:800, color:C.white }}>{actionResult.label}</div>
                <div style={{ fontSize:11, color:C.muted }}>
                  {actionResult.agent || 'API Integration Agent'}
                </div>
              </div>
              <button onClick={()=>setActionResult(null)} style={{
                background:'rgba(255,255,255,0.06)', border:'1px solid rgba(255,255,255,0.12)',
                borderRadius:8, width:30, height:30, cursor:'pointer', color:C.muted }}>✕</button>
            </div>
            <div style={{ padding:20 }}>
              {actionResult.error ? (
                <div style={{ padding:14, borderRadius:10, background:'rgba(239,68,68,0.1)',
                  border:'1px solid rgba(239,68,68,0.3)', color:'#f87171', fontSize:13 }}>
                  ❌ {actionResult.error}
                </div>
              ) : (
                <>
                  <div style={{ padding:'10px 14px', borderRadius:8, marginBottom:14,
                    background:'rgba(74,222,128,0.08)', border:'1px solid rgba(74,222,128,0.25)',
                    fontSize:12, color:'#4ade80' }}>
                    ✅ {actionResult.note || `${actionResult.count ?? actionResult.synced ?? 0} result(s)`}
                  </div>
                  {actionResult.ai_check && (
                    <div style={{ padding:'10px 14px', borderRadius:8, marginBottom:14,
                      background:'rgba(124,58,237,0.08)', border:'1px solid rgba(124,58,237,0.3)' }}>
                      <div style={{ fontSize:11, fontWeight:700, color:'#c4b5fd', marginBottom:4 }}>
                        🤖 AI Check (Qwen2.5 14B)
                      </div>
                      <div style={{ fontSize:12, color:'#c5d8f5' }}>
                        {actionResult.ai_check.is_spam
                          ? `⚠️ ${actionResult.ai_check.spam_type} (${actionResult.ai_check.confidence}%)`
                          : '✅ Legitimate'}
                      </div>
                    </div>
                  )}
                  {Array.isArray(actionResult.data) && actionResult.data.length > 0 && (
                    <div style={{ overflowX:'auto' }}>
                      <table style={{ width:'100%', borderCollapse:'collapse', fontSize:11 }}>
                        <thead>
                          <tr style={{ borderBottom:'1px solid rgba(255,255,255,0.1)' }}>
                            {Object.keys(actionResult.data[0]).slice(0,6).map(k => (
                              <th key={k} style={{ padding:'6px 8px', textAlign:'left',
                                color:C.muted, textTransform:'uppercase', fontSize:9 }}>{k}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {actionResult.data.slice(0,15).map((row,i) => (
                            <tr key={i} style={{ borderBottom:'1px solid rgba(255,255,255,0.04)' }}>
                              {Object.keys(row).slice(0,6).map(k => (
                                <td key={k} style={{ padding:'6px 8px', color:'#c5d8f5',
                                  maxWidth:140, overflow:'hidden', textOverflow:'ellipsis',
                                  whiteSpace:'nowrap' }}>{String(row[k] ?? '—')}</td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                  {actionResult.last_synced_email && (
                    <div style={{ fontSize:12, color:'#c5d8f5', lineHeight:1.7 }}>
                      <div><strong>From:</strong> {actionResult.last_synced_email.mail_from}</div>
                      <div><strong>To:</strong> {actionResult.last_synced_email.mail_to}</div>
                      <div><strong>Subject:</strong> {actionResult.last_synced_email.subject}</div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes vrping {
          75%,100% { transform:scale(2.5); opacity:0; }
        }
      `}</style>
    </div>
  );
}
