import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { themeColors as C } from '../utils/themeColors';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const FRAMEWORKS = [
  { id:'cis',         label:'CIS Benchmark', icon:'🛡️', color:C.teal,   desc:'Center for Internet Security' },
  { id:'gdpr',        label:'GDPR',        icon:'🇪🇺', color:C.blue,   desc:'EU Data Protection' },
  { id:'pci_dss',     label:'PCI DSS',     icon:'💳', color:C.green,  desc:'Payment Card Security' },
  { id:'hipaa',       label:'HIPAA',       icon:'🏥', color:C.red,    desc:'Healthcare Data Privacy' },
  { id:'nist_800_53', label:'NIST 800-53', icon:'🇺🇸', color:C.purple, desc:'US Federal Security Controls' },
  { id:'tsc',         label:'SOC 2 (TSC)', icon:'📋', color:C.amber,  desc:'Trust Service Criteria' },
];

const SEV_COLOR = { Critical:C.red, High:C.orange, Medium:C.amber, Low:C.green };

function StatCard({ icon, label, value, color, sub }) {
  return (
    <div style={{ background:C.card, borderRadius:12, padding:'14px 16px',
      border:`1px solid ${color}33`, borderTop:`3px solid ${color}` }}>
      <div style={{ fontSize:18, marginBottom:6 }}>{icon}</div>
      <div style={{ fontSize:9, color:C.muted, textTransform:'uppercase', letterSpacing:0.6, marginBottom:4 }}>{label}</div>
      <div style={{ fontSize:22, fontWeight:900, color, fontFamily:'monospace' }}>{value}</div>
      {sub && <div style={{ fontSize:9, color:C.muted, marginTop:2 }}>{sub}</div>}
    </div>
  );
}

function ComplianceGauge({ framework, score, pass, fail, source, eventCount, highSeverityEvents }) {
  const meta = FRAMEWORKS.find(f => f.id === framework) || FRAMEWORKS[0];
  const isSCA = source === 'sca';
  const isAlerts = source === 'alerts';
  const hasData = isSCA ? ((pass || 0) + (fail || 0) > 0) : (isAlerts ? (eventCount || 0) > 0 : false);
  const pct = score != null ? Math.round(score) : 0;
  const color = !hasData ? C.muted : isSCA ? (pct >= 80 ? C.green : pct >= 50 ? C.amber : C.red)
    : (highSeverityEvents > 0 ? C.red : C.amber);
  const r = 34, circ = 2 * Math.PI * r;

  return (
    <div style={{ background:C.card, border:`1px solid ${meta.color}33`, borderRadius:14,
      padding:'18px 16px', textAlign:'center', opacity: hasData ? 1 : 0.5 }}>
      <div style={{ fontSize:22, marginBottom:6 }}>{meta.icon}</div>
      <div style={{ fontSize:12, fontWeight:800, color:C.white, marginBottom:2 }}>{meta.label}</div>
      <div style={{ fontSize:9, color:C.muted, marginBottom:10 }}>{meta.desc}</div>

      {isSCA && hasData && (
        <>
          <svg width={90} height={90} style={{ margin:'0 auto' }}>
            <circle cx={45} cy={45} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={8}/>
            <circle cx={45} cy={45} r={r} fill="none" stroke={color} strokeWidth={8}
              strokeDasharray={`${(pct/100)*circ} ${circ}`} strokeDashoffset={circ/4} strokeLinecap="round"
              style={{ transition:'stroke-dasharray 1s ease' }}/>
            <text x={45} y={45} textAnchor="middle" dominantBaseline="middle"
              fill={color} fontSize={18} fontWeight={800} fontFamily="monospace">{pct}%</text>
          </svg>
          <div style={{ fontSize:10, color:C.muted, marginTop:8 }}>
            <span style={{ color:C.green }}>{pass||0} pass</span> · <span style={{ color:C.red }}>{fail||0} fail</span>
          </div>
        </>
      )}

      {isAlerts && hasData && (
        <>
          <div style={{ height:90, display:'flex', flexDirection:'column',
            alignItems:'center', justifyContent:'center' }}>
            <div style={{ fontSize:32, fontWeight:900, color, fontFamily:'monospace' }}>
              {eventCount}
            </div>
            <div style={{ fontSize:9, color:C.muted, marginTop:2 }}>
              alert type{eventCount!==1?'s':''} (30d)
            </div>
          </div>
          <div style={{ fontSize:10, marginTop:8 }}>
            {highSeverityEvents > 0 ? (
              <span style={{ color:C.red }}>⚠️ {highSeverityEvents} high-severity</span>
            ) : (
              <span style={{ color:C.green }}>✓ all low-severity</span>
            )}
          </div>
        </>
      )}

      {!hasData && (
        <div style={{ height:90, display:'flex', alignItems:'center', justifyContent:'center' }}>
          <div style={{ fontSize:10, color:C.muted, lineHeight:1.5 }}>
            No activity<br/>detected yet
          </div>
        </div>
      )}
    </div>
  );
}

export default function WazuhSIEMPage({ server = 'all' }) {
  const [customerId, setCustomerId] = useState(1);
  const [customers, setCustomers]   = useState([]);
  const [summary, setSummary]       = useState(null);
  const [activeTab, setActiveTab]   = useState('overview');
  const [agents, setAgents]         = useState([]);
  const [vulns, setVulns]           = useState([]);
  const [alerts, setAlerts]         = useState([]);
  const [loading, setLoading]       = useState(true);
  const [overviewCriticalVulns, setOverviewCriticalVulns] = useState([]);
  const mailServer = server === 'campaign' ? 'campaign' : server === 'app' ? 'app' : 'all';

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [s, c] = await Promise.all([
        api.get('/wazuh/summary', { params:{ customer_id: customerId, mail_server: mailServer } }).catch(()=>({data:{data:null}})),
        api.get('/platform/customers').catch(()=>({data:{data:[]}})),
      ]);
      setSummary(s.data.data);
      setCustomers(c.data.data || c.data || []);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  }, [customerId, mailServer]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    api.get('/wazuh/vulnerabilities', { params:{ customer_id: customerId, severity:'Critical', limit:10, mail_server: mailServer } })
      .then(r => setOverviewCriticalVulns(r.data.data || [])).catch(()=>{});
  }, [customerId, mailServer]);

  useEffect(() => {
    if (activeTab === 'agents') {
      api.get('/wazuh/agents', { params:{ customer_id: customerId, mail_server: mailServer } })
        .then(r => setAgents(r.data.data || [])).catch(()=>setAgents([]));
    }
    if (activeTab === 'vulnerabilities') {
      api.get('/wazuh/vulnerabilities', { params:{ customer_id: customerId, mail_server: mailServer } })
        .then(r => setVulns(r.data.data || [])).catch(()=>setVulns([]));
    }
    if (activeTab === 'threat-hunting') {
      api.get('/wazuh/alerts', { params:{ customer_id: customerId, hours:168, mail_server: mailServer } })
        .then(r => setAlerts(r.data.data || [])).catch(()=>setAlerts([]));
    }
  }, [activeTab, customerId, mailServer]);

  const stats = summary || {};
  const complianceByFramework = {};
  (stats.compliance || []).forEach(c => {
    // API already returns ONE row per framework (pre-aggregated server-side
    // for alert-tag frameworks, and GROUP BY framework for SCA) — just pass
    // the row through directly, preserving 'source' so the UI can tell
    // SCA-shaped data (total_pass/total_fail/avg_score) apart from
    // alerts-shaped data (event_count/high_severity_events).
    complianceByFramework[c.framework] = c;
  });

  return (
    <div style={{
      minHeight:'100vh', background: 'var(--bg-primary)',
      color: 'var(--text-primary)', fontFamily:'"Inter",-apple-system,sans-serif', padding:'24px 28px' }}>

      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center',
        marginBottom:24, flexWrap:'wrap', gap:12 }}>
        <div>
          <div style={{ display:'inline-flex', alignItems:'center', gap:8, background:C.tealDim,
            border:`1px solid ${C.teal}55`, borderRadius:20, padding:'4px 14px', fontSize:11,
            fontWeight:700, color:C.teal, textTransform:'uppercase', letterSpacing:1, marginBottom:10 }}>
            🛡️ Wazuh SIEM Integration
          </div>
          <h1 style={{ fontSize:24, fontWeight:900, color:'var(--text-primary)' }}>
            Threat Hunting, Vulnerabilities &amp; Compliance
          </h1>
          <div style={{ fontSize:12, color:C.muted, marginTop:4 }}>
            Endpoint security posture correlated alongside email threat data
          </div>
        </div>
        <select value={customerId} onChange={e=>setCustomerId(e.target.value)}
          style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:8,
            padding:'8px 14px', color:'var(--text-primary)', fontSize:13 }}>
          {customers.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'repeat(6,1fr)', gap:10, marginBottom:24 }}>
        <StatCard icon="🖥️" label="Agents"       value={stats.agents?.active||0} color={C.teal}
          sub={`of ${stats.agents?.total||0} total`}/>
        <StatCard icon="🦠" label="Critical Vulns" value={stats.vulnerabilities?.critical||0} color={C.red}/>
        <StatCard icon="⚠️" label="High Vulns"     value={stats.vulnerabilities?.high||0}     color={C.orange}/>
        <StatCard icon="🔍" label="Total Vulns"    value={stats.vulnerabilities?.total||0}    color={C.purple}/>
        <StatCard icon="🚨" label="Alerts (7d)"    value={stats.alerts?.total||0}   color={C.blue}/>
        <StatCard icon="🔥" label="Critical Alerts" value={stats.alerts?.critical||0} color={C.red}/>
      </div>

      <div style={{ display:'flex', gap:2, borderBottom:`1px solid ${C.border}`, marginBottom:20 }}>
        {[
          { id:'overview',       label:'Overview'        },
          { id:'compliance',     label:'Compliance'      },
          { id:'vulnerabilities',label:`Vulnerabilities (${stats.vulnerabilities?.total||0})` },
          { id:'threat-hunting', label:'Threat Hunting'  },
          { id:'agents',         label:`Agents (${stats.agents?.total||0})` },
        ].map(t => (
          <button key={t.id} onClick={()=>setActiveTab(t.id)} style={{
            padding:'10px 16px', background:'transparent', border:'none',
            borderBottom:`2px solid ${activeTab===t.id?C.teal:'transparent'}`,
            color: activeTab===t.id ? '#fff' : C.muted,
            fontSize:13, fontWeight: activeTab===t.id?700:400, cursor:'pointer' }}>
            {t.label}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <div>
          {!stats.agents?.total ? (
            <div style={{ background:C.card, borderRadius:14, padding:48, textAlign:'center',
              border:`1px dashed ${C.border}` }}>
              <div style={{ fontSize:36, marginBottom:12 }}>🔌</div>
              <div style={{ fontSize:15, fontWeight:700, marginBottom:6 }}>No Wazuh data yet</div>
              <div style={{ fontSize:12, color:C.muted }}>
                Deploy wazuh_connector.py with your Wazuh Manager API and Indexer credentials
              </div>
            </div>
          ) : (
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
              {/* Critical vulnerabilities preview */}
              <div style={{ background:C.card, border:`1px solid ${C.red}33`, borderRadius:14,
                padding:'18px 20px' }}>
                <div style={{ display:'flex', justifyContent:'space-between',
                  alignItems:'center', marginBottom:12 }}>
                  <div style={{ fontSize:13, fontWeight:800, color:C.white }}>
                    🦠 Critical Vulnerabilities
                  </div>
                  <button onClick={()=>setActiveTab('vulnerabilities')} style={{
                    fontSize:10, color:C.teal, background:'transparent', border:'none',
                    cursor:'pointer', fontWeight:700 }}>
                    View all {stats.vulnerabilities?.critical||0} →
                  </button>
                </div>
                {overviewCriticalVulns.length > 0 ? (
                  overviewCriticalVulns.slice(0,5).map((v,i)=>(
                    <div key={i} style={{ display:'flex', justifyContent:'space-between',
                      alignItems:'center', padding:'8px 0',
                      borderBottom: i<4 ? '1px solid rgba(255,255,255,0.04)' : 'none' }}>
                      <div>
                        <div style={{ fontSize:11, fontFamily:'monospace', color:C.red, fontWeight:700 }}>
                          {v.cve}
                        </div>
                        <div style={{ fontSize:10, color:C.muted }}>{v.agent_name} · {v.package_name}</div>
                      </div>
                      <div style={{ fontSize:14, fontWeight:800, color:C.red, fontFamily:'monospace' }}>
                        {v.cvss_score}
                      </div>
                    </div>
                  ))
                ) : (
                  <div style={{ fontSize:12, color:C.muted, textAlign:'center', padding:20 }}>
                    Loading critical vulnerabilities...
                  </div>
                )}
              </div>

              {/* Compliance snapshot */}
              <div style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:14,
                padding:'18px 20px' }}>
                <div style={{ display:'flex', justifyContent:'space-between',
                  alignItems:'center', marginBottom:12 }}>
                  <div style={{ fontSize:13, fontWeight:800, color:C.white }}>📋 Compliance Snapshot</div>
                  <button onClick={()=>setActiveTab('compliance')} style={{
                    fontSize:10, color:C.teal, background:'transparent', border:'none',
                    cursor:'pointer', fontWeight:700 }}>
                    View details →
                  </button>
                </div>
                {FRAMEWORKS.map(f => {
                  const c = complianceByFramework[f.id];
                  const isSCA = c?.source === 'sca';
                  const isAlerts = c?.source === 'alerts';
                  const hasData = isSCA
                    ? (Number(c.total_pass||0) + Number(c.total_fail||0)) > 0
                    : isAlerts
                    ? Number(c.event_count||0) > 0
                    : false;
                  const pct = isSCA && hasData ? Math.round(c.avg_score) : null;
                  return (
                    <div key={f.id} style={{ display:'flex', alignItems:'center', gap:10,
                      padding:'7px 0' }}>
                      <span style={{ fontSize:14, width:20 }}>{f.icon}</span>
                      <span style={{ fontSize:11, flex:1, color: hasData ? '#fff' : C.muted }}>
                        {f.label}
                      </span>
                      {isSCA && hasData ? (
                        <span style={{ fontSize:12, fontWeight:800, fontFamily:'monospace',
                          color: pct>=80?C.green:pct>=50?C.amber:C.red }}>{pct}%</span>
                      ) : isAlerts && hasData ? (
                        <span style={{ fontSize:12, fontWeight:800, fontFamily:'monospace',
                          color: c.high_severity_events>0?C.red:C.amber }}>
                          {c.event_count} type{c.event_count!==1?'s':''}
                        </span>
                      ) : (
                        <span style={{ fontSize:9, color:C.muted }}>not configured</span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'compliance' && (
        <div style={{ display:'grid', gridTemplateColumns:'repeat(6,1fr)', gap:14 }}>
          {FRAMEWORKS.map(f => {
            const c = complianceByFramework[f.id];
            return <ComplianceGauge key={f.id} framework={f.id}
              score={c?.avg_score} pass={c?.total_pass} fail={c?.total_fail}
              source={c?.source} eventCount={c?.event_count}
              highSeverityEvents={c?.high_severity_events}/>;
          })}
        </div>
      )}

      {activeTab === 'vulnerabilities' && (
        <div style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:14, overflow:'hidden' }}>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12.5 }}>
            <thead>
              <tr style={{ borderBottom:`1px solid ${C.border}` }}>
                {['CVE','Severity','CVSS','Package','Agent','Title'].map(h=>(
                  <th key={h} style={{ padding:'10px 16px', textAlign:'left', fontSize:10,
                    fontWeight:800, textTransform:'uppercase', color:C.muted }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {vulns.map((v,i)=>(
                <tr key={i} style={{ borderBottom:'1px solid rgba(255,255,255,0.04)' }}>
                  <td style={{ padding:'10px 16px', fontFamily:'monospace', color:C.blue }}>{v.cve}</td>
                  <td style={{ padding:'10px 16px' }}>
                    <span style={{ fontSize:10, fontWeight:800, padding:'2px 8px', borderRadius:20,
                      background:`${SEV_COLOR[v.severity]||C.muted}22`, color:SEV_COLOR[v.severity]||C.muted }}>
                      {v.severity}
                    </span>
                  </td>
                  <td style={{ padding:'10px 16px', fontFamily:'monospace' }}>{v.cvss_score||'—'}</td>
                  <td style={{ padding:'10px 16px' }}>{v.package_name} {v.package_version}</td>
                  <td style={{ padding:'10px 16px', color:C.muted }}>{v.agent_name}</td>
                  <td style={{ padding:'10px 16px', maxWidth:250, overflow:'hidden',
                    textOverflow:'ellipsis', whiteSpace:'nowrap', color:C.muted }}>{v.title}</td>
                </tr>
              ))}
              {!vulns.length && <tr><td colSpan={6} style={{ textAlign:'center', padding:40, color:C.green }}>✅ No active vulnerabilities</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'threat-hunting' && (
        <div style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:14, overflow:'hidden' }}>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12.5 }}>
            <thead>
              <tr style={{ borderBottom:`1px solid ${C.border}` }}>
                {['Time','Level','Rule','Agent','Compliance','MITRE'].map(h=>(
                  <th key={h} style={{ padding:'10px 16px', textAlign:'left', fontSize:10,
                    fontWeight:800, textTransform:'uppercase', color:C.muted }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alerts.map((a,i)=>(
                <tr key={i} style={{ borderBottom:'1px solid rgba(255,255,255,0.04)' }}>
                  <td style={{ padding:'10px 16px', fontFamily:'monospace', fontSize:11, color:C.muted }}>
                    {a.alert_datetime?.slice(0,16)}
                  </td>
                  <td style={{ padding:'10px 16px' }}>
                    <span style={{ fontSize:10, fontWeight:800, padding:'2px 8px', borderRadius:20,
                      background: a.rule_level>=12?`${C.red}22`:a.rule_level>=7?`${C.orange}22`:`${C.muted}22`,
                      color: a.rule_level>=12?C.red:a.rule_level>=7?C.orange:C.muted }}>
                      L{a.rule_level}
                    </span>
                  </td>
                  <td style={{ padding:'10px 16px', maxWidth:280, overflow:'hidden',
                    textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{a.rule_description}</td>
                  <td style={{ padding:'10px 16px', color:C.muted }}>{a.agent_name}</td>
                  <td style={{ padding:'10px 16px' }}>
                    {a.compliance_tags?.split(',').map(t=>(
                      <span key={t} style={{ fontSize:9, padding:'1px 6px', borderRadius:10,
                        background:`${C.blue}22`, color:C.blue, marginRight:4 }}>{t.toUpperCase()}</span>
                    ))}
                  </td>
                  <td style={{ padding:'10px 16px', fontFamily:'monospace', fontSize:11, color:C.purple }}>
                    {a.mitre_technique||'—'}
                  </td>
                </tr>
              ))}
              {!alerts.length && <tr><td colSpan={6} style={{ textAlign:'center', padding:40, color:C.green }}>✅ No alerts in this period</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'agents' && (
        <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:12 }}>
          {agents.map((a,i)=>(
            <div key={i} style={{ background:C.card, border:`1px solid ${C.border}`,
              borderRadius:12, padding:'14px 16px' }}>
              <div style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
                <div style={{ fontSize:13, fontWeight:700 }}>{a.agent_name}</div>
                <span style={{ fontSize:10, fontWeight:700, padding:'2px 8px', borderRadius:20,
                  background: a.status==='active'?`${C.green}22`:`${C.red}22`,
                  color: a.status==='active'?C.green:C.red }}>{a.status}</span>
              </div>
              <div style={{ fontSize:11, color:C.muted }}>{a.os_name}</div>
              <div style={{ fontSize:11, color:C.muted, fontFamily:'monospace' }}>{a.ip_address}</div>
            </div>
          ))}
          {!agents.length && <div style={{ gridColumn:'1/-1', textAlign:'center', padding:40, color:C.muted }}>No agents found</div>}
        </div>
      )}
    </div>
  );
}
