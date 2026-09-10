import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { themeColors as C } from '../utils/themeColors';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const PLATFORMS = [
  { id:'gmail',      icon:'📧', name:'Gmail / Google Workspace', color:C.red,
    method:'Admin SDK + Gmail API', access:'Service Account + Domain-Wide Delegation',
    realtime:'Polling every 2–5 min', direction:'Inbound + Outbound' },
  { id:'m365',       icon:'🪟', name:'Microsoft 365 / Exchange Online', color:C.blue,
    method:'Microsoft Graph API', access:'Azure AD App (Application permissions)',
    realtime:'Polling or webhook subscription', direction:'Inbound + Outbound' },
  { id:'exchange',   icon:'🏢', name:'On-Premise Exchange', color:C.purple,
    method:'EWS (Exchange Web Services)', access:'Service account + ApplicationImpersonation',
    realtime:'Polling every 2–5 min', direction:'Inbound + Outbound' },
  { id:'proofpoint', icon:'🛡️', name:'Proofpoint TAP', color:C.orange,
    method:'REST API (TAP v2)', access:'Service Principal + Secret Key',
    realtime:'Polling every 5 min', direction:'Inbound (native threat feed)' },
  { id:'mimecast',   icon:'🔐', name:'Mimecast', color:C.teal,
    method:'REST API', access:'App ID + App Key + Access/Secret Key',
    realtime:'Polling every 5 min', direction:'Inbound (URL/attachment protect)' },
  { id:'barracuda',  icon:'🐟', name:'Barracuda Email Security', color:C.green,
    method:'REST API', access:'Admin username + password',
    realtime:'Polling every 5 min', direction:'Inbound' },
  { id:'mailchimp',  icon:'🐒', name:'Mailchimp', color:C.amber,
    method:'REST API + Webhook (pre-send)', access:'API Key',
    realtime:'Real-time, pre-delivery', direction:'Outbound campaigns only' },
  { id:'custom',     icon:'🖥️', name:'Custom Mail Server (Postfix/Exim/Sendmail)', color:C.blue,
    method:'Milter (live) or IMAP polling', access:'Root/milter socket OR mailbox credentials',
    realtime:'Live (milter) or 2–5 min (IMAP)', direction:'Inbound + Outbound' },
];

const ATTACK_TYPES = [
  { type:'Phishing',            color:C.red,    coverage:'full',    detected:'Pattern + Typosquat + AI' },
  { type:'Spear Phishing',      color:C.red,    coverage:'full',    detected:'VIP impersonation + authority-language detection' },
  { type:'BEC / Wire Fraud',    color:'#dc2626', coverage:'full',    detected:'Pattern + AI + Risk scoring' },
  { type:'Malware Attachments', color:C.purple, coverage:'full',    detected:'Hash + Static analysis + AI' },
  { type:'Malicious URLs',      color:'#06b6d4',coverage:'full',    detected:'Domain check + AI' },
  { type:'Domain Spoofing',     color:C.orange, coverage:'full',    detected:'Typosquat detector' },
  { type:'Reply-Chain Hijack',  color:C.amber,  coverage:'full',    detected:'Thread tracking' },
  { type:'QR Code Phishing',    color:C.teal,   coverage:'full',    detected:'QR decode + URL check' },
  { type:'Data Leak (Outbound)',color:C.green,  coverage:'full',    detected:'DLP pattern scan' },
  { type:'Account Takeover',    color:'#ec4899',coverage:'full',    detected:'Sender behavioral baseline + cross-customer correlation' },
  { type:'Spam',                color:C.blue,   coverage:'full',    detected:'Pattern + Amavis' },
  { type:'Attachment Sandboxing (Zero-Day)', color:C.purple, coverage:'full', detected:'Static analysis + VirusTotal real dynamic sandbox network' },
];

const PIPELINE_STAGES = [
  { icon:'📨', label:'Ingest',    desc:'Any platform, any region — unified via connector layer' },
  { icon:'🎯', label:'Pattern',   desc:'14 rules, <5ms, zero AI cost' },
  { icon:'🔍', label:'Structural',desc:'Typosquat, attachment analysis, QR decode' },
  { icon:'🤖', label:'AI Deep',   desc:'llama3.1:8b — context, reasoning, MITRE mapping' },
  { icon:'🔗', label:'Correlate', desc:'Cross-customer pattern matching' },
  { icon:'📊', label:'Score',     desc:'0–100 risk, severity classification' },
  { icon:'🚫', label:'Act',       desc:'Block / Quarantine / Tag / Allow' },
  { icon:'🔔', label:'Notify',    desc:'Email / Slack / Teams / Webhook' },
];

function CoverageBadge({ level }) {
  const map = {
    full:    { label:'Full Coverage',    color:C.green,  icon:'✓' },
    partial: { label:'Partial Coverage', color:C.amber,  icon:'◐' },
  };
  const m = map[level] || map.partial;
  return (
    <span style={{ display:'inline-flex', alignItems:'center', gap:5,
      fontSize:10, fontWeight:800, padding:'3px 10px', borderRadius:20,
      background:`${m.color}22`, color:m.color }}>
      {m.icon} {m.label}
    </span>
  );
}

export default function PlatformOverviewPage({ server = 'app' }) {
  const [globalStats, setGlobalStats] = useState(null);
  const [infra, setInfra] = useState([]);
  const [spamByServer, setSpamByServer] = useState([]);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expandedPlatform, setExpandedPlatform] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [r, m, s, h] = await Promise.all([
        api.get('/connectors/summary', { params:{ hours:720 } }).catch(()=>({data:{data:null}})),
        api.get('/platform/mail-servers').catch(()=>({data:{data:[]}})),
        api.get('/spam/summary', { params:{ hours:24, server: 'all' } }).catch(()=>({data:{data:null}})),
        api.get('/platform/infra-health').catch(()=>({data:{data:null}})),
      ]);
      setGlobalStats(r.data.data);
      setInfra(m.data.data || []);
      setSpamByServer(s.data?.data?.byServer || []);
      setHealth(h.data?.data || null);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const stats = globalStats?.stats || {};
  const activeInfra = server === 'campaign' ? 'campaign' : 'app';
  const healthServers = health?.servers || {};
  const cust = health?.customers || {};

  const liveCards = [
    healthServers.app,
    healthServers.campaign,
  ].filter(Boolean);

  return (
    <div style={{
      minHeight:'100vh',
      background: 'var(--bg-primary)',
      color: 'var(--text-primary)', fontFamily:'"Inter",-apple-system,sans-serif',
      padding:'24px 28px' }}>

      {/* Header */}
      <div style={{ textAlign:'center', marginBottom:32 }}>
        <div style={{ display:'inline-flex', alignItems:'center', gap:8,
          background:C.tealDim, border:`1px solid ${C.teal}55`,
          borderRadius:20, padding:'5px 16px', fontSize:11, fontWeight:700,
          letterSpacing:1.2, color:C.teal, textTransform:'uppercase', marginBottom:14 }}>
          Dual mail infra — live ops · Topbar: {activeInfra}
          {loading ? ' · loading…' : ''}
        </div>
        <h1 style={{ fontSize:28, fontWeight:900,
          background:`linear-gradient(135deg,var(--text-primary),${C.teal})`,
          WebkitBackgroundClip:'text', WebkitTextFillColor:'transparent', marginBottom:10 }}>
          Email Infrastructure &amp; Cybersecurity Management
        </h1>
        <p style={{ color:C.muted, fontSize:14, maxWidth:680, margin:'0 auto' }}>
          App mail (mail.worktual.tech) for notifications / CCaaS / client-From via Worktual.
          Campaign (mail.worktual.pl) for bulk with delivery reporting. Separate policies per infra.
        </p>
        <button className="btn btn-ghost btn-sm" style={{ marginTop: 12 }} onClick={load} disabled={loading}>
          Refresh live health
        </button>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:14, marginBottom:28 }}>
        {(liveCards.length ? liveCards : (infra.length ? infra : [
          { key:'app', label:'App Mail', domain:'mail.worktual.tech', role:'CCaaS / notifications', vip:'82.113.72.84', active_ip:'10.180.0.84' },
          { key:'campaign', label:'Campaign Bulk', domain:'mail.worktual.pl', role:'Bulk campaign sending', vip:'82.113.72.80', active_ip:'10.180.0.89' },
        ])).map(m => {
          const key = m.key;
          const spamCount = spamByServer.find(x => x.server === key)?.total || m.spam_24h || 0;
          const selected = activeInfra === key;
          const online = m.agent_online;
          return (
            <div key={key} style={{
              background: selected ? C.tealDim : C.card,
              border: `1px solid ${selected ? C.teal : C.border}`,
              borderRadius: 12, padding: 16,
            }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:6 }}>
                <div style={{ fontSize:14, fontWeight:800 }}>{m.label}</div>
                <span style={{
                  fontSize:10, fontWeight:700, padding:'2px 8px', borderRadius:12,
                  background: online ? 'rgba(22,163,74,0.2)' : 'rgba(220,38,38,0.15)',
                  color: online ? '#4ade80' : '#f87171',
                }}>
                  {online === undefined ? '—' : online ? 'Agent online' : 'Agent offline'}
                </span>
              </div>
              <div style={{ fontSize:12, color:C.muted, marginBottom:10 }}>{m.role || m.domain}</div>
              <div style={{ fontSize:11, fontFamily:'monospace', lineHeight:1.8, color:C.white }}>
                Domain: {m.domain}<br/>
                VIP: {m.vip} · Node: {m.active_ip}<br/>
                Today: {m.delivery_today ?? '—'} · Success: {m.delivery_success ?? '—'} ·
                Failed: {m.delivery_failed ?? '—'} · Bounced: {m.delivery_bounced ?? '—'}<br/>
                7d volume: {m.delivery_7d ?? '—'} · Queue: {m.queue_count ?? '—'} ·
                Realtime today: {m.realtime_today ?? '—'}<br/>
                Spam (24h): {spamCount} · Quarantine: {m.quarantine_open ?? '—'}
                {m.data_source === 'email_log_realtime' ? ' · live-log fallback' : ''}
              </div>
            </div>
          );
        })}
      </div>

      {/* Global stats strip — live where possible */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(6,1fr)', gap:10, marginBottom:32 }}>
        {[
          { label:'Live Postfix hosts', value: 2, color:C.teal,   icon:'🔌' },
          { label:'Attack Types Covered',value:ATTACK_TYPES.filter(a=>a.coverage==='full').length, color:C.green,  icon:'🛡️' },
          { label:'Customers Protected', value: cust.total || stats.active_customers || '—',  color:C.blue,   icon:'👥' },
          { label:'App today',  value: healthServers.app?.delivery_today ?? '—',      color:C.purple, icon:'📊' },
          { label:'Campaign today', value: healthServers.campaign?.delivery_today ?? '—', color:C.red,    icon:'🚫' },
          { label:'AI Model',            value:'llama3.1:8b',                  color:C.amber,  icon:'🤖', isText:true },
        ].map((k,i)=>(
          <div key={i} style={{ background:C.card, borderRadius:12, padding:'14px 16px',
            border:`1px solid ${k.color}33`, borderTop:`3px solid ${k.color}` }}>
            <div style={{ fontSize:18, marginBottom:6 }}>{k.icon}</div>
            <div style={{ fontSize:9, color:C.muted, textTransform:'uppercase',
              letterSpacing:0.6, marginBottom:4 }}>{k.label}</div>
            <div style={{ fontSize: k.isText?13:22, fontWeight:900, color:k.color,
              fontFamily: k.isText?'inherit':'monospace' }}>{k.value}</div>
          </div>
        ))}
      </div>

      {/* ── Pipeline (how it works, top to bottom) ── */}
      <div style={{ fontSize:11, fontWeight:800, letterSpacing:1.5, textTransform:'uppercase',
        color:C.teal, marginBottom:16, display:'flex', alignItems:'center', gap:10 }}>
        How every email is validated
        <div style={{ flex:1, height:1, background:`linear-gradient(90deg,${C.border},transparent)` }}/>
      </div>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(8,1fr)', gap:8, marginBottom:36 }}>
        {PIPELINE_STAGES.map((s,i)=>(
          <div key={i} style={{ position:'relative' }}>
            <div style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:12,
              padding:'16px 12px', textAlign:'center', height:'100%' }}>
              <div style={{ fontSize:22, marginBottom:8 }}>{s.icon}</div>
              <div style={{ fontSize:11, fontWeight:800, color:C.white, marginBottom:4 }}>{s.label}</div>
              <div style={{ fontSize:9, color:C.muted, lineHeight:1.4 }}>{s.desc}</div>
            </div>
            {i < PIPELINE_STAGES.length-1 && (
              <div style={{ position:'absolute', right:-8, top:'50%', transform:'translateY(-50%)',
                fontSize:12, color:C.teal, zIndex:2 }}>→</div>
            )}
          </div>
        ))}
      </div>

      {/* ── Supported platforms grid ── */}
      <div style={{ fontSize:11, fontWeight:800, letterSpacing:1.5, textTransform:'uppercase',
        color:C.teal, marginBottom:16, display:'flex', alignItems:'center', gap:10 }}>
        Supported mail platforms — Postfix live; others are capability docs until connectors are wired
        <div style={{ flex:1, height:1, background:`linear-gradient(90deg,${C.border},transparent)` }}/>
      </div>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12, marginBottom:36 }}>
        {PLATFORMS.map((p,i)=>{
          const isLive = p.id === 'custom';
          return (
          <div key={i}
            onClick={()=>setExpandedPlatform(expandedPlatform===p.id?null:p.id)}
            style={{ background:C.card, border:`1px solid ${expandedPlatform===p.id?p.color:C.border}`,
              borderRadius:14, padding:'18px 16px', cursor:'pointer', transition:'all 0.15s',
              boxShadow: expandedPlatform===p.id ? `0 0 20px ${p.color}33` : 'none',
              opacity: isLive ? 1 : 0.85 }}>
            <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:8 }}>
              <div style={{ width:38, height:38, borderRadius:10, background:`${p.color}22`,
                border:`1px solid ${p.color}44`, display:'flex', alignItems:'center',
                justifyContent:'center', fontSize:20, flexShrink:0 }}>{p.icon}</div>
              <div style={{ fontSize:12.5, fontWeight:700, color:C.white, lineHeight:1.3 }}>{p.name}</div>
            </div>
            <div style={{ fontSize:10, color:C.muted, marginBottom:6 }}>{p.method}</div>
            <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
              <span style={{ fontSize:9, padding:'2px 7px', borderRadius:12,
                background:`${p.color}15`, color:p.color, fontWeight:700 }}>{p.direction}</span>
              <span style={{ fontSize:9, padding:'2px 7px', borderRadius:12,
                background: isLive ? 'rgba(22,163,74,0.2)' : 'rgba(148,163,184,0.2)',
                color: isLive ? '#4ade80' : '#94a3b8', fontWeight:700 }}>
                {isLive ? 'Live (App + Campaign)' : 'Capability doc'}
              </span>
            </div>

            {expandedPlatform===p.id && (
              <div style={{ marginTop:12, paddingTop:12, borderTop:`1px solid ${p.color}33`,
                fontSize:11, color:'#c5d8f5', lineHeight:1.7 }}>
                <div><strong style={{color:p.color}}>Access needed:</strong> {p.access}</div>
                <div><strong style={{color:p.color}}>Detection speed:</strong> {p.realtime}</div>
                {!isLive && (
                  <div style={{ marginTop:6, color:C.muted }}>
                    Not a live OAuth/API product in this release — documentation only.
                  </div>
                )}
                {isLive && (
                  <div style={{ marginTop:6, color:C.muted }}>
                    Maps to mail.worktual.tech (App) and mail.worktual.pl (Campaign) via milter + log agents.
                  </div>
                )}
              </div>
            )}
          </div>
        );})}
      </div>

      {/* ── Attack coverage matrix ── */}
      <div style={{ fontSize:11, fontWeight:800, letterSpacing:1.5, textTransform:'uppercase',
        color:C.teal, marginBottom:16, display:'flex', alignItems:'center', gap:10 }}>
        Attack coverage matrix
        <div style={{ flex:1, height:1, background:`linear-gradient(90deg,${C.border},transparent)` }}/>
      </div>
      <div style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:14,
        padding:'8px 0', marginBottom:36, overflow:'hidden' }}>
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12.5 }}>
          <thead>
            <tr style={{ borderBottom:`1px solid ${C.border}` }}>
              {['Attack Type','Detection Method','Status'].map(h=>(
                <th key={h} style={{ padding:'10px 20px', textAlign:'left', fontSize:10,
                  fontWeight:800, textTransform:'uppercase', letterSpacing:0.6, color:C.muted }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {ATTACK_TYPES.map((a,i)=>(
              <tr key={i} style={{ borderBottom: i<ATTACK_TYPES.length-1 ? '1px solid rgba(255,255,255,0.04)' : 'none' }}>
                <td style={{ padding:'11px 20px' }}>
                  <span style={{ display:'inline-flex', alignItems:'center', gap:8, fontWeight:600 }}>
                    <span style={{ width:8, height:8, borderRadius:'50%', background:a.color }}/>
                    {a.type}
                  </span>
                </td>
                <td style={{ padding:'11px 20px', color:C.muted, fontSize:11.5 }}>{a.detected}</td>
                <td style={{ padding:'11px 20px' }}><CoverageBadge level={a.coverage}/></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── Onboarding checklist (generic, any customer) ── */}
      <div style={{ fontSize:11, fontWeight:800, letterSpacing:1.5, textTransform:'uppercase',
        color:C.teal, marginBottom:16, display:'flex', alignItems:'center', gap:10 }}>
        Onboard a new customer — same 6 steps, any country
        <div style={{ flex:1, height:1, background:`linear-gradient(90deg,${C.border},transparent)` }}/>
      </div>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:12, marginBottom:20 }}>
        {[
          { n:1, icon:'🏢', title:'Identify platform', desc:'Ask which mail system they use — Gmail, M365, custom server, etc.' },
          { n:2, icon:'🔑', title:'Collect credentials', desc:'Platform-specific — API key, service account, or app registration' },
          { n:3, icon:'🔌', title:'Register connector', desc:'One API call to /api/connectors — takes under a minute' },
          { n:4, icon:'🧪', title:'Test connection', desc:'Built-in test button confirms access before going live' },
          { n:5, icon:'🔔', title:'Configure notifications', desc:'Set admin email(s), confidence threshold, channels' },
          { n:6, icon:'✅', title:'Monitor & tune', desc:'1-week observation period, review false positives, go full production' },
        ].map((s,i)=>(
          <div key={i} style={{ background:C.card, border:`1px solid ${C.border}`,
            borderRadius:12, padding:'16px 18px', display:'flex', gap:14, alignItems:'flex-start' }}>
            <div style={{ width:32, height:32, borderRadius:'50%', background:C.tealDim,
              border:`1.5px solid ${C.teal}55`, display:'flex', alignItems:'center',
              justifyContent:'center', fontSize:13, fontWeight:900, color:C.teal, flexShrink:0 }}>{s.n}</div>
            <div>
              <div style={{ fontSize:13, fontWeight:700, marginBottom:3 }}>{s.icon} {s.title}</div>
              <div style={{ fontSize:11.5, color:C.muted, lineHeight:1.5 }}>{s.desc}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Footer note */}
      <div style={{ textAlign:'center', fontSize:11, color:C.muted, paddingTop:20,
        borderTop:`1px solid ${C.border}` }}>
        This platform is region- and provider-agnostic — the same AI engine, pipeline, and
        dashboard serve every customer regardless of country or mail infrastructure.
      </div>

    </div>
  );
}
