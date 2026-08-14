import { useState, useEffect, useRef, useCallback } from 'react';
import { LiveEmailAnalysis } from './LiveEmailAnalysis';
import { themeColors as C } from '../utils/themeColors';

// ── Agent definitions ─────────────────────────────────────────
const AGENTS = [
  {
    id:'api',
    step:1,
    label:'API Integration Agent',
    icon:'🔌',
    color:C.blue,
    dim:C.blueDim,
    role:'Connects to Proofpoint APIs',
    detail:'Ingests emails, alerts, logs, and events from customer platforms in real-time.',
    output:'Raw security event forwarded to AI Orchestrator',
    metrics:[
      { label:'Events/min', value:'247' },
      { label:'Platforms',  value:'5'   },
      { label:'Latency',    value:'12ms' },
    ],
  },
  {
    id:'orchestrator',
    step:2,
    label:'AI Orchestrator',
    icon:'🧠',
    color:C.teal,
    dim:C.tealDim,
    role:'Routes requests across all agents',
    detail:'Acts as the brain — decides which agents to run, in what order, and what data to pass. Does NOT analyze threats itself.',
    output:'Execution plan created with 9 agent tasks',
    metrics:[
      { label:'Active Tasks', value:'9'    },
      { label:'Workflows/hr', value:'1,840'},
      { label:'Accuracy',     value:'99.2%' },
    ],
    isBrain: true,
  },
  {
    id:'event-processing',
    step:3,
    label:'Event Processing Agent',
    icon:'⚙️',
    color:C.blue,
    dim:C.blueDim,
    role:'Normalizes and parses raw events',
    detail:'Validates JSON, removes duplicates, standardizes field names, converts vendor-specific formats into common schema.',
    output:'Clean structured event ready for analysis',
    metrics:[
      { label:'Processed',   value:'3.2M' },
      { label:'Duplicates',  value:'12%'  },
      { label:'Parse time',  value:'8ms'  },
    ],
  },
  {
    id:'ioc-extraction',
    step:4,
    label:'IOC Extraction Agent',
    icon:'🔍',
    color:C.purple,
    dim:C.purpleDim,
    role:'Extracts Indicators of Compromise',
    detail:'Identifies sender email, domain, recipient, URLs, attachment hashes, subjects, timestamps from every event.',
    output:'11 IOCs extracted from event',
    metrics:[
      { label:'IOC Types',  value:'11'   },
      { label:'Extracted',  value:'847K' },
      { label:'Accuracy',   value:'98.7%' },
    ],
    iocs:['Sender Email','Sender Domain','Recipient','URLs','Attachments','Hash','Subject','Timestamp','IP Address','Headers','Customer'],
  },
  {
    id:'threat-classification',
    step:'5A',
    label:'Threat Classification Agent',
    icon:'🎯',
    color:C.red,
    dim:C.redDim,
    role:'Classifies threat type using ML/NLP',
    detail:'AI model analyzes fake domains, password reset requests, urgent wording, executable attachments, suspicious URLs. Maps to MITRE ATT&CK.',
    output:'Credential Phishing — 99% confidence — T1566',
    metrics:[
      { label:'Confidence', value:'99%'  },
      { label:'MITRE',      value:'T1566'},
      { label:'Speed',      value:'180ms'},
    ],
  },
  {
    id:'threat-intelligence',
    step:'5B',
    label:'Threat Intelligence Agent',
    icon:'🌐',
    color:C.orange,
    dim:C.orangeDim,
    role:'Enriches IOCs with external intelligence',
    detail:'Checks VirusTotal, WHOIS, DNS, internal threat DB, reputation services. Domain age, previous reports, hosting country, known campaigns.',
    output:'Domain: 2 days old, Russian hosting, known campaign',
    metrics:[
      { label:'Sources',  value:'12'   },
      { label:'Enriched', value:'94%'  },
      { label:'Cache hit','value':'67%' },
    ],
    checks:[
      { label:'VirusTotal',     result:'Malicious',          color:C.red    },
      { label:'Domain Age',     result:'2 days',             color:C.red    },
      { label:'WHOIS',          result:'Russia',             color:C.orange },
      { label:'Known Campaign', result:'MS Credential Theft',color:C.red    },
      { label:'Reputation',     result:'Blacklisted',        color:C.red    },
    ],
  },
  {
    id:'threat-correlation',
    step:6,
    label:'Threat Correlation Agent',
    icon:'🔗',
    color:C.green,
    dim:C.greenDim,
    role:'Correlates IOCs across all customers',
    detail:'Searches Vector DB and Graph DB to find similar attacks. Identifies relationships between sender, domain, URL, customers, campaigns.',
    output:'Campaign-2026-105 — 3 customers affected',
    metrics:[
      { label:'Customers hit', value:'3'          },
      { label:'Campaign ID',   value:'2026-105'   },
      { label:'Similar IOCs',  value:'47'         },
    ],
    correlations:[
      { customer:'Customer A', match:'Same URL',            color:C.red    },
      { customer:'Customer B', match:'Same Sender Domain',  color:C.red    },
      { customer:'Customer C', match:'Same Attachment Hash',color:C.orange },
    ],
  },
  {
    id:'risk-assessment',
    step:7,
    label:'Risk Assessment Agent',
    icon:'📊',
    color:C.yellow,
    dim:'rgba(234,179,8,0.12)',
    role:'Calculates overall business risk score',
    detail:'Considers malicious domain, new registration, dangerous attachment, multiple affected customers, reputation, and campaign detection.',
    output:'Risk Score: 98/100 — CRITICAL',
    metrics:[
      { label:'Risk Score', value:'98/100'  },
      { label:'Severity',   value:'CRITICAL'},
      { label:'Factors',    value:'6'       },
    ],
  },
  {
    id:'orchestrator-decision',
    step:8,
    label:'AI Orchestrator Decision',
    icon:'⚡',
    color:C.teal,
    dim:C.tealDim,
    role:'Makes decisions based on risk, policy, confidence',
    detail:'Receives outputs from all agents, applies company policies, decides actions. Delegates to specialized agents — does not act itself.',
    output:'6 actions triggered across 4 agents',
    metrics:[
      { label:'Actions',    value:'6'      },
      { label:'Policy',     value:'Auto'   },
      { label:'Time',       value:'<100ms' },
    ],
    decisions:[
      '✅ Store Threat Intelligence',
      '✅ Update Dashboard',
      '✅ Notify IT Admin (Critical)',
      '✅ Notify Affected Users',
      '✅ Notify SOC Team',
      '✅ Update Global Blacklist',
      '✅ Share with Other Customers',
    ],
  },
  {
    id:'blacklist',
    step:'9A',
    label:'Blacklist Agent',
    icon:'🚫',
    color:C.red,
    dim:C.redDim,
    role:'Adds malicious IOCs to blacklist',
    detail:'Automatically blocks sender email, domain, and attachment hash. Future identical emails are blocked immediately without re-analysis.',
    output:'3 IOCs added to global blacklist',
    metrics:[
      { label:'Added',       value:'3'    },
      { label:'Total IOCs',  value:'247K' },
      { label:'Block time',  value:'<1ms' },
    ],
    blocked:['support@micr0soft-login.com','micr0soft-login.com','SHA256: a3f8c2...'],
  },
  {
    id:'notification',
    step:'9B',
    label:'Notification Agent',
    icon:'🔔',
    color:C.orange,
    dim:C.orangeDim,
    role:'Sends alerts and notifications to teams',
    detail:'Delivers targeted notifications to IT Admin, affected end-user, and Virus Rescuers SOC Team via email, Slack, Teams, webhook.',
    output:'3 notifications sent — Admin + User + SOC',
    metrics:[
      { label:'Notified',    value:'3'    },
      { label:'Channels',    value:'4'    },
      { label:'Delivery',    value:'100%' },
    ],
    notifications:[
      {
        to:'IT Administrator',
        icon:'👤',
        color:C.red,
        lines:['🚨 CRITICAL: Credential Phishing','Sender: support@micr0soft-login.com','Risk Score: 98 | Campaign-2026-105','Action: Review blocked email immediately'],
      },
      {
        to:'Employee (john@abcbank.com)',
        icon:'📧',
        color:C.blue,
        lines:['🛡️ A malicious email was blocked','No action required from you','Contact IT if you expected this email'],
      },
      {
        to:'Virus Rescuers SOC Team',
        icon:'🛡️',
        color:C.orange,
        lines:['New phishing campaign detected','Affected Customers: 3','Severity: Critical | Blacklist Updated'],
      },
    ],
  },
  {
    id:'analytics',
    step:'9C',
    label:'Analytics Agent',
    icon:'📈',
    color:C.green,
    dim:C.greenDim,
    role:'Generates dashboards, metrics and insights',
    detail:'Updates all customer dashboards in real-time. Generates trend charts, threat breakdowns, campaign analysis, KPI metrics.',
    output:'Dashboard updated — 328 threats today',
    metrics:[
      { label:'Threats Today', value:'328' },
      { label:'Critical',      value:'12'  },
      { label:'Campaigns',     value:'3'   },
    ],
  },
  {
    id:'report',
    step:'9D',
    label:'Report Agent',
    icon:'📄',
    color:C.purple,
    dim:C.purpleDim,
    role:'Creates detailed reports for stakeholders',
    detail:'Generates Daily SOC Report, Customer-wise Report, Executive Summary, Compliance Report, Weekly Threat Trends. Export as PDF, Excel, CSV.',
    output:'5 report types generated',
    metrics:[
      { label:'Report Types', value:'5'      },
      { label:'Formats',      value:'PDF/XLS/CSV' },
      { label:'Auto-schedule','value':'Daily' },
    ],
    reports:['Daily SOC Report','Customer-wise Report','Executive Summary','Compliance Report','Weekly Threat Trends'],
  },
  {
    id:'central-data',
    step:10,
    label:'Central Data Platform',
    icon:'🗄️',
    color:C.blue,
    dim:C.blueDim,
    role:'Stores events, IOCs, intelligence, decisions',
    detail:'Four storage layers: Threat Intelligence DB (IOCs, scores, campaigns), Historical Repository (events, headers, timeline), Vector DB (semantic similarity), Graph DB (entity relationships).',
    output:'Event stored across 4 database layers',
    metrics:[
      { label:'DB Layers',    value:'4'   },
      { label:'Total Records','value':'12M'},
      { label:'Retention',    value:'1yr' },
    ],
    databases:[
      { name:'Threat Intelligence DB', desc:'IOCs, scores, campaigns, reputation',   icon:'🛡️' },
      { name:'Historical Repository',   desc:'Events, headers, timeline, metadata',   icon:'📜' },
      { name:'Vector Database',         desc:'Semantic representations for similarity',icon:'🔢' },
      { name:'Graph Database',          desc:'Sender→Domain→URL→Customer→Campaign',   icon:'🕸️' },
    ],
  },
  {
    id:'cross-customer',
    step:11,
    label:'Cross-Customer Protection Loop',
    icon:'🛡️',
    color:C.green,
    dim:C.greenDim,
    role:'Shares intelligence across all customers',
    detail:'When the same phishing email arrives at Customer XYZ hours later, it is blocked IMMEDIATELY without re-analysis — already in global blacklist.',
    output:'Future email blocked in <1ms — zero re-analysis needed',
    metrics:[
      { label:'Protected',   value:'All Customers' },
      { label:'Block time',  value:'<1ms'          },
      { label:'Re-analysis', value:'None needed'   },
    ],
  },
];

// ── Flow connections (which steps connect) ────────────────────
const FLOW = [
  ['api','orchestrator'],
  ['orchestrator','event-processing'],
  ['orchestrator','ioc-extraction'],
  ['orchestrator','threat-classification'],
  ['orchestrator','threat-intelligence'],
  ['orchestrator','threat-correlation'],
  ['orchestrator','risk-assessment'],
  ['orchestrator','orchestrator-decision'],
  ['orchestrator-decision','blacklist'],
  ['orchestrator-decision','notification'],
  ['orchestrator-decision','analytics'],
  ['orchestrator-decision','report'],
  ['blacklist','central-data'],
  ['notification','central-data'],
  ['analytics','central-data'],
  ['report','central-data'],
  ['central-data','cross-customer'],
];

// ── Agent card ────────────────────────────────────────────────
function AgentCard({ agent, active, onClick, processing, done }) {
  const isActive = active?.id === agent.id;
  return (
    <div
      onClick={() => onClick(agent)}
      style={{
        background: isActive ? agent.dim : 'rgba(255,255,255,0.03)',
        border: `2px solid ${isActive ? agent.color : processing ? `${agent.color}44` : 'rgba(255,255,255,0.08)'}`,
        borderRadius: 14,
        padding: '14px 16px',
        cursor: 'pointer',
        transition: 'all 0.2s',
        position: 'relative',
        overflow: 'hidden',
        transform: isActive ? 'scale(1.02)' : 'scale(1)',
        boxShadow: isActive ? `0 0 24px ${agent.color}33` : 'none',
      }}
      onMouseOver={e => { if (!isActive) e.currentTarget.style.borderColor = `${agent.color}66`; }}
      onMouseOut={e => { if (!isActive) e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'; }}
    >
      {/* Status indicator */}
      <div style={{
        position: 'absolute', top: 10, right: 10,
        width: 8, height: 8, borderRadius: '50%',
        background: done ? C.green : processing ? agent.color : 'rgba(255,255,255,0.2)',
        boxShadow: (done || processing) ? `0 0 8px ${done ? C.green : agent.color}` : 'none',
        animation: processing ? 'agentPulse 1s infinite' : 'none',
      }}/>

      {/* Processing bar */}
      {processing && (
        <div style={{
          position: 'absolute', bottom: 0, left: 0,
          height: 3, background: agent.color,
          animation: 'agentProgress 2s ease-in-out infinite',
        }}/>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
        <div style={{
          width: 36, height: 36, borderRadius: 10, flexShrink: 0,
          background: agent.dim, border: `1.5px solid ${agent.color}44`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 18,
        }}>{agent.icon}</div>
        <div>
          <div style={{ fontSize: 10, color: agent.color, fontWeight: 700,
            textTransform: 'uppercase', letterSpacing: 0.6 }}>
            Step {agent.step}
          </div>
          <div style={{ fontSize: 12, fontWeight: 700, color: C.white,
            lineHeight: 1.2 }}>{agent.label}</div>
        </div>
      </div>
      <div style={{ fontSize: 10, color: C.muted, lineHeight: 1.4 }}>
        {agent.role}
      </div>
      {done && (
        <div style={{ marginTop: 6, fontSize: 10, color: C.green,
          fontWeight: 600 }}>✓ {agent.output}</div>
      )}
    </div>
  );
}

// ── Agent detail panel ────────────────────────────────────────
function AgentDetail({ agent, onClose }) {
  if (!agent) return null;

  return (
    <div style={{
      background: C.bgCard,
      border: `2px solid ${agent.color}55`,
      borderRadius: 16,
      padding: 24,
      height: '100%',
      overflowY: 'auto',
      boxShadow: `0 0 40px ${agent.color}22`,
      position: 'relative',
    }}>
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0,
        height: 4,
        background: `linear-gradient(90deg,${agent.color},transparent)` }}/>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center',
        gap: 14, marginBottom: 20 }}>
        <div style={{
          width: 56, height: 56, borderRadius: 14,
          background: agent.dim, border: `2px solid ${agent.color}55`,
          display: 'flex', alignItems: 'center',
          justifyContent: 'center', fontSize: 28,
          flexShrink: 0,
        }}>{agent.icon}</div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 11, color: agent.color, fontWeight: 700,
            textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 3 }}>
            Step {agent.step} — Agent Detail
          </div>
          <div style={{ fontSize: 17, fontWeight: 800,
            color: C.white }}>{agent.label}</div>
          <div style={{ fontSize: 11, color: C.muted,
            marginTop: 2 }}>{agent.role}</div>
        </div>
        <button onClick={onClose} style={{
          background: 'rgba(255,255,255,0.06)',
          border: '1px solid rgba(255,255,255,0.12)',
          borderRadius: 8, width: 32, height: 32,
          cursor: 'pointer', color: C.muted,
          fontSize: 14, display: 'flex', alignItems: 'center',
          justifyContent: 'center', flexShrink: 0,
        }}>✕</button>
      </div>

      {/* Description */}
      <div style={{
        background: agent.dim, border: `1px solid ${agent.color}33`,
        borderRadius: 10, padding: 14, marginBottom: 16,
        fontSize: 12, color: '#c5d8f5', lineHeight: 1.7,
      }}>
        {agent.detail}
      </div>

      {/* Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)',
        gap: 10, marginBottom: 16 }}>
        {agent.metrics.map((m, i) => (
          <div key={i} style={{
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: 10, padding: '10px 12px', textAlign: 'center',
          }}>
            <div style={{ fontSize: 9, color: C.muted,
              textTransform: 'uppercase', letterSpacing: 0.5,
              marginBottom: 4 }}>{m.label}</div>
            <div style={{ fontSize: 18, fontWeight: 800,
              color: agent.color, fontFamily: 'monospace' }}>{m.value}</div>
          </div>
        ))}
      </div>

      {/* Output */}
      <div style={{
        background: `${C.green}11`, border: `1px solid ${C.green}33`,
        borderRadius: 10, padding: '10px 14px', marginBottom: 16,
        display: 'flex', alignItems: 'center', gap: 10,
        fontSize: 12, color: C.green,
      }}>
        <span>✅</span>
        <div>
          <div style={{ fontWeight: 700, marginBottom: 2 }}>Output</div>
          <div style={{ color: '#c5d8f5' }}>{agent.output}</div>
        </div>
      </div>

      {/* IOCs */}
      {agent.iocs && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.muted,
            textTransform: 'uppercase', letterSpacing: 0.8,
            marginBottom: 8 }}>IOC Types Extracted</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {agent.iocs.map((ioc, i) => (
              <span key={i} style={{
                padding: '3px 10px', borderRadius: 20, fontSize: 11,
                fontWeight: 600,
                background: agent.dim, border: `1px solid ${agent.color}44`,
                color: agent.color,
              }}>{ioc}</span>
            ))}
          </div>
        </div>
      )}

      {/* Intelligence checks */}
      {agent.checks && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.muted,
            textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>
            Intelligence Sources
          </div>
          {agent.checks.map((c, i) => (
            <div key={i} style={{
              display: 'flex', justifyContent: 'space-between',
              padding: '7px 12px', borderRadius: 7,
              background: 'rgba(255,255,255,0.03)',
              border: '1px solid rgba(255,255,255,0.06)',
              marginBottom: 4, fontSize: 12,
            }}>
              <span style={{ color: C.muted }}>{c.label}</span>
              <span style={{ color: c.color, fontWeight: 700 }}>{c.result}</span>
            </div>
          ))}
        </div>
      )}

      {/* Correlations */}
      {agent.correlations && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.muted,
            textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>
            Cross-Customer Correlations
          </div>
          {agent.correlations.map((c, i) => (
            <div key={i} style={{
              display: 'flex', justifyContent: 'space-between',
              padding: '8px 12px', borderRadius: 7,
              background: `${c.color}11`,
              border: `1px solid ${c.color}33`, marginBottom: 4,
              fontSize: 12,
            }}>
              <span style={{ color: C.white, fontWeight: 600 }}>{c.customer}</span>
              <span style={{ color: c.color }}>{c.match}</span>
            </div>
          ))}
        </div>
      )}

      {/* Decisions */}
      {agent.decisions && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.muted,
            textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>
            Actions Triggered
          </div>
          {agent.decisions.map((d, i) => (
            <div key={i} style={{
              padding: '7px 12px', borderRadius: 7,
              background: `${C.green}08`,
              border: `1px solid ${C.green}22`, marginBottom: 4,
              fontSize: 12, color: '#c5d8f5',
            }}>{d}</div>
          ))}
        </div>
      )}

      {/* Blocked IOCs */}
      {agent.blocked && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.muted,
            textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>
            IOCs Added to Global Blacklist
          </div>
          {agent.blocked.map((b, i) => (
            <div key={i} style={{
              padding: '7px 12px', borderRadius: 7,
              background: `${C.red}10`,
              border: `1px solid ${C.red}33`, marginBottom: 4,
              fontSize: 11, color: C.red,
              fontFamily: 'monospace',
            }}>🚫 {b}</div>
          ))}
        </div>
      )}

      {/* Notifications */}
      {agent.notifications && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.muted,
            textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>
            Notifications Sent
          </div>
          {agent.notifications.map((n, i) => (
            <div key={i} style={{
              background: `${n.color}10`,
              border: `1px solid ${n.color}33`,
              borderRadius: 10, padding: '10px 14px', marginBottom: 8,
            }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: n.color,
                marginBottom: 6 }}>{n.icon} To: {n.to}</div>
              {n.lines.map((line, j) => (
                <div key={j} style={{ fontSize: 11, color: '#c5d8f5',
                  marginBottom: 2, lineHeight: 1.5 }}>{line}</div>
              ))}
            </div>
          ))}
        </div>
      )}

      {/* Database layers */}
      {agent.databases && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.muted,
            textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>
            Storage Layers
          </div>
          {agent.databases.map((db, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'center', gap: 12,
              padding: '10px 12px', borderRadius: 8,
              background: `${agent.color}08`,
              border: `1px solid ${agent.color}22`, marginBottom: 6,
            }}>
              <span style={{ fontSize: 20, flexShrink: 0 }}>{db.icon}</span>
              <div>
                <div style={{ fontSize: 12, fontWeight: 700,
                  color: agent.color }}>{db.name}</div>
                <div style={{ fontSize: 10, color: C.muted }}>{db.desc}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Reports */}
      {agent.reports && (
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.muted,
            textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>
            Report Types Generated
          </div>
          {agent.reports.map((r, i) => (
            <div key={i} style={{
              padding: '7px 12px', borderRadius: 7,
              background: agent.dim,
              border: `1px solid ${agent.color}33`,
              marginBottom: 4, fontSize: 12, color: C.white,
              display: 'flex', alignItems: 'center', gap: 8,
            }}>
              <span style={{ color: agent.color }}>📄</span>{r}
              <span style={{ marginLeft: 'auto', fontSize: 10,
                color: C.muted }}>PDF · XLS · CSV</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────
export default function AIOrchestrationPage() {
  const [activeAgent,   setActiveAgent]   = useState(AGENTS[1]); // start on Orchestrator
  const [runningAgents, setRunningAgents] = useState(new Set());
  const [doneAgents,    setDoneAgents]    = useState(new Set());
  const [simulating,    setSimulating]    = useState(false);
  const [simStep,       setSimStep]       = useState(0);
  const [showExample,   setShowExample]   = useState(false);
  const [mode, setMode] = useState('live'); // 'live' | 'demo'
  const simRef = useRef(null);

  // Simulate full pipeline
  const runSimulation = useCallback(() => {
    if (simulating) {
      clearInterval(simRef.current);
      setSimulating(false);
      setRunningAgents(new Set());
      setDoneAgents(new Set());
      setSimStep(0);
      return;
    }
    setSimulating(true);
    setRunningAgents(new Set());
    setDoneAgents(new Set());
    setSimStep(0);
    let step = 0;

    simRef.current = setInterval(() => {
      if (step >= AGENTS.length) {
        clearInterval(simRef.current);
        setSimulating(false);
        return;
      }
      const agent = AGENTS[step];
      setActiveAgent(agent);
      setRunningAgents(prev => new Set([...prev, agent.id]));
      setTimeout(() => {
        setRunningAgents(prev => {
          const n = new Set(prev); n.delete(agent.id); return n;
        });
        setDoneAgents(prev => new Set([...prev, agent.id]));
      }, 1800);
      setSimStep(step);
      step++;
    }, 2200);
  }, [simulating]);

  useEffect(() => () => clearInterval(simRef.current), []);

  const progress = Math.round((doneAgents.size / AGENTS.length) * 100);

  return (
    <div style={{
      minHeight: '100vh',
      background: 'var(--bg-primary)',
      color: 'var(--text-primary)',
      fontFamily: '"Inter",-apple-system,sans-serif',
      padding: '20px 24px',
    }}>

      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center',
          justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{
                width: 40, height: 40, borderRadius: 10,
                background: C.tealDim, border: `2px solid ${C.teal}55`,
                display: 'flex', alignItems: 'center',
                justifyContent: 'center', fontSize: 20,
              }}>🧠</div>
              <div>
                <h1 style={{ fontSize: 20, fontWeight: 900, margin: 0,
                  background: `linear-gradient(135deg,${C.white},${C.teal})`,
                  WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
                }}>AI Orchestration & Multi-Agent Workflow</h1>
                <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>
                  Complete AI pipeline — 11 specialized agents — Virus Rescuers Platform
                </div>
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            {/* Mode toggle */}
            <div style={{ display:'flex', background:'rgba(255,255,255,0.04)',
              border:'1px solid rgba(255,255,255,0.1)', borderRadius:10, padding:3 }}>
              {[
                { id:'live', label:'🔴 Live Analysis' },
                { id:'demo', label:'▶ Demo Simulation' },
              ].map(m => (
                <button key={m.id} onClick={() => setMode(m.id)} style={{
                  padding:'6px 14px', borderRadius:8, border:'none',
                  cursor:'pointer', fontSize:12, fontWeight:700,
                  background: mode===m.id ? '#00bfa5' : 'transparent',
                  color: mode===m.id ? 'var(--bg-primary)' : C.muted,
                  transition:'all 0.15s',
                }}>{m.label}</button>
              ))}
            </div>
            {mode === 'demo' && (
              <button onClick={() => setShowExample(v => !v)} style={{
                padding: '8px 16px', borderRadius: 8, fontSize: 12,
                fontWeight: 600, cursor: 'pointer',
                border: `1px solid ${C.purple}55`,
                background: showExample ? C.purpleDim : 'transparent',
                color: showExample ? '#c4b5fd' : C.muted,
              }}>
                📧 {showExample ? 'Hide' : 'Show'} Example Email
              </button>
            )}
            {mode === 'demo' && (
              <button onClick={runSimulation} style={{
                padding: '8px 20px', borderRadius: 8, fontSize: 13,
                fontWeight: 700, cursor: 'pointer',
                border: `1px solid ${simulating ? C.red : C.teal}`,
                background: simulating
                  ? `rgba(239,68,68,0.15)` : C.tealDim,
                color: simulating ? C.red : C.teal,
                display: 'flex', alignItems: 'center', gap: 8,
              }}>
                {simulating ? '⏹ Stop Simulation' : '▶ Run Full Pipeline'}
              </button>
            )}
          </div>
        </div>

        {/* Example email */}
        {showExample && (
          <div style={{
            marginTop: 14, padding: 16,
            background: 'rgba(124,58,237,0.08)',
            border: '1px solid rgba(124,58,237,0.3)',
            borderRadius: 12, fontSize: 12,
          }}>
            <div style={{ fontWeight: 700, color: '#c4b5fd',
              marginBottom: 10 }}>📧 Example Phishing Email</div>
            <div style={{ display: 'grid',
              gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ fontFamily: 'monospace', fontSize: 11,
                lineHeight: 1.8, color: '#c5d8f5' }}>
                <div><span style={{ color: C.muted }}>From: </span>
                  <span style={{ color: C.red }}>support@micr0soft-login.com</span></div>
                <div><span style={{ color: C.muted }}>To: </span>
                  john@abcbank.com</div>
                <div><span style={{ color: C.muted }}>Subject: </span>
                  <span style={{ color: C.yellow }}>
                    Your Microsoft 365 Password Will Expire Today
                  </span></div>
                <div style={{ marginTop: 8, color: C.muted }}>Body:</div>
                <div style={{ color: '#c5d8f5' }}>
                  Click below immediately to avoid account suspension.
                </div>
                <div style={{ color: C.red, textDecoration: 'underline' }}>
                  https://micr0soft-login.com/reset-password
                </div>
                <div style={{ marginTop: 6 }}>
                  <span style={{ color: C.muted }}>Attachment: </span>
                  <span style={{ color: C.red }}>Invoice.pdf.exe</span>
                </div>
              </div>
              <div>
                <div style={{ fontSize: 11, fontWeight: 700,
                  color: C.red, marginBottom: 8 }}>🚨 Threat Indicators</div>
                {[
                  { issue:'Misspelled domain', detail:'micr0soft vs microsoft', color: C.red    },
                  { issue:'Urgent wording',     detail:'Expire Today',          color: C.orange  },
                  { issue:'Malicious URL',      detail:'Fake login page',       color: C.red    },
                  { issue:'Executable file',    detail:'.pdf.exe extension',    color: C.red    },
                  { issue:'Credential harvest', detail:'Password reset lure',   color: C.orange  },
                ].map((t, i) => (
                  <div key={i} style={{ display: 'flex', gap: 8,
                    marginBottom: 6, fontSize: 11 }}>
                    <span style={{ color: t.color, flexShrink: 0 }}>•</span>
                    <div>
                      <span style={{ color: t.color, fontWeight: 600 }}>{t.issue}</span>
                      <span style={{ color: C.muted }}> — {t.detail}</span>
                    </div>
                  </div>
                ))}
                <div style={{ marginTop: 10, padding: '8px 12px',
                  background: `${C.red}15`, border: `1px solid ${C.red}33`,
                  borderRadius: 8, fontSize: 11, color: C.red, fontWeight: 700 }}>
                  🚫 Proofpoint: BLOCKED and reported to Virus Rescuers
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Progress bar */}
        {(simulating || doneAgents.size > 0) && (
          <div style={{ marginTop: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between',
              fontSize: 11, color: C.muted, marginBottom: 5 }}>
              <span>Pipeline Progress</span>
              <span style={{ color: C.teal, fontWeight: 700 }}>
                {doneAgents.size}/{AGENTS.length} agents complete — {progress}%
              </span>
            </div>
            <div style={{ height: 6, background: 'rgba(255,255,255,0.06)',
              borderRadius: 3, overflow: 'hidden' }}>
              <div style={{
                height: '100%', borderRadius: 3,
                width: `${progress}%`,
                background: `linear-gradient(90deg,${C.teal},${C.blue})`,
                transition: 'width 0.5s ease',
              }}/>
            </div>
          </div>
        )}
      </div>

      {/* Main layout: agent grid + detail panel */}
      {mode === 'live' ? (
        <LiveEmailAnalysis />
      ) : (
        <>

      <div style={{ display: 'grid',
        gridTemplateColumns: '1fr 380px', gap: 16, alignItems: 'start' }}>

        {/* Left: agent grid */}
        <div>
          {/* Top flow: linear */}
          <div style={{ display: 'grid',
            gridTemplateColumns: 'repeat(4,1fr)', gap: 10, marginBottom: 12 }}>
            {AGENTS.slice(0, 4).map(agent => (
              <AgentCard key={agent.id} agent={agent}
                active={activeAgent}
                processing={runningAgents.has(agent.id)}
                done={doneAgents.has(agent.id)}
                onClick={setActiveAgent}/>
            ))}
          </div>

          {/* Orchestrator Decision hub */}
          <div style={{ position: 'relative', marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center',
              gap: 10, marginBottom: 10 }}>
              <div style={{ flex: 1, height: 1,
                background: 'rgba(255,255,255,0.06)' }}/>
              <div style={{
                fontSize: 10, color: C.muted, fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: 1,
                whiteSpace: 'nowrap', padding: '0 8px',
              }}>
                ⬇ AI Orchestrator routes to parallel agents
              </div>
              <div style={{ flex: 1, height: 1,
                background: 'rgba(255,255,255,0.06)' }}/>
            </div>
            <div style={{ display: 'grid',
              gridTemplateColumns: 'repeat(4,1fr)', gap: 10, marginBottom: 12 }}>
              {AGENTS.slice(4, 8).map(agent => (
                <AgentCard key={agent.id} agent={agent}
                  active={activeAgent}
                  processing={runningAgents.has(agent.id)}
                  done={doneAgents.has(agent.id)}
                  onClick={setActiveAgent}/>
              ))}
            </div>
          </div>

          {/* Decision + 4 action agents */}
          <div style={{ marginBottom: 12 }}>
            <div style={{ display: 'grid',
              gridTemplateColumns: '1fr', gap: 10, marginBottom: 10 }}>
              <AgentCard agent={AGENTS[8]}
                active={activeAgent}
                processing={runningAgents.has(AGENTS[8].id)}
                done={doneAgents.has(AGENTS[8].id)}
                onClick={setActiveAgent}/>
            </div>
            <div style={{ display: 'flex', alignItems: 'center',
              gap: 10, marginBottom: 10 }}>
              <div style={{ flex: 1, height: 1,
                background: 'rgba(255,255,255,0.06)' }}/>
              <span style={{ fontSize: 10, color: C.muted,
                whiteSpace: 'nowrap', padding: '0 8px' }}>
                ⬇ Delegates to 4 specialized action agents
              </span>
              <div style={{ flex: 1, height: 1,
                background: 'rgba(255,255,255,0.06)' }}/>
            </div>
            <div style={{ display: 'grid',
              gridTemplateColumns: 'repeat(4,1fr)', gap: 10 }}>
              {AGENTS.slice(9, 13).map(agent => (
                <AgentCard key={agent.id} agent={agent}
                  active={activeAgent}
                  processing={runningAgents.has(agent.id)}
                  done={doneAgents.has(agent.id)}
                  onClick={setActiveAgent}/>
              ))}
            </div>
          </div>

          {/* Final: Central Data + Cross-customer */}
          <div style={{ display: 'grid',
            gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            {AGENTS.slice(13).map(agent => (
              <AgentCard key={agent.id} agent={agent}
                active={activeAgent}
                processing={runningAgents.has(agent.id)}
                done={doneAgents.has(agent.id)}
                onClick={setActiveAgent}/>
            ))}
          </div>

          {/* Stats bar */}
          <div style={{
            marginTop: 16, padding: '12px 16px',
            background: 'rgba(255,255,255,0.03)',
            border: '1px solid rgba(255,255,255,0.06)',
            borderRadius: 12,
            display: 'flex', gap: 24, flexWrap: 'wrap', justifyContent: 'center',
          }}>
            {[
              { label:'Total Agents',      value:'11',     color:C.teal   },
              { label:'Processing Steps',  value:'15',     color:C.blue   },
              { label:'Avg Pipeline Time', value:'<2s',    color:C.green  },
              { label:'Threats/day',       value:'3,800+', color:C.orange },
              { label:'Customers Protected','value':'∞',   color:C.purple },
              { label:'Accuracy',          value:'99.2%',  color:C.green  },
            ].map((s, i) => (
              <div key={i} style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 18, fontWeight: 900,
                  color: s.color, fontFamily: 'monospace' }}>{s.value}</div>
                <div style={{ fontSize: 9, color: C.muted,
                  textTransform: 'uppercase', letterSpacing: 0.5 }}>{s.label}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: detail panel */}
        <div style={{ position: 'sticky', top: 20 }}>
          <AgentDetail agent={activeAgent} onClose={() => setActiveAgent(null)}/>
          {!activeAgent && (
            <div style={{ background: C.bgCard,
              border: '1px solid rgba(255,255,255,0.06)',
              borderRadius: 16, padding: 48, textAlign: 'center' }}>
              <div style={{ fontSize: 36, marginBottom: 12 }}>👆</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: C.white,
                marginBottom: 6 }}>Click any agent to see details</div>
              <div style={{ fontSize: 12, color: C.muted }}>
                Or click Run Full Pipeline to watch the AI process a phishing email
              </div>
            </div>
          )}
        </div>
      </div>

        </>
      )}

      <style>{`
        @keyframes agentPulse {
          0%,100% { opacity:1; transform:scale(1); }
          50%      { opacity:0.5; transform:scale(1.5); }
        }
        @keyframes agentProgress {
          0%   { width:0%; }
          100% { width:100%; }
        }
      `}</style>
    </div>
  );
}
