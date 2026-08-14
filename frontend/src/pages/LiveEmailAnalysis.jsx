// ============================================================
// LIVE EMAIL ANALYSIS MODE
// Add this to AIOrchestrationPage.jsx — replaces/supplements
// the scripted demo with REAL email processing.
//
// Integration: paste this component into AIOrchestrationPage.jsx
// and add a mode toggle between 'demo' and 'live'.
// ============================================================

import { useState } from 'react';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const STAGE_COLORS = {
  'api':                    '#1565e8',
  'orchestrator':           '#00bfa5',
  'event-processing':       '#1565e8',
  'ioc-extraction':         '#7c3aed',
  'threat-classification':  '#ef4444',
  'threat-intelligence':    '#f97316',
  'ai-analysis':            '#a855f7',
  'threat-correlation':     '#10b981',
  'risk-assessment':        '#eab308',
  'orchestrator-decision':  '#00bfa5',
  'blacklist':              '#ef4444',
  'notification':           '#f97316',
  'analytics':              '#10b981',
  'report':                 '#7c3aed',
  'central-data':           '#1565e8',
  'cross-customer':         '#10b981',
};

const STATUS_STYLE = {
  complete: { color:'#4ade80', bg:'rgba(74,222,128,0.12)', label:'✅ Complete' },
  clean:    { color:'#4ade80', bg:'rgba(74,222,128,0.12)', label:'✅ Clean'    },
  skipped:  { color:'#6b7280', bg:'rgba(107,114,128,0.12)',label:'⊘ Skipped'   },
  error:    { color:'#f87171', bg:'rgba(248,113,113,0.12)',label:'❌ Error'    },
};

function LiveStageRow({ stage, isNew }) {
  const color = STAGE_COLORS[stage.id] || '#6b7280';
  const status = STATUS_STYLE[stage.status] || STATUS_STYLE.complete;

  return (
    <div style={{
      display:'flex', gap:14, padding:'14px 16px',
      background:'rgba(255,255,255,0.03)',
      border:`1px solid ${color}33`,
      borderLeft:`4px solid ${color}`,
      borderRadius:10, marginBottom:10,
      animation: isNew ? 'stageSlideIn 0.4s ease' : 'none',
    }}>
      <div style={{
        width:40, height:40, borderRadius:10, flexShrink:0,
        background:`${color}22`, border:`1.5px solid ${color}44`,
        display:'flex', alignItems:'center', justifyContent:'center',
        fontSize:20,
      }}>{stage.icon}</div>
      <div style={{ flex:1, minWidth:0 }}>
        <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:4 }}>
          <span style={{ fontSize:13, fontWeight:700, color:'#f0f6ff' }}>
            {stage.label}
          </span>
          <span style={{ fontSize:10, fontWeight:600, padding:'2px 8px',
            borderRadius:20, background:status.bg, color:status.color }}>
            {status.label}
          </span>
          <span style={{ fontSize:10, color:'#5b7a9d', marginLeft:'auto',
            fontFamily:'monospace' }}>
            {stage.duration_ms}ms
          </span>
        </div>
        <div style={{ fontSize:12, color:'#c5d8f5', lineHeight:1.5 }}>
          {stage.output}
        </div>

        {/* Expandable data preview for key stages */}
        {stage.id === 'ioc-extraction' && stage.data && (
          <div style={{ marginTop:8, display:'flex', flexWrap:'wrap', gap:5 }}>
            {stage.data.sender_domain && (
              <span style={{ fontSize:10, padding:'2px 8px', borderRadius:20,
                background:`${color}15`, color, fontFamily:'monospace' }}>
                domain: {stage.data.sender_domain}
              </span>
            )}
            {stage.data.urls?.length > 0 && (
              <span style={{ fontSize:10, padding:'2px 8px', borderRadius:20,
                background:`${color}15`, color }}>
                {stage.data.urls.length} URL(s)
              </span>
            )}
          </div>
        )}

        {stage.id === 'threat-intelligence' && stage.data?.typosquat_detail && (
          <div style={{ marginTop:8, padding:'8px 12px', borderRadius:8,
            background:'rgba(239,68,68,0.1)', border:'1px solid rgba(239,68,68,0.3)',
            fontSize:11, color:'#f87171' }}>
            ⚠️ {stage.data.typosquat_detail.reason}
          </div>
        )}

        {stage.id === 'ai-analysis' && stage.data?.ai_result?.mitre && (
          <div style={{ marginTop:6, fontSize:10, color:'#5b7a9d' }}>
            MITRE ATT&CK: <span style={{ color, fontWeight:700,
              fontFamily:'monospace' }}>{stage.data.ai_result.mitre}</span>
          </div>
        )}

        {stage.id === 'threat-correlation' && stage.data?.correlated_events?.length > 0 && (
          <div style={{ marginTop:8 }}>
            {stage.data.correlated_events.slice(0,3).map((c,i) => (
              <div key={i} style={{ fontSize:11, color:'#93c5fd',
                padding:'3px 0' }}>
                → {c.customer_name}: {c.subject?.slice(0,50)}
              </div>
            ))}
          </div>
        )}

        {stage.id === 'risk-assessment' && stage.data?.factors?.length > 0 && (
          <div style={{ marginTop:8, display:'flex', flexDirection:'column', gap:3 }}>
            {stage.data.factors.map((f,i) => (
              <div key={i} style={{ fontSize:11, color:'#c5d8f5' }}>• {f}</div>
            ))}
          </div>
        )}

        {stage.id === 'orchestrator-decision' && stage.data?.decisions?.length > 0 && (
          <div style={{ marginTop:8, display:'flex', flexWrap:'wrap', gap:5 }}>
            {stage.data.decisions.map((d,i) => (
              <span key={i} style={{ fontSize:10, padding:'2px 8px',
                borderRadius:20, background:'rgba(74,222,128,0.1)',
                color:'#4ade80', border:'1px solid rgba(74,222,128,0.3)' }}>
                ✓ {d}
              </span>
            ))}
          </div>
        )}

        {stage.id === 'notification' && stage.data?.notifications?.length > 0 && (
          <div style={{ marginTop:8 }}>
            {stage.data.notifications.map((n,i) => (
              <div key={i} style={{ fontSize:11, color:'#fbbf24',
                padding:'4px 0' }}>
                📧 → {n.to} ({n.reason})
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function VerdictCard({ verdict }) {
  if (!verdict) return null;
  const isThreat = verdict.is_threat;
  const sevColor = {
    CRITICAL:'#ef4444', HIGH:'#f97316', MEDIUM:'#eab308', LOW:'#4ade80',
  }[verdict.severity] || '#6b7280';

  return (
    <div style={{
      padding:20, borderRadius:14, marginBottom:16, textAlign:'center',
      background: isThreat ? 'rgba(239,68,68,0.08)' : 'rgba(74,222,128,0.08)',
      border:`2px solid ${isThreat ? sevColor : '#4ade80'}55`,
    }}>
      <div style={{ fontSize:42, marginBottom:8 }}>
        {isThreat ? '🚨' : '✅'}
      </div>
      <div style={{ fontSize:20, fontWeight:900,
        color: isThreat ? sevColor : '#4ade80', marginBottom:6 }}>
        {isThreat ? (verdict.threat_type || 'THREAT').toUpperCase() : 'CLEAN — NO THREAT'}
      </div>
      {isThreat && (
        <div style={{ display:'flex', gap:20, justifyContent:'center',
          marginTop:12, flexWrap:'wrap' }}>
          <div>
            <div style={{ fontSize:24, fontWeight:900, color:sevColor,
              fontFamily:'monospace' }}>{verdict.risk_score}</div>
            <div style={{ fontSize:10, color:'#5b7a9d' }}>Risk Score</div>
          </div>
          <div>
            <div style={{ fontSize:24, fontWeight:900, color:sevColor,
              fontFamily:'monospace' }}>{verdict.confidence}%</div>
            <div style={{ fontSize:10, color:'#5b7a9d' }}>Confidence</div>
          </div>
          <div>
            <div style={{ fontSize:16, fontWeight:900, color:sevColor,
              padding:'4px 0' }}>{verdict.severity}</div>
            <div style={{ fontSize:10, color:'#5b7a9d' }}>Severity</div>
          </div>
          <div>
            <div style={{ fontSize:14, fontWeight:700, color:'#93c5fd',
              padding:'6px 0', textTransform:'capitalize' }}>{verdict.method}</div>
            <div style={{ fontSize:10, color:'#5b7a9d' }}>Detection Method</div>
          </div>
        </div>
      )}
    </div>
  );
}

export function LiveEmailAnalysis() {
  const [input, setInput] = useState({
    mail_from: '', mail_to: '', subject: '', body: '',
  });
  const [analyzing, setAnalyzing] = useState(false);
  const [result,    setResult]    = useState(null);
  const [error,     setError]     = useState(null);
  const [visibleStages, setVisibleStages] = useState([]);

  const EXAMPLES = [
    {
      label: 'Phishing (Microsoft lookalike)',
      data: {
        mail_from: 'support@micr0soft-login.com',
        mail_to:   'john@abcbank.com',
        subject:   'Your Microsoft 365 Password Will Expire Today',
        body:      'Click below immediately to avoid account suspension.\nhttps://micr0soft-login.com/reset-password\nAttachment: Invoice.pdf.exe',
      },
    },
    {
      label: 'Scam (Lottery)',
      data: {
        mail_from: 'claims@international-lottery-dept.com',
        mail_to:   'user@company.com',
        subject:   'You have won $5,000,000 in the international lottery',
        body:      'Dear beneficiary, contact us immediately to claim your prize before it expires.',
      },
    },
    {
      label: 'BEC (Wire transfer)',
      data: {
        mail_from: 'ceo.office@company-finance-dept.net',
        mail_to:   'finance@company.com',
        subject:   'Urgent wire transfer needed today',
        body:      'Please process a wire transfer of $85,000 immediately. Confidential — do not discuss with anyone.',
      },
    },
    {
      label: 'Legitimate email',
      data: {
        mail_from: 'sarah@company.com',
        mail_to:   'team@company.com',
        subject:   'Meeting notes from today',
        body:      'Hi team, attaching the notes from our standup. Let me know if I missed anything.',
      },
    },
  ];

  const runAnalysis = async () => {
    if (!input.subject && !input.body && !input.mail_from) return;
    setAnalyzing(true);
    setError(null);
    setResult(null);
    setVisibleStages([]);

    try {
      const r = await api.post('/orchestration/analyze', input);
      const data = r.data;
      setResult(data);

      // Animate stages appearing one by one
      for (let i = 0; i < data.stages.length; i++) {
        await new Promise(res => setTimeout(res, 250));
        setVisibleStages(prev => [...prev, data.stages[i]]);
      }
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>

      {/* LEFT: Input */}
      <div>
        <div style={{
          background:'#0d1528', border:'1px solid rgba(0,191,165,0.2)',
          borderRadius:14, padding:20, marginBottom:16,
        }}>
          <div style={{ fontSize:13, fontWeight:700, color:'#00bfa5',
            marginBottom:14, display:'flex', alignItems:'center', gap:8 }}>
            📧 Live Email Input
          </div>

          <div style={{ marginBottom:10 }}>
            <label style={{ fontSize:11, color:'#7B9CC4' }}>From</label>
            <input value={input.mail_from}
              onChange={e=>setInput(p=>({...p,mail_from:e.target.value}))}
              placeholder="sender@example.com"
              style={{ width:'100%', marginTop:4, padding:'8px 12px',
                background:'#0a0f1e', border:'1px solid rgba(255,255,255,0.1)',
                borderRadius:8, color:'#f0f6ff', fontSize:12 }}/>
          </div>
          <div style={{ marginBottom:10 }}>
            <label style={{ fontSize:11, color:'#7B9CC4' }}>To</label>
            <input value={input.mail_to}
              onChange={e=>setInput(p=>({...p,mail_to:e.target.value}))}
              placeholder="recipient@company.com"
              style={{ width:'100%', marginTop:4, padding:'8px 12px',
                background:'#0a0f1e', border:'1px solid rgba(255,255,255,0.1)',
                borderRadius:8, color:'#f0f6ff', fontSize:12 }}/>
          </div>
          <div style={{ marginBottom:10 }}>
            <label style={{ fontSize:11, color:'#7B9CC4' }}>Subject</label>
            <input value={input.subject}
              onChange={e=>setInput(p=>({...p,subject:e.target.value}))}
              placeholder="Email subject line"
              style={{ width:'100%', marginTop:4, padding:'8px 12px',
                background:'#0a0f1e', border:'1px solid rgba(255,255,255,0.1)',
                borderRadius:8, color:'#f0f6ff', fontSize:12 }}/>
          </div>
          <div style={{ marginBottom:14 }}>
            <label style={{ fontSize:11, color:'#7B9CC4' }}>Body</label>
            <textarea value={input.body}
              onChange={e=>setInput(p=>({...p,body:e.target.value}))}
              placeholder="Paste the email body content..."
              style={{ width:'100%', marginTop:4, padding:'8px 12px', height:100,
                background:'#0a0f1e', border:'1px solid rgba(255,255,255,0.1)',
                borderRadius:8, color:'#f0f6ff', fontSize:12, resize:'vertical' }}/>
          </div>

          <button onClick={runAnalysis} disabled={analyzing}
            style={{ width:'100%', padding:'12px', borderRadius:10,
              border:'none', cursor: analyzing ? 'not-allowed' : 'pointer',
              background: analyzing ? 'rgba(0,191,165,0.3)' : 'linear-gradient(135deg,#00bfa5,#1565e8)',
              color:'#fff', fontSize:13, fontWeight:700,
              display:'flex', alignItems:'center', justifyContent:'center', gap:8 }}>
            {analyzing
              ? <>⏳ Processing through AI pipeline...</>
              : <>▶ Analyze This Email — Live</>}
          </button>

          {error && (
            <div style={{ marginTop:10, padding:'10px 12px', borderRadius:8,
              background:'rgba(239,68,68,0.1)', border:'1px solid rgba(239,68,68,0.3)',
              fontSize:12, color:'#f87171' }}>
              ❌ {error}
            </div>
          )}
        </div>

        {/* Quick examples */}
        <div style={{
          background:'#0d1528', border:'1px solid rgba(255,255,255,0.06)',
          borderRadius:14, padding:16,
        }}>
          <div style={{ fontSize:11, color:'#7B9CC4', marginBottom:10 }}>
            Quick test examples:
          </div>
          {EXAMPLES.map((ex,i) => (
            <button key={i} onClick={()=>setInput(ex.data)}
              style={{ display:'block', width:'100%', textAlign:'left',
                padding:'8px 12px', marginBottom:6, borderRadius:8,
                background:'rgba(255,255,255,0.03)',
                border:'1px solid rgba(255,255,255,0.08)',
                color:'#c5d8f5', fontSize:12, cursor:'pointer' }}>
              {ex.label}
            </button>
          ))}
        </div>
      </div>

      {/* RIGHT: Live pipeline output */}
      <div style={{ maxHeight:'85vh', overflowY:'auto' }}>
        {result && <VerdictCard verdict={result.verdict}/>}

        {visibleStages.length === 0 && !analyzing && (
          <div style={{ background:'#0d1528',
            border:'1px solid rgba(255,255,255,0.06)',
            borderRadius:14, padding:48, textAlign:'center' }}>
            <div style={{ fontSize:36, marginBottom:12 }}>🔬</div>
            <div style={{ fontSize:14, fontWeight:700, color:'#f0f6ff',
              marginBottom:6 }}>Ready for live analysis</div>
            <div style={{ fontSize:12, color:'#7B9CC4' }}>
              Enter an email or pick an example, then click Analyze.<br/>
              Every stage runs real pattern matching and real AI classification —
              no scripted output.
            </div>
          </div>
        )}

        {visibleStages.map((stage, i) => (
          <LiveStageRow key={stage.id} stage={stage}
            isNew={i === visibleStages.length - 1}/>
        ))}

        {result && (
          <div style={{ fontSize:11, color:'#5b7a9d', textAlign:'center',
            marginTop:8 }}>
            Total pipeline time: <strong style={{ color:'#00bfa5' }}>
              {result.total_duration_ms}ms
            </strong> · {result.stages.length} agents executed
          </div>
        )}
      </div>

      <style>{`
        @keyframes stageSlideIn {
          from { opacity:0; transform:translateY(-8px); }
          to   { opacity:1; transform:translateY(0); }
        }
      `}</style>
    </div>
  );
}
