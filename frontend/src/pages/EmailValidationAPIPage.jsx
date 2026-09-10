import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const CODE_BG = '#0a0f1e';

function CodeBlock({ children, lang = 'bash' }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(children.trim());
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div style={{ position:'relative', marginBottom:16 }}>
      <div style={{ display:'flex', justifyContent:'space-between',
        alignItems:'center', padding:'6px 12px',
        background:'rgba(255,255,255,0.04)',
        borderRadius:'8px 8px 0 0', border:'1px solid rgba(255,255,255,0.08)',
        borderBottom:'none' }}>
        <span style={{ fontSize:10, color:'var(--text-muted)',
          textTransform:'uppercase', letterSpacing:0.5 }}>{lang}</span>
        <button onClick={copy} style={{
          background:'transparent', border:'none', cursor:'pointer',
          color: copied ? '#4ade80' : 'var(--text-muted)', fontSize:11 }}>
          {copied ? '✓ Copied' : '📋 Copy'}
        </button>
      </div>
      <pre style={{
        margin:0, padding:16, background:CODE_BG,
        border:'1px solid rgba(255,255,255,0.08)',
        borderRadius:'0 0 8px 8px', overflowX:'auto',
        fontSize:12, lineHeight:1.6, color:'#93c5fd',
        fontFamily:'var(--font-mono)',
      }}><code>{children.trim()}</code></pre>
    </div>
  );
}

function EndpointCard({ method, path, desc, children }) {
  const methodColors = { GET:'#4ade80', POST:'#60a5fa', PUT:'#fbbf24', DELETE:'#f87171' };
  return (
    <div className="card" style={{ marginBottom:16 }}>
      <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:8 }}>
        <span style={{ fontSize:11, fontWeight:800, padding:'3px 10px',
          borderRadius:6, background:`${methodColors[method]}22`,
          color:methodColors[method] }}>{method}</span>
        <code style={{ fontSize:13, fontWeight:600, color:'var(--text-primary)' }}>
          {path}
        </code>
      </div>
      <div style={{ fontSize:12, color:'var(--text-muted)', marginBottom:14 }}>
        {desc}
      </div>
      {children}
    </div>
  );
}

export default function EmailValidationAPIPage() {
  const [customers, setCustomers] = useState([]);
  const [apiKeys,   setApiKeys]   = useState([]);
  const [selectedCustomer, setSelectedCustomer] = useState('');
  const [newKeyName, setNewKeyName] = useState('');
  const [generating, setGenerating] = useState(false);
  const [toast, setToast] = useState('');
  const [activeTab, setActiveTab] = useState('docs');
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);
  const [testInput, setTestInput] = useState({
    mail_from: 'support@micr0soft-login.com',
    mail_to:   'john@abcbank.com',
    subject:   'Your Microsoft 365 Password Will Expire Today',
    body:      'Click below immediately to avoid account suspension.\nhttps://micr0soft-login.com/reset-password',
  });

  const showToast = (msg) => { setToast(msg); setTimeout(()=>setToast(''),3000); };

  const load = useCallback(async () => {
    try {
      const c = await api.get('/platform/customers').catch(()=>({data:{data:[]}}));
      const custList = c.data.data || c.data || [];
      setCustomers(custList);

      // Fetch keys for every customer and merge with customer name
      const keyLists = await Promise.all(
        custList.map(cust =>
          api.get(`/platform/customers/${cust.id}/keys`)
            .then(r => (r.data.data || []).map(k => ({ ...k, customer_id: cust.id, customer_name: cust.name })))
            .catch(() => [])
        )
      );
      setApiKeys(keyLists.flat());
    } catch(e) { console.error(e); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const [revealedKey, setRevealedKey] = useState(null);

  const generateKey = async () => {
    if (!selectedCustomer) return;
    setGenerating(true);
    try {
      const r = await api.post(`/platform/customers/${selectedCustomer}/keys`, {
        key_name: newKeyName || 'Email Validation API Key',
        permissions: { ingest: true, query: true, validate: true },
      });
      setRevealedKey(r.data.api_key);
      showToast('✅ API key generated');
      setNewKeyName('');
      load();
    } catch(e) { alert(e.response?.data?.error || e.message); }
    finally { setGenerating(false); }
  };

  const [testApiKey, setTestApiKey] = useState('');

  const runTest = async () => {
    if (!testApiKey) { alert('Paste an API key to test with (copy it when you generate a new one)'); return; }

    setTesting(true); setTestResult(null);
    try {
      const r = await axios.post('/api/v1/validate-email', testInput, {
        headers: { 'X-API-Key': testApiKey }
      });
      setTestResult(r.data);
    } catch(e) {
      setTestResult({ error: e.response?.data?.error || e.message });
    } finally { setTesting(false); }
  };

  return (
    <div>
      {toast && (
        <div style={{ position:'fixed', top:16, right:16, zIndex:9999,
          padding:'10px 20px', borderRadius:8, fontSize:13,
          background:'rgba(22,163,74,0.95)', color:'#fff', fontWeight:600 }}>
          {toast}
        </div>
      )}

      <div className="mb-16">
        <div className="section-title">📡 Email Validation API</div>
        <div className="section-sub">
          Customer-facing REST API — validate email content for spam, phishing, malware,
          BEC using Worktual AI Engine · Auto-sends threat notifications
        </div>
      </div>

      <div className="tab-bar" style={{ marginBottom:16 }}>
        {[
          { id:'docs',    label:'📖 Documentation' },
          { id:'keys',    label:'🔑 API Keys'      },
          { id:'test',    label:'🧪 Live Test'     },
        ].map(t => (
          <button key={t.id} className={`tab-item ${activeTab===t.id?'active':''}`}
            onClick={()=>setActiveTab(t.id)}>{t.label}</button>
        ))}
      </div>

      {/* ── DOCUMENTATION ── */}
      {activeTab === 'docs' && (
        <div>
          <div className="card mb-16">
            <div className="card-title" style={{ marginBottom:10 }}>Overview</div>
            <div style={{ fontSize:13, color:'var(--text-secondary)', lineHeight:1.7 }}>
              The Email Validation API lets customers submit email content (from your own
              application, mail server, or email security platform) and receive an instant
              AI-powered threat verdict. When a threat is detected above your configured
              confidence threshold, the platform automatically sends notifications to your
              IT Administrator.
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)',
              gap:10, marginTop:16 }}>
              {[
                { icon:'🎯', label:'Pattern Matching', desc:'14 built-in threat patterns' },
                { icon:'🤖', label:'AI Classification', desc:'Qwen2.5 14B + deepseek-r1:32b' },
                { icon:'🔍', label:'Typosquat Detection', desc:'Brand impersonation check' },
                { icon:'🔔', label:'Auto Notification', desc:'Instant admin alerts' },
              ].map((f,i) => (
                <div key={i} style={{ padding:12, borderRadius:8,
                  background:'var(--bg-primary)', border:'1px solid var(--border)',
                  textAlign:'center' }}>
                  <div style={{ fontSize:20, marginBottom:6 }}>{f.icon}</div>
                  <div style={{ fontSize:11, fontWeight:700 }}>{f.label}</div>
                  <div style={{ fontSize:10, color:'var(--text-muted)',
                    marginTop:2 }}>{f.desc}</div>
                </div>
              ))}
            </div>
          </div>

          <EndpointCard method="POST" path="/api/v1/validate-email"
            desc="Validate a single email for spam/phishing/malware/BEC content. Returns instant verdict and triggers notifications if a threat is found.">
            <div style={{ fontSize:12, fontWeight:600, marginBottom:6 }}>Headers</div>
            <CodeBlock lang="http">
{`X-API-Key: your_api_key_here
Content-Type: application/json`}
            </CodeBlock>

            <div style={{ fontSize:12, fontWeight:600, marginBottom:6 }}>Request Body</div>
            <CodeBlock lang="json">
{`{
  "mail_from": "support@micr0soft-login.com",
  "mail_to": "john@abcbank.com",
  "subject": "Your Microsoft 365 Password Will Expire Today",
  "body": "Click below immediately to avoid account suspension.\\nhttps://micr0soft-login.com/reset-password",
  "notify": true
}`}
            </CodeBlock>

            <div style={{ fontSize:12, fontWeight:600, marginBottom:6 }}>Example — cURL</div>
            <CodeBlock lang="bash">
{`curl -X POST https://email-management.worktual.tech/api/v1/validate-email \\
  -H "X-API-Key: vr_live_your_key_here" \\
  -H "Content-Type: application/json" \\
  -d '{
    "mail_from": "attacker@evil-domain.com",
    "mail_to": "user@yourcompany.com",
    "subject": "Urgent: Verify your account",
    "body": "Click here to verify: http://phishing-site.com"
  }'`}
            </CodeBlock>

            <div style={{ fontSize:12, fontWeight:600, marginBottom:6 }}>Response — Threat Detected</div>
            <CodeBlock lang="json">
{`{
  "success": true,
  "event_id": 48291,
  "verdict": {
    "is_threat": true,
    "spam_type": "phishing",
    "confidence": 95,
    "method": "pattern+ai+typosquat",
    "reason": "Email impersonates Microsoft using a lookalike domain and requests urgent credential verification",
    "indicators": {
      "pattern_match": true,
      "ai_flagged": true,
      "typosquat_detected": true,
      "typosquat_detail": "Domain resembles \\"microsoft\\" using character substitution",
      "domain_resolves": true,
      "urls_found": 1
    }
  },
  "notification": { "sent": true, "recipients": 2 },
  "processing_time_ms": 847,
  "customer": "ABC Bank"
}`}
            </CodeBlock>

            <div style={{ fontSize:12, fontWeight:600, marginBottom:6 }}>Response — Clean Email</div>
            <CodeBlock lang="json">
{`{
  "success": true,
  "event_id": 48292,
  "verdict": {
    "is_threat": false,
    "spam_type": "legitimate",
    "confidence": 0,
    "reason": "No threat indicators found"
  },
  "notification": { "sent": false, "reason": "not requested" },
  "processing_time_ms": 612
}`}
            </CodeBlock>
          </EndpointCard>

          <EndpointCard method="POST" path="/api/v1/validate-batch"
            desc="Validate up to 50 emails in a single request. Uses fast pattern matching only (no AI call per email) for high throughput.">
            <CodeBlock lang="json">
{`{
  "emails": [
    { "mail_from": "sender1@example.com", "subject": "...", "body": "..." },
    { "mail_from": "sender2@example.com", "subject": "...", "body": "..." }
  ],
  "notify": false
}`}
            </CodeBlock>
          </EndpointCard>

          <EndpointCard method="GET" path="/api/v1/validate-status"
            desc="Check your API key validity and view usage statistics for the last 30 days.">
            <CodeBlock lang="bash">
{`curl https://email-management.worktual.tech/api/v1/validate-status \\
  -H "X-API-Key: vr_live_your_key_here"`}
            </CodeBlock>
          </EndpointCard>

          {/* Integration examples */}
          <div className="card">
            <div className="card-title" style={{ marginBottom:12 }}>
              Integration Examples
            </div>

            <div style={{ fontSize:12, fontWeight:600, marginBottom:6 }}>Python</div>
            <CodeBlock lang="python">
{`import requests

def validate_email(mail_from, subject, body):
    r = requests.post(
        "https://email-management.worktual.tech/api/v1/validate-email",
        headers={"X-API-Key": "vr_live_your_key_here"},
        json={"mail_from": mail_from, "subject": subject, "body": body}
    )
    result = r.json()
    if result["verdict"]["is_threat"]:
        print(f"⚠️ THREAT: {result['verdict']['spam_type']} ({result['verdict']['confidence']}%)")
        # Quarantine or reject the email here
    return result`}
            </CodeBlock>

            <div style={{ fontSize:12, fontWeight:600, marginBottom:6, marginTop:16 }}>
              Node.js
            </div>
            <CodeBlock lang="javascript">
{`const axios = require('axios');

async function validateEmail(mailFrom, subject, body) {
  const { data } = await axios.post(
    'https://email-management.worktual.tech/api/v1/validate-email',
    { mail_from: mailFrom, subject, body },
    { headers: { 'X-API-Key': 'vr_live_your_key_here' } }
  );
  if (data.verdict.is_threat) {
    console.log(\`⚠️ THREAT: \${data.verdict.spam_type} (\${data.verdict.confidence}%)\`);
  }
  return data;
}`}
            </CodeBlock>
          </div>
        </div>
      )}

      {/* ── API KEYS ── */}
      {activeTab === 'keys' && (
        <div>
          <div className="card mb-16">
            <div className="card-title" style={{ marginBottom:12 }}>
              Generate New API Key
            </div>
            <div style={{ display:'grid',
              gridTemplateColumns:'1fr 1fr auto', gap:10, alignItems:'end' }}>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>Customer *</label>
                <select className="input" style={{ marginTop:4 }}
                  value={selectedCustomer}
                  onChange={e=>setSelectedCustomer(e.target.value)}>
                  <option value="">Select customer...</option>
                  {customers.map(c => (
                    <option key={c.id} value={c.id}>{c.name}</option>
                  ))}
                </select>
              </div>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>Key Name</label>
                <input className="input" style={{ marginTop:4 }}
                  placeholder="e.g. Production Integration"
                  value={newKeyName}
                  onChange={e=>setNewKeyName(e.target.value)}/>
              </div>
              <button className="btn btn-primary btn-sm" onClick={generateKey}
                disabled={!selectedCustomer || generating}>
                {generating ? 'Generating...' : '🔑 Generate Key'}
              </button>
            </div>
            {revealedKey && (
              <div style={{ marginTop:16, padding:14, borderRadius:10,
                background:'rgba(245,158,11,0.1)', border:'1px solid rgba(245,158,11,0.4)' }}>
                <div style={{ fontSize:12, fontWeight:700, color:'#fbbf24', marginBottom:6 }}>
                  ⚠️ Copy this key now — it won't be shown again
                </div>
                <div style={{ display:'flex', gap:8, alignItems:'center' }}>
                  <code style={{ flex:1, fontSize:12, padding:'8px 12px',
                    background:'var(--bg-primary)', borderRadius:6,
                    color:'#60a5fa', wordBreak:'break-all' }}>{revealedKey}</code>
                  <button className="btn btn-ghost btn-sm" onClick={()=>{
                    navigator.clipboard.writeText(revealedKey);
                    showToast('Copied to clipboard');
                  }}>📋 Copy</button>
                </div>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom:12 }}>
              Active API Keys ({apiKeys.length})
            </div>
            <div className="table-wrapper">
              <table>
                <thead><tr>
                  <th>Customer</th><th>Key Name</th><th>API Key</th>
                  <th>Created</th><th>Status</th>
                </tr></thead>
                <tbody>
                  {apiKeys.map((k,i) => (
                    <tr key={i}>
                      <td style={{ fontWeight:600 }}>{k.customer_name || '—'}</td>
                      <td style={{ fontSize:12 }}>{k.name || 'Default'}</td>
                      <td className="mono" style={{ fontSize:11, color:'#60a5fa' }}>
                        {k.key_prefix}••••••••••••••••
                      </td>
                      <td style={{ fontSize:11, color:'var(--text-muted)' }}>
                        {k.created_at?.slice(0,10) || '—'}
                      </td>
                      <td>
                        <span style={{ fontSize:11, fontWeight:600,
                          padding:'2px 8px', borderRadius:20,
                          background: k.active ? 'rgba(74,222,128,0.15)' : 'rgba(107,114,128,0.15)',
                          color: k.active ? '#4ade80' : '#6b7280' }}>
                          {k.active ? '● Active' : '○ Inactive'}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {!apiKeys.length && (
                    <tr><td colSpan={5} style={{ textAlign:'center',
                      padding:32, color:'var(--text-muted)' }}>
                      No API keys generated yet
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── LIVE TEST ── */}
      {activeTab === 'test' && (
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
          <div className="card">
            <div className="card-title" style={{ marginBottom:12 }}>
              Test the API Live
            </div>
            <div style={{ marginBottom:12 }}>
              <label style={{ fontSize:11, color:'var(--text-muted)' }}>
                API Key * (paste the key shown when you generated it)
              </label>
              <input className="input" style={{ marginTop:4, fontFamily:'var(--font-mono)', fontSize:12 }}
                placeholder="tp_live_xxxxxxxxxxxxxxxxxxxxxxxx"
                value={testApiKey}
                onChange={e=>setTestApiKey(e.target.value)}/>
            </div>
            {['mail_from','mail_to','subject'].map(field => (
              <div key={field} style={{ marginBottom:10 }}>
                <label style={{ fontSize:11, color:'var(--text-muted)',
                  textTransform:'capitalize' }}>{field.replace('_',' ')}</label>
                <input className="input" style={{ marginTop:4 }}
                  value={testInput[field]}
                  onChange={e=>setTestInput(p=>({...p,[field]:e.target.value}))}/>
              </div>
            ))}
            <div style={{ marginBottom:14 }}>
              <label style={{ fontSize:11, color:'var(--text-muted)' }}>Body</label>
              <textarea className="input" style={{ marginTop:4, height:100 }}
                value={testInput.body}
                onChange={e=>setTestInput(p=>({...p,body:e.target.value}))}/>
            </div>
            <button className="btn btn-primary" onClick={runTest}
              disabled={testing || !selectedCustomer}
              style={{ width:'100%' }}>
              {testing ? '⏳ Validating...' : '▶ Send to API'}
            </button>
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom:12 }}>API Response</div>
            {!testResult && (
              <div style={{ textAlign:'center', padding:48,
                color:'var(--text-muted)', fontSize:13 }}>
                Run a test to see the live API response
              </div>
            )}
            {testResult?.error && (
              <div style={{ padding:16, borderRadius:8,
                background:'rgba(239,68,68,0.1)', border:'1px solid rgba(239,68,68,0.3)',
                color:'#f87171', fontSize:13 }}>
                ❌ {testResult.error}
              </div>
            )}
            {testResult?.verdict && (
              <div>
                <div style={{
                  padding:16, borderRadius:10, marginBottom:14, textAlign:'center',
                  background: testResult.verdict.is_threat
                    ? 'rgba(239,68,68,0.1)' : 'rgba(74,222,128,0.1)',
                  border: `2px solid ${testResult.verdict.is_threat ? 'rgba(239,68,68,0.4)' : 'rgba(74,222,128,0.4)'}`,
                }}>
                  <div style={{ fontSize:32 }}>
                    {testResult.verdict.is_threat ? '🚨' : '✅'}
                  </div>
                  <div style={{ fontSize:18, fontWeight:800,
                    color: testResult.verdict.is_threat ? '#f87171' : '#4ade80' }}>
                    {testResult.verdict.spam_type.toUpperCase()}
                  </div>
                  <div style={{ fontSize:13, color:'var(--text-muted)' }}>
                    Confidence: {testResult.verdict.confidence}%
                  </div>
                </div>
                <div style={{ fontSize:12, color:'var(--text-secondary)',
                  marginBottom:10, lineHeight:1.5 }}>
                  {testResult.verdict.reason}
                </div>
                {testResult.notification && (
                  <div style={{ fontSize:12, padding:'8px 12px', borderRadius:8,
                    background: testResult.notification.sent
                      ? 'rgba(74,222,128,0.1)' : 'rgba(107,114,128,0.1)',
                    color: testResult.notification.sent ? '#4ade80' : 'var(--text-muted)' }}>
                    {testResult.notification.sent
                      ? `📧 Notification sent to ${testResult.notification.recipients} admin(s)`
                      : `No notification: ${testResult.notification.reason}`}
                  </div>
                )}
                <div style={{ fontSize:11, color:'var(--text-muted)',
                  marginTop:10, textAlign:'right' }}>
                  {testResult.processing_time_ms}ms
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
