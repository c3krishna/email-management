import { useState, useEffect } from 'react';
import { RefreshCw, Plus, Key, Trash2, Copy, Check, Users, Globe } from 'lucide-react';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

function CopyBtn({ text }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={copy} style={{background:'none',border:'none',cursor:'pointer',padding:'2px 6px',color:'var(--text-muted)'}}>
      {copied ? <Check size={13} color="#4ade80"/> : <Copy size={13}/>}
    </button>
  );
}

export default function CustomerManagementPage() {
  const [customers, setCustomers]   = useState([]);
  const [loading,   setLoading]     = useState(true);
  const [showAdd,   setShowAdd]     = useState(false);
  const [selectedC, setSelectedC]   = useState(null);
  const [keys,      setKeys]        = useState([]);
  const [newKey,    setNewKey]      = useState(null);
  const [showKeyForm, setShowKeyForm] = useState(false);
  const [form,      setForm]        = useState({ name:'', domain:'', plan:'professional', retention_days:365, contact_email:'', mail_server:'app' });
  const [keyForm,   setKeyForm]     = useState({ key_name:'', rate_limit:1000, expires_days:'' });

  const loadCustomers = async () => {
    setLoading(true);
    try {
      const r = await api.get('/platform/customers');
      setCustomers(r.data.data || []);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  };

  const loadKeys = async (cid) => {
    try {
      const r = await api.get(`/platform/customers/${cid}/keys`);
      setKeys(r.data.data || []);
    } catch(e) { console.error(e); }
  };

  useEffect(() => { loadCustomers(); }, []);
  useEffect(() => { if (selectedC) loadKeys(selectedC.id); }, [selectedC]);

  const addCustomer = async () => {
    try {
      await api.post('/platform/customers', form);
      setShowAdd(false);
      setForm({ name:'', domain:'', plan:'professional', retention_days:365, contact_email:'', mail_server:'app' });
      loadCustomers();
    } catch(e) { alert(e.response?.data?.error || e.message); }
  };

  const generateKey = async () => {
    try {
      const r = await api.post(`/platform/customers/${selectedC.id}/keys`, keyForm);
      setNewKey(r.data.api_key);
      setShowKeyForm(false);
      setKeyForm({ key_name:'', rate_limit:1000, expires_days:'' });
      loadKeys(selectedC.id);
    } catch(e) { alert(e.response?.data?.error || e.message); }
  };

  const revokeKey = async (kid) => {
    if (!window.confirm('Revoke this API key?')) return;
    try {
      await api.delete(`/platform/customers/${selectedC.id}/keys/${kid}`);
      loadKeys(selectedC.id);
    } catch(e) { alert(e.message); }
  };

  const PLAN_COLORS = { starter:'#0891b2', professional:'#7c3aed', enterprise:'#d97706' };

  return (
    <div>
      <div className="flex-between mb-24">
        <div>
          <div className="section-title">Customer Management</div>
          <div className="section-sub">{customers.length} customers · API key management · Retention policies</div>
        </div>
        <button className="btn btn-primary btn-sm" onClick={() => setShowAdd(true)}>
          <Plus size={13}/> Add Customer
        </button>
      </div>

      <div style={{ display:'grid', gridTemplateColumns: selectedC ? '320px 1fr' : '1fr', gap:16 }}>

        {/* Customer list */}
        <div>
          {loading ? (
            <div className="loading-state"><RefreshCw size={16} className="spin"/></div>
          ) : customers.map(c => (
            <div key={c.id} className="card" style={{
              marginBottom:10, cursor:'pointer',
              borderLeft: selectedC?.id===c.id ? '3px solid var(--accent-blue)' : '3px solid transparent',
              background: selectedC?.id===c.id ? 'rgba(37,99,235,0.06)' : undefined,
            }} onClick={() => setSelectedC(selectedC?.id===c.id ? null : c)}>
              <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:8}}>
                <div style={{width:36,height:36,borderRadius:8,background:'rgba(37,99,235,0.15)',
                  display:'flex',alignItems:'center',justifyContent:'center',fontSize:16}}>🏢</div>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{fontSize:13,fontWeight:700,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{c.name}</div>
                  <div style={{fontSize:11,color:'var(--text-muted)'}}>
                    {c.domain}
                    {c.mail_server && (
                      <span style={{marginLeft:8,fontWeight:700,color:c.mail_server==='campaign'?'#ea580c':'#2563eb'}}>
                        · {c.mail_server}
                      </span>
                    )}
                  </div>
                </div>
                <div style={{display:'flex',gap:6,alignItems:'center'}}>
                  <span style={{fontSize:10,fontWeight:700,padding:'2px 8px',borderRadius:20,
                    background:`${PLAN_COLORS[c.plan]||'#6b7280'}22`,
                    color: PLAN_COLORS[c.plan]||'#9ca3af'}}>
                    {c.plan}
                  </span>
                  <div style={{width:8,height:8,borderRadius:'50%',
                    background:c.active?'#4ade80':'#6b7280'}}/>
                </div>
              </div>
              <div style={{display:'flex',gap:16,fontSize:11,color:'var(--text-muted)'}}>
                <span><Key size={10}/> {c.active_keys||0} keys</span>
                <span><Globe size={10}/> {c.retention_days} day retention</span>
                {c.last_ingest && <span>Last ingest: {new Date(c.last_ingest).toLocaleDateString('en-IN')}</span>}
              </div>
            </div>
          ))}

          {customers.length === 0 && !loading && (
            <div className="card" style={{textAlign:'center',padding:40}}>
              <Users size={32} style={{opacity:0.2,marginBottom:12}}/>
              <div style={{color:'var(--text-muted)'}}>No customers yet</div>
              <button className="btn btn-primary btn-sm" style={{marginTop:12}} onClick={()=>setShowAdd(true)}>
                <Plus size={13}/> Add First Customer
              </button>
            </div>
          )}
        </div>

        {/* Customer detail */}
        {selectedC && (
          <div>
            {/* Header */}
            <div className="card mb-16">
              <div style={{display:'flex',alignItems:'center',gap:12,marginBottom:12}}>
                <div style={{width:48,height:48,borderRadius:12,background:'rgba(37,99,235,0.15)',
                  display:'flex',alignItems:'center',justifyContent:'center',fontSize:24}}>🏢</div>
                <div>
                  <div style={{fontSize:18,fontWeight:700}}>{selectedC.name}</div>
                  <div style={{fontSize:13,color:'var(--text-muted)'}}>{selectedC.domain}</div>
                </div>
                <span style={{marginLeft:'auto',fontSize:11,fontWeight:700,padding:'3px 10px',
                  borderRadius:20,background:`${PLAN_COLORS[selectedC.plan]||'#6b7280'}22`,
                  color:PLAN_COLORS[selectedC.plan]||'#9ca3af'}}>{selectedC.plan?.toUpperCase()}</span>
              </div>
              <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:10}}>
                {[
                  {label:'Retention',     value:`${selectedC.retention_days} days`},
                  {label:'Contact',       value:selectedC.contact_email||'—'},
                  {label:'Status',        value:selectedC.active?'Active':'Inactive'},
                ].map(f => (
                  <div key={f.label} style={{background:'var(--bg-primary)',borderRadius:8,padding:'10px 12px'}}>
                    <div style={{fontSize:11,color:'var(--text-muted)',marginBottom:3}}>{f.label}</div>
                    <div style={{fontSize:13,fontWeight:600}}>{f.value}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* New key alert */}
            {newKey && (
              <div style={{background:'rgba(22,163,74,0.1)',border:'1px solid rgba(22,163,74,0.3)',
                borderRadius:8,padding:'12px 16px',marginBottom:16}}>
                <div style={{fontWeight:700,color:'#4ade80',marginBottom:6}}>
                  ✅ API key generated — copy now, it won't be shown again
                </div>
                <div style={{display:'flex',alignItems:'center',gap:8,background:'var(--bg-primary)',
                  borderRadius:6,padding:'8px 12px'}}>
                  <code style={{flex:1,fontFamily:'var(--font-mono)',fontSize:12,color:'#4ade80',
                    wordBreak:'break-all'}}>{newKey}</code>
                  <CopyBtn text={newKey}/>
                </div>
                <button className="btn btn-ghost btn-sm" style={{marginTop:8}} onClick={()=>setNewKey(null)}>
                  Dismiss
                </button>
              </div>
            )}

            {/* API Keys */}
            <div className="card">
              <div className="flex-between mb-16">
                <span className="card-title">API Keys ({keys.length})</span>
                <button className="btn btn-primary btn-sm" onClick={()=>setShowKeyForm(true)}>
                  <Key size={13}/> Generate Key
                </button>
              </div>

              {showKeyForm && (
                <div style={{background:'var(--bg-primary)',borderRadius:8,padding:16,marginBottom:16}}>
                  <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:10,marginBottom:10}}>
                    <div>
                      <label style={{fontSize:11,color:'var(--text-muted)'}}>Key Name *</label>
                      <input className="input" style={{marginTop:4}} placeholder="e.g. Virus Rescuers Integration"
                        value={keyForm.key_name} onChange={e=>setKeyForm(f=>({...f,key_name:e.target.value}))}/>
                    </div>
                    <div>
                      <label style={{fontSize:11,color:'var(--text-muted)'}}>Rate Limit (req/hr)</label>
                      <input className="input" style={{marginTop:4}} type="number" value={keyForm.rate_limit}
                        onChange={e=>setKeyForm(f=>({...f,rate_limit:parseInt(e.target.value)}))}/>
                    </div>
                    <div>
                      <label style={{fontSize:11,color:'var(--text-muted)'}}>Expires (days, blank=never)</label>
                      <input className="input" style={{marginTop:4}} type="number" placeholder="never"
                        value={keyForm.expires_days}
                        onChange={e=>setKeyForm(f=>({...f,expires_days:e.target.value}))}/>
                    </div>
                  </div>
                  <div style={{display:'flex',gap:8}}>
                    <button className="btn btn-primary btn-sm" onClick={generateKey}
                      disabled={!keyForm.key_name}>Generate</button>
                    <button className="btn btn-ghost btn-sm" onClick={()=>setShowKeyForm(false)}>Cancel</button>
                  </div>
                </div>
              )}

              {keys.length === 0 ? (
                <div style={{textAlign:'center',padding:32,color:'var(--text-muted)'}}>
                  No API keys yet
                </div>
              ) : (
                <div className="table-wrapper">
                  <table>
                    <thead><tr>
                      <th>Name</th><th>Prefix</th><th>Rate Limit</th>
                      <th>Last Used</th><th>Expires</th><th>Status</th><th></th>
                    </tr></thead>
                    <tbody>
                      {keys.map((k,i) => (
                        <tr key={i}>
                          <td style={{fontSize:13,fontWeight:500}}>{k.key_name}</td>
                          <td>
                            <div style={{display:'flex',alignItems:'center',gap:6}}
                              title="Only the prefix is stored for security. The full key was shown once when generated and cannot be retrieved — revoke and generate a new key if lost.">
                              <code style={{fontSize:12,fontFamily:'var(--font-mono)',
                                background:'var(--bg-primary)',padding:'2px 6px',borderRadius:4,
                                color:'var(--text-muted)'}}>
                                {k.key_prefix}••••••••••••••••</code>
                            </div>
                          </td>
                          <td style={{fontFamily:'var(--font-mono)',fontSize:12}}>{k.rate_limit}/hr</td>
                          <td style={{fontSize:11,color:'var(--text-muted)'}}>
                            {k.last_used_at ? new Date(k.last_used_at).toLocaleString('en-IN') : 'Never'}</td>
                          <td style={{fontSize:11,color:'var(--text-muted)'}}>
                            {k.expires_at ? new Date(k.expires_at).toLocaleDateString('en-IN') : 'Never'}</td>
                          <td>
                            <span style={{fontSize:11,fontWeight:600,padding:'2px 8px',borderRadius:20,
                              background:k.active?'rgba(22,163,74,0.15)':'rgba(107,114,128,0.15)',
                              color:k.active?'#4ade80':'#9ca3af'}}>
                              {k.active ? 'Active' : 'Revoked'}
                            </span>
                          </td>
                          <td>
                            {k.active && (
                              <button className="btn btn-danger btn-sm" style={{padding:'2px 8px',fontSize:11}}
                                onClick={()=>revokeKey(k.id)}>
                                <Trash2 size={11}/> Revoke
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* API usage examples */}
              <div style={{marginTop:16,padding:14,background:'var(--bg-primary)',borderRadius:8}}>
                <div style={{fontSize:12,fontWeight:600,marginBottom:8,color:'var(--text-muted)'}}>
                  API usage examples
                </div>
                <pre style={{fontSize:11,fontFamily:'var(--font-mono)',color:'#4ade80',
                  overflowX:'auto',margin:0,lineHeight:1.8}}>{
`# Ingest email logs
curl -X POST https://email-management.worktual.tech/api/platform/v1/ingest/events \\
  -H "X-Api-Key: <your-key>" -H "Content-Type: application/json" \\
  -d '{"events":[{"event_type":"delivery","mail_from":"...","status":"sent"}]}'

# Historical query
curl "https://email-management.worktual.tech/api/platform/v1/logs/history?from=2026-01-01&to=2026-12-31" \\
  -H "X-Api-Key: <your-key>"

# Check if email is a known threat
curl "https://email-management.worktual.tech/api/threats/v1/check?indicator=spam@evil.com" \\
  -H "X-Api-Key: <your-key>"

# Get threat feed
curl "https://email-management.worktual.tech/api/threats/v1/feed?limit=100" \\
  -H "X-Api-Key: <your-key>"`}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Add customer modal */}
      {showAdd && (
        <div style={{position:'fixed',inset:0,background:'rgba(0,0,0,0.7)',
          display:'flex',alignItems:'center',justifyContent:'center',zIndex:1000}}>
          <div style={{background:'var(--bg-card)',border:'1px solid var(--border)',
            borderRadius:12,width:480,padding:24}}>
            <div style={{fontSize:16,fontWeight:700,marginBottom:20}}>Add Customer</div>
            <div style={{display:'flex',flexDirection:'column',gap:12}}>
              {[
                {key:'name',          label:'Customer Name *',  type:'text', ph:'Virus Rescuers Ltd'},
                {key:'domain',        label:'Primary Domain *', type:'text', ph:'example.com'},
                {key:'contact_email', label:'Contact Email',    type:'email',ph:'admin@example.com'},
              ].map(f=>(
                <div key={f.key}>
                  <label style={{fontSize:12,color:'var(--text-muted)'}}>{f.label}</label>
                  <input className="input" style={{marginTop:4}} type={f.type} placeholder={f.ph}
                    value={form[f.key]} onChange={e=>setForm(p=>({...p,[f.key]:e.target.value}))}/>
                </div>
              ))}
              <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
                <div>
                  <label style={{fontSize:12,color:'var(--text-muted)'}}>Plan</label>
                  <select className="input" style={{marginTop:4}} value={form.plan}
                    onChange={e=>setForm(p=>({...p,plan:e.target.value}))}>
                    <option value="starter">Starter</option>
                    <option value="professional">Professional</option>
                    <option value="enterprise">Enterprise</option>
                  </select>
                </div>
                <div>
                  <label style={{fontSize:12,color:'var(--text-muted)'}}>Retention (days)</label>
                  <input className="input" style={{marginTop:4}} type="number" value={form.retention_days}
                    onChange={e=>setForm(p=>({...p,retention_days:parseInt(e.target.value)}))}/>
                </div>
              </div>
              <div>
                <label style={{fontSize:12,color:'var(--text-muted)'}}>Mail server infra</label>
                <select className="input" style={{marginTop:4}} value={form.mail_server}
                  onChange={e=>setForm(p=>({...p,mail_server:e.target.value}))}>
                  <option value="app">App — mail.worktual.tech (CCaaS / notifications)</option>
                  <option value="campaign">Campaign — mail.worktual.pl (bulk)</option>
                  <option value="both">Both infrastructures</option>
                </select>
              </div>
            </div>
            <div style={{display:'flex',gap:8,marginTop:20}}>
              <button className="btn btn-primary" onClick={addCustomer} disabled={!form.name||!form.domain}>
                Add Customer
              </button>
              <button className="btn btn-ghost" onClick={()=>setShowAdd(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
