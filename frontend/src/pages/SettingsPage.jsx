import { useState, useEffect, useCallback } from 'react';
import { Save, CheckCircle, RefreshCw, Mail } from 'lucide-react';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

export default function SettingsPage({ server }) {
  const [activeTab, setActiveTab] = useState('system');
  const [saved, setSaved] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [settings, setSettings] = useState({});
  const [runtime, setRuntime] = useState({});
  const [agentStatus, setAgentStatus] = useState(null);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [s, a] = await Promise.all([
        api.get('/policies/settings', { params: { server } }),
        api.get('/agent/status').catch(() => ({ data: null })),
      ]);
      setSettings(s.data.settings || {});
      setRuntime(s.data.runtime || {});
      setAgentStatus(a.data?.agents || null);
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  }, [server]);

  useEffect(() => { load(); }, [load]);

  const saveSettings = async () => {
    setError(null);
    try {
      await api.put('/policies/settings', { server, settings });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
      load();
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  const testSMTP = async () => {
    setTesting(true); setTestResult(null);
    try {
      await api.post('/inbox/send', {
        to: runtime.mail_smtp_host ? 'admin@worktual.tech' : 'test@example.com',
        subject: 'SMTP Test from Email Management Dashboard',
        body: 'This is a test email to verify SMTP connectivity.',
      });
      setTestResult({ ok: true, msg: 'SMTP test email sent successfully' });
    } catch (e) {
      setTestResult({ ok: false, msg: e.response?.data?.error || e.message });
    } finally { setTesting(false); }
  };

  const testIMAPI = async () => {
    setTesting(true); setTestResult(null);
    try {
      const r = await api.get('/inbox/count');
      setTestResult({ ok: true, msg: `IMAP connected — ${r.data.unread} unread messages` });
    } catch (e) {
      setTestResult({ ok: false, msg: e.response?.data?.error || e.message });
    } finally { setTesting(false); }
  };

  const updateSetting = (key, value) => setSettings(s => ({ ...s, [key]: value }));

  return (
    <div>
      <div className="flex-between mb-24">
        <div>
          <div className="section-title">Settings</div>
          <div className="section-sub">Persisted system configuration · Runtime status · Agents</div>
        </div>
        <button className="btn btn-primary btn-sm" onClick={saveSettings}>
          {saved ? <><CheckCircle size={13}/> Saved!</> : <><Save size={13}/> Save</>}
        </button>
      </div>

      {error && (
        <div style={{ marginBottom: 12, padding: '10px 14px', borderRadius: 8, background: 'rgba(220,38,38,0.12)', color: '#f87171', fontSize: 13 }}>
          {error}
        </div>
      )}

      <div className="tab-bar" style={{ marginBottom: 20 }}>
        {[
          { id: 'system', label: 'System Info' },
          { id: 'editable', label: 'Editable' },
          { id: 'smtp', label: 'SMTP / IMAP' },
          { id: 'agents', label: 'Log Agents' },
        ].map(t => (
          <button key={t.id} className={`tab-item ${activeTab === t.id ? 'active' : ''}`}
            onClick={() => setActiveTab(t.id)}>{t.label}</button>
        ))}
      </div>

      {activeTab === 'system' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <div className="card">
            <div className="card-header"><span className="card-title">Runtime</span></div>
            {[
              { label: 'Node Env', value: runtime.node_env },
              { label: 'API Port', value: runtime.port },
              { label: 'Frontend URL', value: runtime.frontend_url || '—' },
              { label: 'App DB Host', value: runtime.db_host || '—' },
              { label: 'Campaign DB Host', value: runtime.db_host_campaign || '—' },
              { label: 'Platform DB', value: runtime.platform_db },
              { label: 'JWT configured', value: runtime.jwt_configured ? 'Yes' : 'No' },
              { label: 'Agent secret configured', value: runtime.agent_secret_configured ? 'Yes' : 'No' },
            ].map(r => (
              <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                <span style={{ color: 'var(--text-muted)' }}>{r.label}</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{String(r.value)}</span>
              </div>
            ))}
          </div>
          <div className="card">
            <div className="card-header"><span className="card-title">Mail / AI endpoints</span></div>
            {[
              { label: 'IMAP Host', value: runtime.mail_imap_host || '—' },
              { label: 'SMTP Host', value: runtime.mail_smtp_host || '—' },
              { label: 'Ollama URL', value: runtime.ollama_url || settings.ollama_url || '—' },
              { label: 'Timezone', value: settings.dashboard_timezone || 'Asia/Kolkata' },
            ].map(r => (
              <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                <span style={{ color: 'var(--text-muted)' }}>{r.label}</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{String(r.value)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'editable' && (
        <div className="card">
          <div className="card-header"><span className="card-title">Persisted settings</span></div>
          {[
            { key: 'dashboard_timezone', label: 'Dashboard timezone' },
            { key: 'agent_poll_seconds', label: 'Agent poll interval (seconds)' },
            { key: 'notify_enabled', label: 'Notifications enabled (true/false)' },
            { key: 'ollama_url', label: 'Ollama URL override' },
          ].map(f => (
            <div key={f.key} style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 16, alignItems: 'center', padding: '12px 0', borderBottom: '1px solid var(--border)' }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>{f.label}</div>
              <input className="input" value={settings[f.key] || ''} onChange={e => updateSetting(f.key, e.target.value)}/>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'smtp' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <div className="card">
            <div className="card-header"><span className="card-title">SMTP (Outbound)</span></div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
              Configured via environment variables (MAIL_SMTP_* / NOTIFY_SMTP_*).
            </div>
            <button className="btn btn-primary btn-sm" onClick={testSMTP} disabled={testing}>
              {testing ? <RefreshCw size={13} className="spin"/> : <Mail size={13}/>} Test SMTP
            </button>
          </div>
          <div className="card">
            <div className="card-header"><span className="card-title">IMAP (Inbox)</span></div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
              Configured via MAIL_IMAP_* environment variables.
            </div>
            <button className="btn btn-primary btn-sm" onClick={testIMAPI} disabled={testing}>
              {testing ? <RefreshCw size={13} className="spin"/> : <Mail size={13}/>} Test IMAP
            </button>
          </div>
          {testResult && (
            <div style={{
              gridColumn: '1/-1', padding: '10px 16px', borderRadius: 8,
              background: testResult.ok ? 'rgba(22,163,74,0.1)' : 'rgba(220,38,38,0.1)',
              border: `1px solid ${testResult.ok ? 'rgba(22,163,74,0.3)' : 'rgba(220,38,38,0.3)'}`,
              fontSize: 13, color: testResult.ok ? '#4ade80' : '#f87171'
            }}>
              {testResult.ok ? 'OK' : 'Error'} — {testResult.msg}
            </div>
          )}
        </div>
      )}

      {activeTab === 'agents' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Live agent status</span>
            <button className="btn btn-ghost btn-sm" onClick={load}><RefreshCw size={13}/> Refresh</button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            {['app', 'campaign'].map(key => {
              const a = agentStatus?.[key];
              return (
                <div key={key} style={{ background: 'var(--bg-primary)', borderRadius: 8, padding: 14 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                    <div style={{
                      width: 8, height: 8, borderRadius: '50%',
                      background: a?.online ? '#4ade80' : '#6b7280',
                      boxShadow: a?.online ? '0 0 6px #4ade80' : 'none'
                    }}/>
                    <span style={{ fontWeight: 700, fontSize: 13 }}>{key === 'app' ? 'App Mail' : 'Campaign'}</span>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{a?.online ? 'online' : 'offline'}</span>
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.8 }}>
                    Queue: {a?.queue?.queue_count ?? '—'} · Deferred: {a?.queue?.deferred_count ?? '—'}<br/>
                    Events today: {a?.realtime?.total_today ?? '—'}<br/>
                    Last event: {a?.realtime?.last_event || '—'}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
