import { useState, useEffect, useCallback } from 'react';
import { Save, Plus, Trash2, CheckCircle } from 'lucide-react';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const FIELD_META = {
  spam_threshold:        { label: 'Spam Score Threshold', desc: 'Emails above this score are flagged as spam', type: 'number', min: 0, max: 20, step: 0.5 },
  block_threshold:       { label: 'Auto-Block Threshold', desc: 'Emails above this score are auto-blocked', type: 'number', min: 0, max: 20, step: 0.5 },
  quarantine_threshold:  { label: 'Quarantine Threshold', desc: 'Emails above this score are quarantined', type: 'number', min: 0, max: 20, step: 0.5 },
  max_recipients:        { label: 'Max Recipients per Mail', desc: 'Alert if a single mail has more than N recipients', type: 'number', min: 1, max: 1000 },
  bounce_rate_alert:     { label: 'Bounce Rate Alert (%)', desc: 'Alert when bounce rate exceeds this percentage', type: 'number', min: 0, max: 100 },
  failed_rate_alert:     { label: 'Failure Rate Alert (%)', desc: 'Alert when failure rate exceeds this percentage', type: 'number', min: 0, max: 100 },
  alert_failed_threshold:{ label: 'Failed Count Threshold', desc: 'Absolute failed-mail count that triggers DevOps/Backend alerts', type: 'number', min: 1, max: 100000 },
  alert_bounce_threshold:{ label: 'Bounce Count Threshold', desc: 'Absolute bounce count that triggers email-team alerts', type: 'number', min: 1, max: 100000 },
  alert_spam_threshold:  { label: 'Spam Block Count Threshold', desc: 'Absolute spam-block count that triggers DevOps alerts', type: 'number', min: 1, max: 100000 },
  alert_email:           { label: 'Alert Email Address', desc: 'Send alerts to this email address', type: 'email' },
  alert_slack:           { label: 'Slack Webhook URL', desc: 'Send alerts to this Slack webhook (optional)', type: 'url' },
  retention_hot_days:    { label: 'Hot DB Retention (days)', desc: 'Keep logs in fast DB for this many days', type: 'number', min: 7, max: 365 },
  retention_archive_days:{ label: 'Archive Retention (days)', desc: 'Keep archive logs for this many days', type: 'number', min: 90, max: 3650 },
};

const EMPTY = Object.fromEntries(Object.keys(FIELD_META).map(k => [k, '']));

export default function PoliciesPage({ server }) {
  const [policies, setPolicies] = useState(EMPTY);
  const [blocklist, setBlocklist] = useState([]);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('thresholds');
  const [newBlock, setNewBlock] = useState({ type: 'domain', value: '', reason: '' });

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const r = await api.get('/policies', { params: { server } });
      setPolicies({ ...EMPTY, ...(r.data.policies || {}) });
      setBlocklist(r.data.blocklist || []);
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    } finally {
      setLoading(false);
    }
  }, [server]);

  useEffect(() => { load(); }, [load]);

  const updatePolicy = (key, value) => {
    setPolicies(p => ({ ...p, [key]: value }));
    setSaved(false);
  };

  const saveAll = async () => {
    setError(null);
    try {
      await api.put('/policies', { server, policies });
      await api.post('/alerts/update-thresholds', {
        server,
        failed_threshold: policies.alert_failed_threshold,
        bounce_threshold: policies.alert_bounce_threshold,
        spam_threshold: policies.alert_spam_threshold,
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  const addBlock = async () => {
    if (!newBlock.value) return;
    try {
      await api.post('/policies/blocklist', { ...newBlock, server });
      setNewBlock({ type: 'domain', value: '', reason: '' });
      load();
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  const removeBlock = async (id) => {
    try {
      await api.delete(`/policies/blocklist/${id}`, { params: { server } });
      load();
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  const THRESHOLD_KEYS = [
    'spam_threshold', 'block_threshold', 'quarantine_threshold', 'max_recipients',
    'bounce_rate_alert', 'failed_rate_alert',
    'alert_failed_threshold', 'alert_bounce_threshold', 'alert_spam_threshold',
  ];
  const NOTIFICATION_KEYS = ['alert_email', 'alert_slack'];
  const RETENTION_KEYS = ['retention_hot_days', 'retention_archive_days'];

  const renderField = (key) => {
    const meta = FIELD_META[key];
    if (!meta) return null;
    return (
      <div key={key} style={{
        display: 'grid', gridTemplateColumns: '1fr 180px', gap: 16, alignItems: 'center',
        padding: '14px 0', borderBottom: '1px solid var(--border)'
      }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600 }}>{meta.label}</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 3 }}>{meta.desc}</div>
        </div>
        <input
          type={meta.type === 'number' ? 'number' : meta.type === 'email' ? 'email' : 'text'}
          className="input"
          value={policies[key] ?? ''}
          min={meta.min} max={meta.max} step={meta.step}
          placeholder={meta.type === 'url' ? 'https://hooks.slack.com/...' : meta.type === 'email' ? 'admin@example.com' : ''}
          onChange={e => updatePolicy(key, e.target.value)}
          style={{ fontSize: 13, fontFamily: meta.type === 'number' ? 'var(--font-mono)' : undefined }}
        />
      </div>
    );
  };

  return (
    <div>
      <div className="flex-between mb-24">
        <div>
          <div className="section-title">Policies</div>
          <div className="section-sub">Server-persisted filtering rules, alert thresholds and blocklists</div>
        </div>
        <button className="btn btn-primary btn-sm" onClick={saveAll} disabled={loading}>
          {saved ? <><CheckCircle size={13}/> Saved!</> : <><Save size={13}/> Save All</>}
        </button>
      </div>

      {error && (
        <div style={{ marginBottom: 12, padding: '10px 14px', borderRadius: 8, background: 'rgba(220,38,38,0.12)', color: '#f87171', fontSize: 13 }}>
          {error}
        </div>
      )}

      <div className="tab-bar" style={{ marginBottom: 20 }}>
        {[
          { id: 'thresholds', label: 'Thresholds' },
          { id: 'notifications', label: 'Notifications' },
          { id: 'retention', label: 'Retention' },
          { id: 'blocklist', label: `Blocklist (${blocklist.length})` },
        ].map(t => (
          <button key={t.id} className={`tab-item ${activeTab === t.id ? 'active' : ''}`}
            onClick={() => setActiveTab(t.id)}>{t.label}</button>
        ))}
      </div>

      {activeTab === 'thresholds' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Spam & filtering thresholds</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Stored in app_settings · applied live</span>
          </div>
          {THRESHOLD_KEYS.map(renderField)}
          <div style={{ marginTop: 20, padding: 16, background: 'var(--bg-primary)', borderRadius: 8 }}>
            <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 12, color: 'var(--text-muted)' }}>Spam score action map</div>
            <div style={{ position: 'relative', height: 32, background: 'var(--border)', borderRadius: 6, overflow: 'hidden' }}>
              <div style={{ position: 'absolute', left: 0, width: `${(parseFloat(policies.spam_threshold || 5) / 20) * 100}%`, height: '100%', background: 'rgba(22,163,74,0.4)' }}/>
              <div style={{ position: 'absolute', left: `${(parseFloat(policies.spam_threshold || 5) / 20) * 100}%`, width: `${((parseFloat(policies.block_threshold || 8) - parseFloat(policies.spam_threshold || 5)) / 20) * 100}%`, height: '100%', background: 'rgba(217,119,6,0.4)' }}/>
              <div style={{ position: 'absolute', left: `${(parseFloat(policies.block_threshold || 8) / 20) * 100}%`, width: `${((parseFloat(policies.quarantine_threshold || 10) - parseFloat(policies.block_threshold || 8)) / 20) * 100}%`, height: '100%', background: 'rgba(234,88,12,0.4)' }}/>
              <div style={{ position: 'absolute', left: `${(parseFloat(policies.quarantine_threshold || 10) / 20) * 100}%`, right: 0, height: '100%', background: 'rgba(220,38,38,0.4)' }}/>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6, fontSize: 11, color: 'var(--text-muted)' }}>
              <span>0 — Clean</span>
              <span style={{ color: '#d97706' }}>{policies.spam_threshold} — Flag</span>
              <span style={{ color: '#ea580c' }}>{policies.block_threshold} — Block</span>
              <span style={{ color: '#dc2626' }}>{policies.quarantine_threshold} — Quarantine</span>
              <span>20</span>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'notifications' && (
        <div className="card">
          <div className="card-header"><span className="card-title">Alert & notification settings</span></div>
          {NOTIFICATION_KEYS.map(renderField)}
        </div>
      )}

      {activeTab === 'retention' && (
        <div className="card">
          <div className="card-header"><span className="card-title">Log retention policy</span></div>
          {RETENTION_KEYS.map(renderField)}
        </div>
      )}

      {activeTab === 'blocklist' && (
        <div>
          <div className="card mb-16">
            <div className="card-header"><span className="card-title">Add to blocklist</span></div>
            <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr 1fr auto', gap: 10, alignItems: 'end' }}>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>Type</label>
                <select className="input" style={{ marginTop: 4 }} value={newBlock.type}
                  onChange={e => setNewBlock(p => ({ ...p, type: e.target.value }))}>
                  <option value="domain">Domain</option>
                  <option value="email">Email</option>
                  <option value="ip">IP</option>
                  <option value="cidr">CIDR</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>Value *</label>
                <input className="input" style={{ marginTop: 4 }} placeholder="spam.example.com"
                  value={newBlock.value} onChange={e => setNewBlock(p => ({ ...p, value: e.target.value }))}/>
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>Reason</label>
                <input className="input" style={{ marginTop: 4 }} placeholder="Known spam source"
                  value={newBlock.reason} onChange={e => setNewBlock(p => ({ ...p, reason: e.target.value }))}/>
              </div>
              <button className="btn btn-primary btn-sm" onClick={addBlock} disabled={!newBlock.value}>
                <Plus size={13}/> Add
              </button>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <span className="card-title">Blocklist ({blocklist.length})</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Mirrored to firewall_manual_blocks when available</span>
            </div>
            <div className="table-wrapper">
              <table>
                <thead><tr><th>Type</th><th>Value</th><th>Reason</th><th>Added</th><th></th></tr></thead>
                <tbody>
                  {blocklist.map((b) => (
                    <tr key={b.id}>
                      <td><span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 20, background: 'rgba(220,38,38,0.15)', color: '#f87171' }}>{b.type}</span></td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{b.value}</td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{b.reason}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{String(b.added || '').slice(0, 10)}</td>
                      <td>
                        <button className="btn btn-danger btn-sm" style={{ padding: '2px 8px' }}
                          onClick={() => removeBlock(b.id)}><Trash2 size={11}/></button>
                      </td>
                    </tr>
                  ))}
                  {blocklist.length === 0 && (
                    <tr><td colSpan={5} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>No blocklist entries</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
