import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Plus, Trash2, Shield, UserCheck, AlertTriangle } from 'lucide-react';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

export default function VIPProtectionPage() {
  const [customers, setCustomers] = useState([]);
  const [customerId, setCustomerId] = useState('');
  const [vips, setVips] = useState([]);
  const [impersonation, setImpersonation] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState('vips');
  const [form, setForm] = useState({ display_name: '', real_email: '', title: '' });
  const [error, setError] = useState(null);

  useEffect(() => {
    api.get('/platform/customers').then(r => {
      const list = r.data.data || [];
      setCustomers(list);
      if (list.length && !customerId) setCustomerId(String(list[0].id));
    }).catch(() => {});
  }, []);

  const load = useCallback(async () => {
    if (!customerId) return;
    setLoading(true); setError(null);
    try {
      const [v, i, a, s] = await Promise.all([
        api.get('/protection/vip-contacts', { params: { customer_id: customerId } }),
        api.get('/protection/impersonation-alerts', { params: { customer_id: customerId } }),
        api.get('/protection/anomaly-alerts', { params: { customer_id: customerId } }),
        api.get('/protection/protection-summary', { params: { customer_id: customerId } }),
      ]);
      setVips(v.data.data || []);
      setImpersonation(i.data.data || []);
      setAnomalies(a.data.data || []);
      setSummary(s.data.data || null);
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    } finally {
      setLoading(false);
    }
  }, [customerId]);

  useEffect(() => { load(); }, [load]);

  const addVip = async () => {
    try {
      await api.post('/protection/vip-contacts', { ...form, customer_id: Number(customerId) });
      setForm({ display_name: '', real_email: '', title: '' });
      load();
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  const removeVip = async (id) => {
    if (!window.confirm('Deactivate this VIP contact?')) return;
    try {
      await api.delete(`/protection/vip-contacts/${id}`);
      load();
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  const review = async (kind, id) => {
    try {
      await api.patch(`/protection/${kind}-alerts/${id}/review`, { status: 'reviewed' });
      load();
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  return (
    <div>
      <div className="flex-between mb-16">
        <div>
          <div className="section-title">VIP Protection</div>
          <div className="section-sub">Executive contacts · Impersonation · Behavioral anomalies</div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <select className="input" style={{ width: 220, fontSize: 12 }} value={customerId}
            onChange={e => setCustomerId(e.target.value)}>
            <option value="">Select customer</option>
            {customers.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
          <button className="btn btn-ghost btn-sm" onClick={load} disabled={!customerId || loading}>
            <RefreshCw size={13}/> Refresh
          </button>
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: 12, padding: '10px 14px', borderRadius: 8, background: 'rgba(220,38,38,0.12)', color: '#f87171', fontSize: 13 }}>{error}</div>
      )}

      {summary && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12, marginBottom: 20 }}>
          {[
            { label: 'VIP Contacts', value: summary.vip_contacts_registered, icon: UserCheck, color: '#2563eb' },
            { label: 'Impersonation (7d)', value: summary.impersonation_attempts, icon: Shield, color: '#f43f5e' },
            { label: 'Anomalies (7d)', value: summary.behavioral_anomalies, icon: AlertTriangle, color: '#f97316' },
          ].map(s => (
            <div key={s.label} className="card" style={{ padding: '14px 16px', borderTop: `3px solid ${s.color}` }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <s.icon size={14} color={s.color}/>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{s.label}</span>
              </div>
              <div style={{ fontSize: 24, fontWeight: 800, color: s.color, fontFamily: 'var(--font-mono)' }}>{s.value}</div>
            </div>
          ))}
        </div>
      )}

      <div className="tab-bar" style={{ marginBottom: 16 }}>
        {[
          { id: 'vips', label: `VIP Contacts (${vips.length})` },
          { id: 'impersonation', label: `Impersonation (${impersonation.length})` },
          { id: 'anomalies', label: `Anomalies (${anomalies.length})` },
        ].map(t => (
          <button key={t.id} className={`tab-item ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </div>

      {tab === 'vips' && (
        <div>
          <div className="card mb-16">
            <div className="card-header"><span className="card-title">Add VIP contact</span></div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: 10, alignItems: 'end' }}>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>Display name</label>
                <input className="input" style={{ marginTop: 4 }} value={form.display_name}
                  onChange={e => setForm(f => ({ ...f, display_name: e.target.value }))}/>
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>Real email</label>
                <input className="input" style={{ marginTop: 4 }} value={form.real_email}
                  onChange={e => setForm(f => ({ ...f, real_email: e.target.value }))}/>
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>Title</label>
                <input className="input" style={{ marginTop: 4 }} value={form.title}
                  onChange={e => setForm(f => ({ ...f, title: e.target.value }))}/>
              </div>
              <button className="btn btn-primary btn-sm" onClick={addVip}
                disabled={!form.display_name || !form.real_email || !customerId}>
                <Plus size={13}/> Add
              </button>
            </div>
          </div>
          <div className="card">
            <div className="table-wrapper">
              <table>
                <thead><tr><th>Name</th><th>Email</th><th>Title</th><th>Active</th><th></th></tr></thead>
                <tbody>
                  {vips.map(v => (
                    <tr key={v.id}>
                      <td style={{ fontWeight: 600 }}>{v.display_name}</td>
                      <td className="mono" style={{ fontSize: 12 }}>{v.real_email}</td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{v.title || '—'}</td>
                      <td>{v.active ? 'Yes' : 'No'}</td>
                      <td>
                        <button className="btn btn-ghost btn-sm" onClick={() => removeVip(v.id)}><Trash2 size={12}/></button>
                      </td>
                    </tr>
                  ))}
                  {!vips.length && !loading && (
                    <tr><td colSpan={5} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>No VIP contacts yet</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {tab === 'impersonation' && (
        <div className="card">
          <div className="table-wrapper">
            <table>
              <thead><tr><th>Detected</th><th>Details</th><th>Status</th><th></th></tr></thead>
              <tbody>
                {impersonation.map(row => (
                  <tr key={row.id}>
                    <td className="mono" style={{ fontSize: 11 }}>{String(row.detected_at || '').slice(0, 19)}</td>
                    <td style={{ fontSize: 12 }}>
                      <div style={{ fontWeight: 600 }}>{row.spoofed_name || row.sender || row.subject || 'Impersonation alert'}</div>
                      <div style={{ color: 'var(--text-muted)' }}>{row.details || row.reason || row.matched_vip || ''}</div>
                    </td>
                    <td style={{ fontSize: 12 }}>{row.reviewed ? 'reviewed' : (row.status || 'open')}</td>
                    <td>
                      {!row.reviewed && (
                        <button className="btn btn-ghost btn-sm" onClick={() => review('impersonation', row.id)}>Mark reviewed</button>
                      )}
                    </td>
                  </tr>
                ))}
                {!impersonation.length && (
                  <tr><td colSpan={4} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>No impersonation alerts</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'anomalies' && (
        <div className="card">
          <div className="table-wrapper">
            <table>
              <thead><tr><th>Detected</th><th>Details</th><th>Status</th><th></th></tr></thead>
              <tbody>
                {anomalies.map(row => (
                  <tr key={row.id}>
                    <td className="mono" style={{ fontSize: 11 }}>{String(row.detected_at || '').slice(0, 19)}</td>
                    <td style={{ fontSize: 12 }}>
                      <div style={{ fontWeight: 600 }}>{row.sender || row.anomaly_type || 'Anomaly'}</div>
                      <div style={{ color: 'var(--text-muted)' }}>{row.details || row.reason || ''}</div>
                    </td>
                    <td style={{ fontSize: 12 }}>{row.reviewed ? 'reviewed' : (row.status || 'open')}</td>
                    <td>
                      {!row.reviewed && (
                        <button className="btn btn-ghost btn-sm" onClick={() => review('anomaly', row.id)}>Mark reviewed</button>
                      )}
                    </td>
                  </tr>
                ))}
                {!anomalies.length && (
                  <tr><td colSpan={4} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>No anomaly alerts</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
