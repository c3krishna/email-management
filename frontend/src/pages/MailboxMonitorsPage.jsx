import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Plus, Trash2, Play, Power, Save, Bell } from 'lucide-react';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const EMPTY_FORM = {
  display_name: '', imap_host: 'imap.gmail.com', imap_port: 993, imap_user: '', imap_pass: '',
  folder: 'INBOX', use_ssl: true, poll_interval: 120,
  notify_emails: '', mail_server: 'app',
};

export default function MailboxMonitorsPage() {
  const [customers, setCustomers] = useState([]);
  const [customerId, setCustomerId] = useState('');
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [msg, setMsg] = useState(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [notif, setNotif] = useState({
    admin_emails: '', notify_admin: true, notify_spam: true,
    min_confidence: 70, active: true,
  });
  const [editNotifyId, setEditNotifyId] = useState(null);
  const [editNotifyEmails, setEditNotifyEmails] = useState('');

  useEffect(() => {
    api.get('/platform/customers').then(r => {
      const list = r.data.data || [];
      setCustomers(list);
      if (list.length) setCustomerId(String(list[0].id));
    }).catch(() => {});
  }, []);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const r = await api.get('/mailbox-monitors', {
        params: customerId ? { customer_id: customerId } : {},
      });
      setRows(r.data.data || []);
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    } finally {
      setLoading(false);
    }
  }, [customerId]);

  const loadNotif = useCallback(async () => {
    if (!customerId) return;
    try {
      const r = await api.get(`/notifications/settings/${customerId}`);
      const d = r.data.data || {};
      const emails = Array.isArray(d.admin_emails) ? d.admin_emails.join(', ') : (d.admin_emails || '');
      setNotif({
        admin_emails: emails,
        notify_admin: !!d.notify_admin,
        notify_spam: d.notify_spam !== 0,
        min_confidence: d.min_confidence ?? 70,
        active: d.active !== 0,
      });
    } catch (_) {}
  }, [customerId]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadNotif(); }, [loadNotif]);

  const add = async () => {
    try {
      await api.post('/mailbox-monitors', {
        ...form,
        customer_id: Number(customerId),
        notify_emails: form.notify_emails,
      });
      setForm(EMPTY_FORM);
      setMsg({ ok: true, text: 'Mailbox monitor added — threats will alert the notify emails' });
      load();
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  const saveNotif = async () => {
    if (!customerId) return;
    try {
      const emails = notif.admin_emails.split(/[,;\s]+/).map(e => e.trim()).filter(e => e.includes('@'));
      await api.post('/notifications/settings', {
        customer_id: Number(customerId),
        admin_emails: emails,
        notify_admin: notif.notify_admin,
        notify_spam: notif.notify_spam,
        min_confidence: Number(notif.min_confidence) || 70,
        active: notif.active,
        notify_end_user: false,
      });
      setMsg({ ok: true, text: `Customer alert emails saved (${emails.length})` });
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  const testNotif = async () => {
    const first = notif.admin_emails.split(/[,;\s]+/).find(e => e.includes('@'));
    if (!first) { setError('Add at least one admin email first'); return; }
    try {
      const r = await api.post('/notifications/test', { customer_id: Number(customerId), email: first });
      setMsg({ ok: true, text: r.data.message || 'Test sent' });
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  const saveRowNotify = async (id) => {
    try {
      await api.put(`/mailbox-monitors/${id}`, { notify_emails: editNotifyEmails });
      setEditNotifyId(null);
      setMsg({ ok: true, text: 'Notify emails updated for this mailbox' });
      load();
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  const test = async (id) => {
    setMsg(null);
    try {
      const r = await api.post(`/mailbox-monitors/${id}/test`);
      setMsg({ ok: !!r.data.success, text: r.data.message || 'Test complete' });
    } catch (e) {
      setMsg({ ok: false, text: e.response?.data?.error || e.message });
    }
  };

  const toggle = async (row) => {
    try {
      await api.put(`/mailbox-monitors/${row.id}`, { active: !row.active });
      load();
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  const remove = async (id) => {
    if (!window.confirm('Deactivate this mailbox monitor?')) return;
    try {
      await api.delete(`/mailbox-monitors/${id}`);
      load();
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  return (
    <div>
      <div className="flex-between mb-16">
        <div>
          <div className="section-title">Customer Mailbox Protection</div>
          <div className="section-sub">
            Scan important customer inboxes (Gmail / Microsoft / IMAP) for spam, phishing &amp; junk —
            alert other emails when threats are found
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <select className="input" style={{ width: 220, fontSize: 12 }} value={customerId}
            onChange={e => setCustomerId(e.target.value)}>
            <option value="">All customers</option>
            {customers.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
          <button className="btn btn-ghost btn-sm" onClick={() => { load(); loadNotif(); }}>
            <RefreshCw size={13}/> Refresh
          </button>
        </div>
      </div>

      {(error || msg) && (
        <div style={{
          marginBottom: 12, padding: '10px 14px', borderRadius: 8, fontSize: 13,
          background: (msg?.ok ?? !error) ? 'rgba(22,163,74,0.12)' : 'rgba(220,38,38,0.12)',
          color: (msg?.ok ?? !error) ? 'var(--accent-green)' : 'var(--accent-red)',
        }}>{msg?.text || error}</div>
      )}

      {customerId && (
        <div className="card mb-16">
          <div className="card-header">
            <span className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Bell size={14}/> Alert notification emails (customer IT / security team)
            </span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 120px 100px auto auto', gap: 10, alignItems: 'end' }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                Notify these emails when spam / phishing / junk is detected (comma-separated)
              </label>
              <input className="input" style={{ marginTop: 4 }}
                placeholder="security@customer.com, it-admin@customer.com"
                value={notif.admin_emails}
                onChange={e => setNotif(n => ({ ...n, admin_emails: e.target.value }))}/>
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>Min confidence</label>
              <input className="input" style={{ marginTop: 4 }} type="number" min={0} max={100}
                value={notif.min_confidence}
                onChange={e => setNotif(n => ({ ...n, min_confidence: e.target.value }))}/>
            </div>
            <label style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, paddingBottom: 8 }}>
              <input type="checkbox" checked={notif.active}
                onChange={e => setNotif(n => ({ ...n, active: e.target.checked }))}/> Active
            </label>
            <button className="btn btn-primary btn-sm" onClick={saveNotif}><Save size={13}/> Save</button>
            <button className="btn btn-ghost btn-sm" onClick={testNotif}>Test email</button>
          </div>
        </div>
      )}

      <div className="card mb-16">
        <div className="card-header"><span className="card-title">Add mailbox to scan</span></div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10 }}>
          {[
            ['display_name', 'Display name (e.g. CEO inbox)'],
            ['imap_host', 'IMAP host (imap.gmail.com)'],
            ['imap_user', 'Mailbox email / IMAP user'],
            ['imap_pass', 'App password'],
          ].map(([key, label]) => (
            <div key={key}>
              <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>{label}</label>
              <input className="input" style={{ marginTop: 4 }} type={key === 'imap_pass' ? 'password' : 'text'}
                value={form[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}/>
            </div>
          ))}
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>Mail server</label>
            <select className="input" style={{ marginTop: 4 }} value={form.mail_server}
              onChange={e => setForm(f => ({ ...f, mail_server: e.target.value }))}>
              <option value="app">App — mail.worktual.tech</option>
              <option value="campaign">Campaign — mail.worktual.pl</option>
              <option value="both">Both</option>
            </select>
          </div>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>Port</label>
            <input className="input" style={{ marginTop: 4 }} type="number" value={form.imap_port}
              onChange={e => setForm(f => ({ ...f, imap_port: Number(e.target.value) }))}/>
          </div>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>Folder</label>
            <input className="input" style={{ marginTop: 4 }} value={form.folder}
              onChange={e => setForm(f => ({ ...f, folder: e.target.value }))}/>
          </div>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>Poll interval (s)</label>
            <input className="input" style={{ marginTop: 4 }} type="number" value={form.poll_interval}
              onChange={e => setForm(f => ({ ...f, poll_interval: Number(e.target.value) }))}/>
          </div>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Extra notify emails (optional, per mailbox)
            </label>
            <input className="input" style={{ marginTop: 4 }}
              placeholder="ceo-assistant@customer.com"
              value={form.notify_emails}
              onChange={e => setForm(f => ({ ...f, notify_emails: e.target.value }))}/>
          </div>
          <div style={{ display: 'flex', alignItems: 'end' }}>
            <button className="btn btn-primary btn-sm" onClick={add}
              disabled={!customerId || !form.imap_host || !form.imap_user || !form.imap_pass}>
              <Plus size={13}/> Add monitor
            </button>
          </div>
        </div>
        <div style={{ marginTop: 10, fontSize: 12, color: 'var(--text-muted)' }}>
          Gmail: enable IMAP + create an App Password. Outlook: use imap-mail.outlook.com / App Password or OAuth IMAP.
          The mailbox-monitor agent scans for phishing, spam, BEC, malware patterns and emails your notify list.
        </div>
      </div>

      <div className="card">
        {loading ? (
          <div className="loading-state"><RefreshCw size={18} className="spin"/></div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Name</th><th>Customer</th><th>Host</th><th>User</th>
                  <th>Notify</th>
                  <th>Poll</th><th>Scanned</th><th>Threats</th><th>Last check</th><th>Active</th><th></th>
                </tr>
              </thead>
              <tbody>
                {rows.map(row => (
                  <tr key={row.id}>
                    <td style={{ fontWeight: 600 }}>{row.display_name}</td>
                    <td style={{ fontSize: 12 }}>{row.customer_name || row.customer_id}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{row.imap_host}:{row.imap_port}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{row.imap_user}</td>
                    <td style={{ fontSize: 11, maxWidth: 200 }}>
                      {editNotifyId === row.id ? (
                        <div style={{ display: 'flex', gap: 4 }}>
                          <input className="input" style={{ fontSize: 11 }} value={editNotifyEmails}
                            onChange={e => setEditNotifyEmails(e.target.value)}/>
                          <button className="btn btn-primary btn-sm" onClick={() => saveRowNotify(row.id)}>Save</button>
                        </div>
                      ) : (
                        <button className="btn btn-ghost btn-sm" style={{ fontSize: 11 }}
                          onClick={() => {
                            setEditNotifyId(row.id);
                            setEditNotifyEmails((row.notify_emails || []).join(', '));
                          }}>
                          {(row.notify_emails || []).length
                            ? (row.notify_emails || []).join(', ')
                            : 'Set emails…'}
                        </button>
                      )}
                    </td>
                    <td className="mono" style={{ fontSize: 11 }}>{row.poll_interval}s</td>
                    <td className="mono" style={{ fontSize: 11 }}>{row.total_scanned ?? 0}</td>
                    <td className="mono" style={{ fontSize: 11, color: row.total_threats ? 'var(--accent-red)' : undefined }}>{row.total_threats ?? 0}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{row.last_checked ? String(row.last_checked).slice(0, 16) : '—'}</td>
                    <td>
                      <span style={{
                        fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 20,
                        background: row.active ? 'rgba(22,163,74,0.15)' : 'rgba(107,114,128,0.15)',
                        color: row.active ? 'var(--accent-green)' : 'var(--text-muted)'
                      }}>{row.active ? 'on' : 'off'}</span>
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <button className="btn btn-ghost btn-sm" title="Test IMAP" onClick={() => test(row.id)}><Play size={12}/></button>
                      <button className="btn btn-ghost btn-sm" title="Toggle" onClick={() => toggle(row)}><Power size={12}/></button>
                      <button className="btn btn-ghost btn-sm" title="Deactivate" onClick={() => remove(row.id)}><Trash2 size={12}/></button>
                    </td>
                  </tr>
                ))}
                {!rows.length && (
                  <tr><td colSpan={11} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>No mailbox monitors configured</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
