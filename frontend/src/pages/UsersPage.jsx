import { useState, useEffect } from 'react';
import { UserPlus, Edit, Trash2, Unlock, RefreshCw, Shield, Eye, Settings } from 'lucide-react';
import axios from 'axios';

const ROLE_BADGE = {
  super_admin: { label: 'Super Admin', color: '#f97316', bg: 'rgba(249,115,22,0.15)' },
  admin:       { label: 'Admin',       color: '#60a5fa', bg: 'rgba(96,165,250,0.15)' },
  viewer:      { label: 'Viewer',      color: '#4ade80', bg: 'rgba(74,222,128,0.15)' },
};

const ROLE_DESC = {
  super_admin: 'Full access — manage users, view all data, send notifications',
  admin:       'View all data, send notifications, manage alerts',
  viewer:      'View dashboard and mail data only — no notifications or user management',
};

export default function UsersPage({ currentUser }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null); // null | 'create' | 'edit' | 'delete'
  const [selected, setSelected] = useState(null);
  const [form, setForm] = useState({ name: '', email: '', password: '', role: 'viewer', is_active: true });
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState({ type: '', text: '' });
  const [audit, setAudit] = useState([]);
  const [tab, setTab] = useState('users');

  const token = localStorage.getItem('em_token');
  const api = axios.create({ headers: { Authorization: `Bearer ${token}` } });

  const load = async () => {
    setLoading(true);
    try {
      const r = await api.get('/api/users');
      setUsers(r.data.data);
    } catch (e) {
      setMsg({ type: 'error', text: e.response?.data?.error || 'Failed to load users' });
    } finally {
      setLoading(false);
    }
  };

  const loadAudit = async () => {
    try {
      const r = await api.get('/api/users/audit');
      setAudit(r.data.data);
    } catch (e) { /* silent */ }
  };

  useEffect(() => { load(); }, []);
  useEffect(() => { if (tab === 'audit') loadAudit(); }, [tab]);

  const openCreate = () => {
    setForm({ name: '', email: '', password: '', role: 'viewer', is_active: true });
    setMsg({ type: '', text: '' });
    setModal('create');
  };

  const openEdit = (u) => {
    setSelected(u);
    setForm({ name: u.name, email: u.email, password: '', role: u.role, is_active: u.is_active === 1 });
    setMsg({ type: '', text: '' });
    setModal('edit');
  };

  const handleCreate = async () => {
    if (!form.name || !form.email || !form.password || !form.role) {
      return setMsg({ type: 'error', text: 'All fields required.' });
    }
    setSaving(true);
    try {
      await api.post('/api/users', form);
      setMsg({ type: 'success', text: `User ${form.email} created. Welcome email sent.` });
      setModal(null);
      load();
    } catch (e) {
      setMsg({ type: 'error', text: e.response?.data?.error || 'Failed to create user.' });
    } finally {
      setSaving(false);
    }
  };

  const handleEdit = async () => {
    setSaving(true);
    try {
      const payload = { name: form.name, role: form.role, is_active: form.is_active };
      if (form.password) payload.password = form.password;
      await api.put(`/api/users/${selected.id}`, payload);
      setMsg({ type: 'success', text: 'User updated.' });
      setModal(null);
      load();
    } catch (e) {
      setMsg({ type: 'error', text: e.response?.data?.error || 'Failed to update.' });
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    setSaving(true);
    try {
      await api.delete(`/api/users/${selected.id}`);
      setModal(null);
      load();
    } catch (e) {
      setMsg({ type: 'error', text: e.response?.data?.error || 'Failed to delete.' });
    } finally {
      setSaving(false);
    }
  };

  const handleUnlock = async (userId) => {
    try {
      await api.post(`/api/users/${userId}/unlock`);
      load();
    } catch (e) { alert(e.response?.data?.error); }
  };

  const RoleBadge = ({ role }) => {
    const r = ROLE_BADGE[role] || { label: role, color: '#9ca3af', bg: 'rgba(156,163,175,0.15)' };
    return (
      <span style={{ background: r.bg, color: r.color, padding: '2px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700 }}>
        {r.label}
      </span>
    );
  };

  return (
    <div>
      <div className="flex-between mb-24">
        <div>
          <div className="section-title">User Management</div>
          <div className="section-sub">Manage dashboard access with role-based permissions</div>
        </div>
        {currentUser?.role === 'super_admin' && (
          <button className="btn btn-primary" onClick={openCreate}>
            <UserPlus size={14} /> Create User
          </button>
        )}
      </div>

      {msg.text && !modal && (
        <div className={`alert-box ${msg.type === 'error' ? 'alert-critical' : 'alert-info'}`} style={{ marginBottom: 16 }}>
          {msg.type === 'error' ? '❌' : '✅'} {msg.text}
        </div>
      )}

      {/* Role descriptions */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12, marginBottom: 24 }}>
        {Object.entries(ROLE_BADGE).map(([role, r]) => (
          <div key={role} style={{ background: 'var(--bg-card)', border: `1px solid ${r.color}33`, borderRadius: 8, padding: '14px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              {role === 'super_admin' ? <Shield size={14} color={r.color} /> : role === 'admin' ? <Settings size={14} color={r.color} /> : <Eye size={14} color={r.color} />}
              <span style={{ fontWeight: 700, color: r.color, fontSize: 13 }}>{r.label}</span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>{ROLE_DESC[role]}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="tab-bar">
        <button className={`tab-item ${tab === 'users' ? 'active' : ''}`} onClick={() => setTab('users')}>Users ({users.length})</button>
        <button className={`tab-item ${tab === 'audit' ? 'active' : ''}`} onClick={() => setTab('audit')}>Audit Log</button>
      </div>

      {tab === 'users' && (
        <div className="card">
          {loading ? (
            <div className="loading-state"><RefreshCw size={18} className="spin" /></div>
          ) : (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Name</th><th>Email</th><th>Role</th><th>Status</th>
                    <th>Last Login</th><th>Login Attempts</th><th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map(u => (
                    <tr key={u.id}>
                      <td style={{ fontWeight: 600 }}>{u.name}</td>
                      <td className="mono" style={{ fontSize: 12 }}>{u.email}</td>
                      <td><RoleBadge role={u.role} /></td>
                      <td>
                        <span className={`badge ${u.is_active ? 'badge-sent' : 'badge-failed'}`}>
                          {u.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {u.last_login ? new Date(u.last_login).toLocaleString('en-IN') : 'Never'}
                      </td>
                      <td>
                        {u.login_attempts > 0 ? (
                          <span style={{ color: u.login_attempts >= 5 ? '#f87171' : '#fbbf24', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                            {u.login_attempts} {u.login_attempts >= 5 ? '🔒 Locked' : ''}
                          </span>
                        ) : <span style={{ color: 'var(--text-muted)' }}>0</span>}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6 }}>
                          {currentUser?.role === 'super_admin' && (
                            <>
                              <button className="btn btn-ghost btn-sm" onClick={() => openEdit(u)} title="Edit">
                                <Edit size={12} />
                              </button>
                              {u.login_attempts >= 5 && (
                                <button className="btn btn-warn btn-sm" onClick={() => handleUnlock(u.id)} title="Unlock">
                                  <Unlock size={12} />
                                </button>
                              )}
                              {u.id !== currentUser?.id && (
                                <button className="btn btn-danger btn-sm" onClick={() => { setSelected(u); setModal('delete'); }} title="Delete">
                                  <Trash2 size={12} />
                                </button>
                              )}
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'audit' && (
        <div className="card">
          <div className="table-wrapper">
            <table>
              <thead>
                <tr><th>Time</th><th>User</th><th>Action</th><th>Details</th><th>IP</th></tr>
              </thead>
              <tbody>
                {audit.map(a => (
                  <tr key={a.id}>
                    <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
                      {new Date(a.created_at).toLocaleString('en-IN')}
                    </td>
                    <td style={{ fontSize: 12 }}>{a.user_email}</td>
                    <td>
                      <span className={`badge ${a.action.includes('FAIL') ? 'badge-failed' : a.action.includes('SUCCESS') ? 'badge-sent' : 'badge-processing'}`}>
                        {a.action}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{a.details || '—'}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{a.ip_address}</td>
                  </tr>
                ))}
                {audit.length === 0 && (
                  <tr><td colSpan={5} className="text-center" style={{ padding: 32, color: 'var(--text-muted)' }}>No audit logs</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ---- CREATE / EDIT MODAL ---- */}
      {(modal === 'create' || modal === 'edit') && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, padding: 28, width: 480, maxWidth: '90vw' }}>
            <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 20 }}>
              {modal === 'create' ? '➕ Create New User' : '✏️ Edit User'}
            </div>

            {[
              { key: 'name', label: 'Full Name', type: 'text', placeholder: 'John Smith' },
              { key: 'email', label: 'Email', type: 'email', placeholder: 'john@worktual.tech', disabled: modal === 'edit' },
              { key: 'password', label: modal === 'create' ? 'Password' : 'New Password (leave blank to keep)', type: 'password', placeholder: '••••••••' },
            ].map(f => (
              <div key={f.key} style={{ marginBottom: 14 }}>
                <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4, textTransform: 'uppercase' }}>{f.label}</label>
                <input className="input" type={f.type} placeholder={f.placeholder}
                  value={form[f.key]} disabled={f.disabled}
                  onChange={e => setForm(p => ({ ...p, [f.key]: e.target.value }))} />
              </div>
            ))}

            <div style={{ marginBottom: 14 }}>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4, textTransform: 'uppercase' }}>Role</label>
              <select className="input" value={form.role} onChange={e => setForm(p => ({ ...p, role: e.target.value }))}>
                <option value="viewer">Viewer — Read only</option>
                <option value="admin">Admin — Manage alerts</option>
                <option value="super_admin">Super Admin — Full access</option>
              </select>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{ROLE_DESC[form.role]}</div>
            </div>

            {modal === 'edit' && (
              <div style={{ marginBottom: 16, display: 'flex', alignItems: 'center', gap: 10 }}>
                <input type="checkbox" id="is_active" checked={form.is_active}
                  onChange={e => setForm(p => ({ ...p, is_active: e.target.checked }))} />
                <label htmlFor="is_active" style={{ fontSize: 13, cursor: 'pointer' }}>Account Active</label>
              </div>
            )}

            {msg.text && (
              <div className={`alert-box ${msg.type === 'error' ? 'alert-critical' : 'alert-info'}`} style={{ marginBottom: 14 }}>
                {msg.type === 'error' ? '❌' : '✅'} {msg.text}
              </div>
            )}

            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="btn btn-ghost" onClick={() => setModal(null)}>Cancel</button>
              <button className="btn btn-primary" disabled={saving}
                onClick={modal === 'create' ? handleCreate : handleEdit}>
                {saving ? <RefreshCw size={13} className="spin" /> : null}
                {modal === 'create' ? 'Create User' : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ---- DELETE CONFIRM ---- */}
      {modal === 'delete' && selected && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, padding: 28, width: 400 }}>
            <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 8 }}>🗑️ Delete User</div>
            <p style={{ color: 'var(--text-muted)', marginBottom: 20 }}>
              Delete <strong style={{ color: 'var(--text-primary)' }}>{selected.name}</strong> ({selected.email})?
              This cannot be undone.
            </p>
            {msg.text && <div className="alert-box alert-critical" style={{ marginBottom: 14 }}>❌ {msg.text}</div>}
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="btn btn-ghost" onClick={() => setModal(null)}>Cancel</button>
              <button className="btn btn-danger" disabled={saving} onClick={handleDelete}>
                {saving ? 'Deleting...' : 'Delete User'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
