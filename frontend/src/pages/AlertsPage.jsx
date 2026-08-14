import { useState, useEffect } from 'react';
import { Bell, Send, AlertTriangle, CheckCircle, RefreshCw, Zap } from 'lucide-react';
import { alertsApi } from '../utils/api';

export default function AlertsPage({ server, setAlertCount }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [autoSending, setAutoSending] = useState(false);
  const [autoResult, setAutoResult] = useState(null);
  const [manualForm, setManualForm] = useState({ team: 'devops', subject: '', message: '' });
  const [manualSending, setManualSending] = useState(false);
  const [manualResult, setManualResult] = useState(null);

  const load = async () => {
    setLoading(true);
    try {
      const r = await alertsApi.getThresholds({ server });
      setData(r);
      setAlertCount(r.alerts?.length || 0);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const runAutoNotify = async () => {
    setAutoSending(true); setAutoResult(null);
    try {
      const r = await alertsApi.autoNotify({ server });
      setAutoResult({ success: true, message: r.message, sent: r.notifications_sent });
    } catch (e) { setAutoResult({ success: false, message: e.message }); }
    finally { setAutoSending(false); }
  };

  const sendManual = async () => {
    if (!manualForm.message && !manualForm.subject) return;
    setManualSending(true); setManualResult(null);
    try {
      const r = await alertsApi.sendNotify(manualForm);
      setManualResult({ success: true, message: r.message });
    } catch (e) { setManualResult({ success: false, message: e.message }); }
    finally { setManualSending(false); }
  };

  const SEVERITY_STYLES = {
    critical: { bg: 'rgba(220,38,38,0.1)', border: 'rgba(220,38,38,0.3)', color: '#f87171', label: '🔴 CRITICAL' },
    high: { bg: 'rgba(234,88,12,0.1)', border: 'rgba(234,88,12,0.3)', color: '#fb923c', label: '🟠 HIGH' },
    warning: { bg: 'rgba(217,119,6,0.1)', border: 'rgba(217,119,6,0.3)', color: '#fbbf24', label: '🟡 WARNING' },
  };

  return (
    <div>
      <div className="flex-between mb-24">
        <div>
          <div className="section-title">Alerts & Team Notifications</div>
          <div className="section-sub">Automatic threshold monitoring and manual team notifications</div>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load}><RefreshCw size={13} className={loading ? 'spin' : ''} /></button>
      </div>

      {loading ? (
        <div className="loading-state"><RefreshCw size={20} className="spin" /></div>
      ) : (
        <div className="grid-2">
          {/* Active Alerts */}
          <div>
            <div className="card mb-20">
              <div className="card-header">
                <span className="card-title">Today's Active Alerts</span>
                <span className="badge badge-failed">{data?.alerts?.length || 0} active</span>
              </div>

              {data?.alerts?.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 32, color: '#4ade80' }}>
                  <CheckCircle size={32} style={{ marginBottom: 8 }} />
                  <div style={{ fontWeight: 600 }}>All metrics within threshold</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>No alerts to report today</div>
                </div>
              ) : (
                data?.alerts?.map((alert, i) => {
                  const s = SEVERITY_STYLES[alert.severity] || SEVERITY_STYLES.warning;
                  return (
                    <div key={i} style={{ background: s.bg, border: `1px solid ${s.border}`, borderRadius: 8, padding: '14px 16px', marginBottom: 10 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: s.color }}>{s.label}</span>
                        <span className="badge" style={{ background: s.bg, color: s.color, border: `1px solid ${s.border}` }}>{alert.type}</span>
                        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)' }}>→ {alert.team} team</span>
                      </div>
                      <div style={{ fontSize: 13, color: 'var(--text-primary)' }}>{alert.message}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                        Count: <strong style={{ color: s.color }}>{Number(alert.count).toLocaleString()}</strong> · Threshold: {alert.threshold}
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Today's Stats */}
            <div className="card">
              <div className="card-header"><span className="card-title">Today's Stats Snapshot</span></div>
              {data?.stats && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  {[
                    { label: 'Total', val: data.stats.total, c: '#2563eb' },
                    { label: 'Success', val: data.stats.success, c: '#16a34a' },
                    { label: 'Failed', val: data.stats.failed, c: '#dc2626' },
                    { label: 'Bounced', val: data.stats.bounced, c: '#ea580c' },
                    { label: 'Spam Blocked', val: data.stats.spam, c: '#be185d' },
                    { label: 'Deferred', val: data.stats.deferred, c: '#d97706' },
                    { label: 'Timed Out', val: data.stats.timedout, c: '#7c3aed' },
                  ].map(s => (
                    <div key={s.label} style={{ background: 'var(--bg-primary)', borderRadius: 8, padding: '10px 14px', display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{s.label}</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: s.c }}>{Number(s.val || 0).toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Notification Tools */}
          <div>
            {/* Auto-Notify */}
            <div className="card mb-20">
              <div className="card-header">
                <span className="card-title">Auto-Notify All Teams</span>
              </div>
              <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.6 }}>
                Evaluates today's metrics against configured thresholds and automatically emails the relevant teams:
                DevOps (spam/blacklist), Backend (failed/invalid), Email Team (bounces).
              </p>
              <button className="btn btn-primary" onClick={runAutoNotify} disabled={autoSending} style={{ width: '100%', justifyContent: 'center' }}>
                {autoSending ? <><RefreshCw size={14} className="spin" /> Sending alerts...</> : <><Zap size={14} /> Run Auto-Notify Now</>}
              </button>
              {autoResult && (
                <div className={`alert-box ${autoResult.success ? 'alert-info' : 'alert-critical'}`} style={{ marginTop: 12 }}>
                  {autoResult.success ? '✅ ' : '❌ '}{autoResult.message}
                  {autoResult.sent?.length > 0 && (
                    <ul style={{ marginTop: 8, paddingLeft: 20, fontSize: 12 }}>
                      {autoResult.sent.map((s, i) => <li key={i}>{s}</li>)}
                    </ul>
                  )}
                </div>
              )}
            </div>

            {/* Manual Notify */}
            <div className="card mb-20">
              <div className="card-header"><span className="card-title">Manual Team Notification</span></div>
              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>TEAM</label>
                <select className="input" value={manualForm.team} onChange={e => setManualForm(f => ({ ...f, team: e.target.value }))}>
                  <option value="devops">DevOps Team</option>
                  <option value="backend">Backend / App Team</option>
                  <option value="email">Email / Campaign Team</option>
                </select>
              </div>
              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>SUBJECT</label>
                <input className="input" placeholder="Alert subject line..." value={manualForm.subject} onChange={e => setManualForm(f => ({ ...f, subject: e.target.value }))} />
              </div>
              <div style={{ marginBottom: 14 }}>
                <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>MESSAGE</label>
                <textarea className="input" rows={5} placeholder="Describe the issue and steps needed..." value={manualForm.message} onChange={e => setManualForm(f => ({ ...f, message: e.target.value }))} style={{ resize: 'vertical' }} />
              </div>
              <button className="btn btn-primary" onClick={sendManual} disabled={manualSending || (!manualForm.subject && !manualForm.message)} style={{ width: '100%', justifyContent: 'center' }}>
                {manualSending ? <><RefreshCw size={14} className="spin" /> Sending...</> : <><Send size={14} /> Send to Team</>}
              </button>
              {manualResult && (
                <div className={`alert-box ${manualResult.success ? 'alert-info' : 'alert-critical'}`} style={{ marginTop: 12 }}>
                  {manualResult.success ? '✅ ' : '❌ '}{manualResult.message}
                </div>
              )}
            </div>

            {/* Team Config */}
            <div className="card">
              <div className="card-header"><span className="card-title">Team Contact Config</span></div>
              {data?.teams && Object.entries(data.teams).map(([key, team]) => (
                <div key={key} style={{ padding: '10px 0', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                  <Bell size={14} style={{ marginTop: 3, color: 'var(--text-muted)', flexShrink: 0 }} />
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600 }}>{team.name}</div>
                    <div style={{ fontSize: 11, color: 'var(--accent-blue-light)', fontFamily: 'var(--font-mono)' }}>{team.email}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 3 }}>{team.issues.join(' · ')}</div>
                  </div>
                </div>
              ))}
              <div style={{ marginTop: 12, fontSize: 12, color: 'var(--text-muted)' }}>
                ℹ️ Update team emails via <code style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>.env</code> file: NOTIFY_TEAM_DEVOPS, NOTIFY_TEAM_BACKEND, NOTIFY_TEAM_EMAIL
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
