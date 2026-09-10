import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Shield, AlertTriangle, Ban, Bug, Mail } from 'lucide-react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, LineChart, Line } from 'recharts';
import { statsApi } from '../utils/api';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const TT = { background: '#0d1117', border: '1px solid #2d3748', borderRadius: 8, fontSize: 12 };

const THREAT_CATS = [
  { key: 'spam',      label: 'Spam',        color: '#f97316', icon: Ban,           desc: 'Bulk/unsolicited mail blocked by RBL/DNSBL' },
  { key: 'phishing',  label: 'Phishing',    color: '#f43f5e', icon: AlertTriangle, desc: 'Phishing / impersonation (delivery + AI engine)' },
  { key: 'malware',   label: 'Malware',     color: '#a855f7', icon: Bug,           desc: 'Virus/malware detected by Amavis/ClamAV' },
  { key: 'blocked',   label: 'Blocked',     color: '#ef4444', icon: Shield,        desc: 'Rejected by policy/blacklist' },
  { key: 'bounced',   label: 'Bounced',     color: '#ea580c', icon: Mail,          desc: 'Permanent delivery failures (5xx)' },
  { key: 'failed',    label: 'Failed',      color: '#dc2626', icon: AlertTriangle, desc: 'General delivery failures' },
];

export default function ThreatsPage({ server, range, selectedDate }) {
  const [threatData,   setThreatData]   = useState(null);
  const [wrongHits,    setWrongHits]    = useState([]);
  const [spamSenders,  setSpamSenders]  = useState([]);
  const [recentThreats,setRecentThreats]= useState([]);
  const [loading,      setLoading]      = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = { server, range };
      if (range === 'today') params.date = selectedDate;

      const [td, wh, ss, rt] = await Promise.all([
        statsApi.getThreatBreakdown ? statsApi.getThreatBreakdown(params) : api.get('/stats/threat-breakdown', { params }),
        api.get('/stats/wrong-hits-trend', { params: { range: range === '30d' ? '30d' : '7d', server } }),
        api.get('/mails/spam-analysis', { params: { server } }),
        api.get('/agent/realtime-logs',  { params: { server, limit: 50 } }),
      ]);

      setThreatData(td.data?.data || td.data || {});
      setWrongHits((wh.data?.data || []).map(r => ({
        ...r,
        failed:      Number(r.failed      || 0),
        bounced:     Number(r.bounced     || 0),
        spam:        Number(r.spam        || 0),
        invalid:     Number(r.invalid     || 0),
        total_wrong: Number(r.total_wrong || 0),
      })));
      setSpamSenders(ss.data?.data || []);

      // Filter only threat events from realtime logs
      const threats = (rt.data?.data || []).filter(l =>
        l.spam_score > 5 ||
        ['Spam','Phishing','Malware','Blacklisted'].includes(l.classification) ||
        l.status === 'rejected' || l.status === 'blocked' ||
        (l.reason && (l.reason.toLowerCase().includes('spam') ||
                      l.reason.toLowerCase().includes('reject') ||
                      l.reason.toLowerCase().includes('blocked')))
      );
      setRecentThreats(threats);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [server, range, selectedDate]);

  useEffect(() => { load(); }, [load]);

  const serverLabel = server === 'campaign' ? '🟠 Campaign' : '🔵 App Mail';

  const total = Object.values(threatData || {}).reduce((a, b) => a + Number(b || 0), 0);
  const threatTotal = total - Number(threatData?.clean || 0);

  const pieData = THREAT_CATS.map(c => ({
    name:  c.label,
    value: Number(threatData?.[c.key] || 0),
    color: c.color,
  })).filter(d => d.value > 0);

  const dateLabel = v => {
    if (!v) return '';
    const d = v.includes('T') ? new Date(v) : new Date(v + 'T00:00:00');
    return `${(d.getMonth()+1).toString().padStart(2,'0')}-${d.getDate().toString().padStart(2,'0')}`;
  };

  if (loading) return <div className="loading-state"><RefreshCw size={20} className="spin" /></div>;

  return (
    <div>
      <div className="flex-between mb-24">
        <div>
          <div className="section-title">Threat Map</div>
          <div className="section-sub">
            {serverLabel} · Spam, phishing, malware and rejection analysis
            {threatData?.engine_enriched ? ' · Includes AI Threat Engine indicators' : ''}
          </div>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load}><RefreshCw size={13} /> Refresh</button>
      </div>

      {/* Threat summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12, marginBottom: 20 }}>
        {THREAT_CATS.map(cat => {
          const val = Number(threatData?.[cat.key] || 0);
          const Icon = cat.icon;
          return (
            <div key={cat.key} className="card" style={{ borderTop: `3px solid ${cat.color}` }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                <div style={{ width: 32, height: 32, borderRadius: 8, background: `${cat.color}18`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <Icon size={16} color={cat.color} />
                </div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>{cat.label}</div>
              </div>
              <div style={{ fontSize: 28, fontWeight: 800, color: val > 0 ? cat.color : 'var(--text-muted)', fontFamily: 'var(--font-mono)', lineHeight: 1 }}>
                {val.toLocaleString()}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>{cat.desc}</div>
              {total > 0 && val > 0 && (
                <div style={{ marginTop: 8 }}>
                  <div style={{ background: 'var(--border)', borderRadius: 3, height: 3 }}>
                    <div style={{ width: `${(val/total)*100}%`, height: '100%', background: cat.color, borderRadius: 3 }} />
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 3 }}>
                    {((val/total)*100).toFixed(1)}% of total
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 16, marginBottom: 20 }}>
        {/* Wrong hits trend */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Wrong Hits / Threat Trend</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>7-day history</span>
          </div>
          {wrongHits.length === 0 ? (
            <div className="loading-state">No trend data yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={wrongHits} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="log_date" tick={{ fill: '#6e7681', fontSize: 10 }} tickFormatter={dateLabel} />
                <YAxis tick={{ fill: '#6e7681', fontSize: 10 }} domain={[0,'auto']} allowDecimals={false} />
                <Tooltip contentStyle={TT} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Line type="monotone" dataKey="total_wrong" stroke="#dc2626" strokeWidth={2} dot={{ r: 3 }} name="Total Threats" />
                <Line type="monotone" dataKey="spam"        stroke="#f97316" strokeWidth={1.5} dot={false} strokeDasharray="4 2" name="Spam" />
                <Line type="monotone" dataKey="bounced"     stroke="#ea580c" strokeWidth={1.5} dot={false} strokeDasharray="4 2" name="Bounced" />
                <Line type="monotone" dataKey="invalid"     stroke="#7c3aed" strokeWidth={1}   dot={false} strokeDasharray="2 2" name="Invalid" />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Threat pie */}
        <div className="card">
          <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>Threat Breakdown</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12 }}>
            {threatTotal.toLocaleString()} total threats detected
          </div>
          {pieData.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 32, color: '#4ade80' }}>
              <Shield size={28} style={{ marginBottom: 8 }} />
              <div>No threats detected</div>
            </div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={140}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={40} outerRadius={60} dataKey="value" paddingAngle={2}>
                    {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
                  </Pie>
                  <Tooltip contentStyle={TT} />
                </PieChart>
              </ResponsiveContainer>
              {pieData.map((d, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: d.color }} />
                    <span style={{ color: 'var(--text-muted)' }}>{d.name}</span>
                  </div>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: d.color }}>{d.value.toLocaleString()}</span>
                </div>
              ))}
            </>
          )}
        </div>
      </div>

      {/* Recent threat events from realtime log */}
      <div className="card mb-16">
        <div className="card-header">
          <span className="card-title">Recent Threat Events</span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>From real-time log agent · {recentThreats.length} events</span>
        </div>
        {recentThreats.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 32, color: '#4ade80' }}>
            ✅ No threat events in recent logs
          </div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr><th>Time</th><th>From</th><th>To</th><th>Subject</th><th>Type</th><th>Score</th><th>Status</th><th>Reason</th></tr>
              </thead>
              <tbody>
                {recentThreats.map((l, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                      {(l.log_datetime || '').slice(0, 19)}
                    </td>
                    <td style={{ fontSize: 12, maxWidth: 160 }}>
                      <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{l.mail_from || '—'}</div>
                    </td>
                    <td style={{ fontSize: 12, maxWidth: 160 }}>
                      <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{l.mail_to || '—'}</div>
                    </td>
                    <td style={{ fontSize: 12, maxWidth: 200 }}>
                      <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: l.subject ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                        {l.subject || '—'}
                      </div>
                    </td>
                    <td>
                      {l.classification && (
                        <span style={{
                          fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 20,
                          background: l.classification === 'Spam' ? 'rgba(249,115,22,0.15)' :
                                      l.classification === 'Phishing' ? 'rgba(244,63,94,0.15)' :
                                      l.classification === 'Malware' ? 'rgba(168,85,247,0.15)' : 'rgba(239,68,68,0.15)',
                          color: l.classification === 'Spam' ? '#f97316' :
                                 l.classification === 'Phishing' ? '#f43f5e' :
                                 l.classification === 'Malware' ? '#a855f7' : '#ef4444',
                        }}>{l.classification}</span>
                      )}
                    </td>
                    <td>
                      {l.spam_score != null ? (
                        <span className="mono" style={{
                          fontSize: 11, fontWeight: 700,
                          color: l.spam_score > 10 ? '#f87171' : l.spam_score > 5 ? '#fbbf24' : '#4ade80'
                        }}>{Number(l.spam_score).toFixed(1)}</span>
                      ) : '—'}
                    </td>
                    <td>
                      <span style={{
                        fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 20,
                        background: 'rgba(220,38,38,0.15)', color: '#f87171',
                      }}>{l.status || '—'}</span>
                    </td>
                    <td style={{ fontSize: 11, color: '#fbbf24', maxWidth: 200 }}>
                      <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={l.reason}>
                        {l.reason || '—'}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Top spam senders */}
      {spamSenders.length > 0 && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Top Spam Sources (30 Days)</span>
          </div>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr><th>Sender</th><th>Blocks</th><th>First Seen</th><th>Last Seen</th><th>Days Active</th><th>Reasons</th></tr>
              </thead>
              <tbody>
                {spamSenders.map((r, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ fontSize: 12 }}>{r.mail_from}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#f87171' }}>{Number(r.count).toLocaleString()}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{r.first_seen}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{r.last_seen}</td>
                    <td>{r.days_active}</td>
                    <td style={{ fontSize: 11, color: '#fbbf24', maxWidth: 300 }}>{(r.reasons || '').slice(0, 150)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
