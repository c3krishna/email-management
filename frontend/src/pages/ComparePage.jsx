import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, AlertTriangle, CheckCircle, Download, Search } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer, Cell,
  AreaChart, Area,
} from 'recharts';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const S = { success: '#16a34a', failed: '#dc2626', bounced: '#ea580c', deferred: '#d97706', missing: '#7c3aed' };
const TT = { background: '#1c2230', border: '1px solid #2d3748', borderRadius: 8, fontSize: 12 };

function Stat({ label, value, color, sub }) {
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 18px' }}>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color: color || 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      {sub && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

export default function ComparePage({ range, selectedDate, dateFrom, dateTo, server = 'campaign' }) {
  const [campaigns,  setCampaigns]  = useState([]);
  const [summary,    setSummary]    = useState([]);
  const [missing,    setMissing]    = useState([]);
  const [mismatch,   setMismatch]   = useState([]);
  const [hourly,     setHourly]     = useState([]);
  const [loading,    setLoading]    = useState(true);
  const [activeTab,  setActiveTab]  = useState('overview');
  const [selectedCampaign, setSelectedCampaign] = useState('');
  const [searchMissing, setSearchMissing] = useState('');
  const [missingPage,   setMissingPage]   = useState(1);
  const [missingTotal,  setMissingTotal]  = useState(0);

  // Queue tables are Campaign-only; delivery waveform uses Topbar server
  const queueServer = 'campaign';
  const waveServer  = server || 'app';

  const buildParams = useCallback((extra = {}) => {
    const p = { range, server: queueServer, ...extra };
    if (range === 'today') p.date = selectedDate;
    if (range === 'custom') { p.from = dateFrom; p.to = dateTo; }
    if (selectedCampaign) p.campaign_id = selectedCampaign;
    return p;
  }, [range, selectedDate, dateFrom, dateTo, selectedCampaign]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [c, s, h] = await Promise.all([
        api.get('/compare/campaigns', { params: { range, server: queueServer, ...(range === 'today' ? { date: selectedDate } : {}), ...(range === 'custom' ? { from: dateFrom, to: dateTo } : {}) } }),
        api.get('/compare/summary',   { params: buildParams() }),
        api.get('/stats/hourly', { params: { date: selectedDate, range, server: waveServer } }).catch(() => ({ data: { data: [] } })),
      ]);
      setCampaigns(c.data.data || []);
      setSummary(s.data.data || []);
      const rawHourly = h.data?.data || [];
      setHourly(Array.from({ length: 24 }, (_, hour) => {
        const row = rawHourly.find(r => Number(r.hour) === hour) || {};
        return {
          hour: `${String(hour).padStart(2, '0')}:00`,
          delivered: Number(row.success || 0),
          failed: Number(row.failed || 0),
          bounced: Number(row.bounced || 0),
          total: Number(row.total || 0),
        };
      }));
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [buildParams, range, waveServer, selectedDate, dateFrom, dateTo]);

  const loadMissing = useCallback(async (pg = 1) => {
    try {
      const r = await api.get('/compare/missing', { params: { ...buildParams(), page: pg, limit: 100 } });
      setMissing(r.data.data);
      setMissingTotal(r.data.total);
    } catch (e) { console.error(e); }
  }, [buildParams]);

  const loadMismatch = useCallback(async () => {
    try {
      const r = await api.get('/compare/mismatch', { params: buildParams() });
      setMismatch(r.data.data);
    } catch (e) { console.error(e); }
  }, [buildParams]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (activeTab === 'missing') loadMissing(missingPage); }, [activeTab, missingPage, loadMissing]);
  useEffect(() => { if (activeTab === 'mismatch') loadMismatch(); }, [activeTab, loadMismatch]);

  // Totals from campaigns array
  const totals = campaigns.reduce((a, c) => ({
    queued:       a.queued       + Number(c.total_queued    || 0),
    sent:         a.sent         + Number(c.queue_sent      || 0),
    pending:      a.pending      + Number(c.queue_pending   || 0),
    delivered:    a.delivered    + Number(c.total_delivered || 0),
    success:      a.success      + Number(c.delivery_success|| 0),
    failed:       a.failed       + Number(c.delivery_failed || 0),
    bounced:      a.bounced      + Number(c.delivery_bounced|| 0),
    not_tracked:  a.not_tracked  + Number(c.sent_not_tracked|| 0),
  }), { queued:0, sent:0, pending:0, delivered:0, success:0, failed:0, bounced:0, not_tracked:0 });

  // Chart data: queue vs delivery per campaign
  const chartData = campaigns.slice(0, 20).map(c => ({
    campaign_id:      c.campaign_id,
    'Queued':         Number(c.total_queued    || 0),
    'Delivery Match': Number(c.total_delivered || 0),
    'Success':        Number(c.delivery_success|| 0),
    'Not Tracked':    Number(c.sent_not_tracked|| 0),
  }));

  const exportMissing = () => {
    const headers = ['Queue ID','Campaign','From','To Email','Subject','Queue Status','Sent At','Date','Message ID'];
    const rows = missing.map(m => [
      m.id, m.campaign_id, m.fromMail, m.contact_email,
      (m.subject||'').replace(/,/g,';'), m.queue_status,
      m.sent_at, m.create_date, m.message_id
    ]);
    const csv  = [headers, ...rows].map(r => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = `missing-deliveries-${selectedDate || 'export'}.csv`; a.click();
  };

  const filteredMissing = searchMissing
    ? missing.filter(m =>
        (m.contact_email || '').includes(searchMissing) ||
        (m.campaign_id   || '').includes(searchMissing) ||
        (m.subject       || '').toLowerCase().includes(searchMissing.toLowerCase())
      )
    : missing;

  if (loading) return <div className="loading-state"><RefreshCw size={20} className="spin" /></div>;

  return (
    <div>
      {/* Header */}
      <div className="flex-between mb-16">
        <div>
          <div className="section-title">Queue vs Delivery Comparison</div>
          <div className="section-sub">
            Matching <code style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>email_campaign_queue.message_id</code>
            {' '}↔{' '}
            <code style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>email_delivery_details.message_id</code>
            {' · '}Campaign metrics DB
            {waveServer === 'app' && ' · Delivery waveform uses App Mail (Topbar)'}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <select
            className="input"
            style={{ width: 180 }}
            value={selectedCampaign}
            onChange={e => setSelectedCampaign(e.target.value)}
          >
            <option value="">All Campaigns</option>
            {campaigns.map(c => (
              <option key={c.campaign_id} value={c.campaign_id}>{c.campaign_id}</option>
            ))}
          </select>
          <button className="btn btn-ghost btn-sm" onClick={load}><RefreshCw size={13} /> Refresh</button>
        </div>
      </div>

      {/* KPI row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, marginBottom: 20 }}>
        <Stat label="Total Queued"      value={totals.queued}      color="#2563eb"    sub={`${totals.pending.toLocaleString()} pending`} />
        <Stat label="Queue Sent"        value={totals.sent}        color="#0891b2"    sub="Marked sent in queue" />
        <Stat label="Delivery Matched"  value={totals.delivered}   color={S.success}  sub={`${totals.success.toLocaleString()} confirmed success`} />
        <Stat
          label="Sent Not Tracked"
          value={totals.not_tracked}
          color={totals.not_tracked > 0 ? S.missing : S.success}
          sub="In queue-sent, missing delivery record"
        />
      </div>

      {totals.queued === 0 && (
        <div style={{
          background: 'rgba(37,99,235,0.08)', border: '1px solid rgba(37,99,235,0.25)',
          borderRadius: 8, padding: '12px 16px', marginBottom: 16, fontSize: 13, color: 'var(--text-muted)',
        }}>
          No campaign queue rows for this date on the Campaign metrics DB.
          Delivery waveform below still reflects {waveServer === 'campaign' ? 'Campaign' : 'App'} mail traffic from Topbar.
        </div>
      )}

      {/* Alert if missing records found */}
      {totals.not_tracked > 0 && (
        <div style={{
          background: 'rgba(124,58,237,0.1)', border: '1px solid rgba(124,58,237,0.3)',
          borderRadius: 8, padding: '12px 16px', marginBottom: 16,
          display: 'flex', alignItems: 'center', gap: 12
        }}>
          <AlertTriangle size={18} color="#a78bfa" />
          <div>
            <div style={{ fontWeight: 600, color: '#a78bfa', fontSize: 13 }}>
              {totals.not_tracked.toLocaleString()} sent mails have no delivery record
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
              These were marked sent in the queue but have no matching entry in email_delivery_details.
              Could indicate Postfix log parsing gaps or delivery system issues.
            </div>
          </div>
          <button className="btn btn-ghost btn-sm" style={{ marginLeft: 'auto', flexShrink: 0 }}
            onClick={() => setActiveTab('missing')}>
            View Missing →
          </button>
        </div>
      )}

      {/* Tabs */}
      <div className="tab-bar">
        {[
          { id: 'overview',  label: 'Overview' },
          { id: 'campaigns', label: `Campaigns (${campaigns.length})` },
          { id: 'datewise',  label: 'Date Breakdown' },
          { id: 'missing',   label: `Missing Deliveries (${totals.not_tracked.toLocaleString()})` },
          { id: 'mismatch',  label: 'Status Mismatch' },
        ].map(t => (
          <button key={t.id} className={`tab-item ${activeTab === t.id ? 'active' : ''}`}
            onClick={() => setActiveTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ===== OVERVIEW TAB ===== */}
      {activeTab === 'overview' && (
        <>
          <div className="card mb-20" style={{ marginTop: 16 }}>
            <div className="card-header">
              <span className="card-title">
                Delivery waveform ({waveServer === 'campaign' ? 'Campaign' : 'App'} · hourly)
              </span>
            </div>
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart data={hourly} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="gwDel" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={S.success} stopOpacity={0.35} />
                    <stop offset="95%" stopColor={S.success} stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gwFail" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={S.failed} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={S.failed} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="hour" tick={{ fill: '#6e7681', fontSize: 10 }} interval={2} />
                <YAxis tick={{ fill: '#6e7681', fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={TT} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Area type="monotone" dataKey="delivered" stroke={S.success} fill="url(#gwDel)" strokeWidth={2} name="Delivered" />
                <Area type="monotone" dataKey="failed" stroke={S.failed} fill="url(#gwFail)" strokeWidth={2} name="Failed" />
                <Area type="monotone" dataKey="bounced" stroke={S.bounced} fill="transparent" strokeWidth={2} name="Bounced" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="card mb-20">
            <div className="card-header">
              <span className="card-title">Queue vs delivery match by campaign</span>
            </div>
            {chartData.length === 0 ? (
              <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                No campaign queue data for this range.
              </div>
            ) : (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={chartData} margin={{ top: 4, right: 8, left: -20, bottom: 50 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="campaign_id" tick={{ fill: '#6e7681', fontSize: 10 }} angle={-35} textAnchor="end" />
                <YAxis tick={{ fill: '#6e7681', fontSize: 11 }} />
                <Tooltip contentStyle={TT} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Bar dataKey="Queued"         fill="#2563eb"    stackId={undefined} />
                <Bar dataKey="Delivery Match" fill={S.success}  stackId={undefined} />
                <Bar dataKey="Not Tracked"    fill={S.missing}  stackId={undefined} />
              </BarChart>
            </ResponsiveContainer>
            )}
          </div>

          {/* Summary stats by status */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div className="card">
              <div className="card-header"><span className="card-title">Queue table breakdown</span></div>
              {[
                { label: 'Total queued',  value: totals.queued,   color: '#2563eb' },
                { label: 'Sent',          value: totals.sent,     color: S.success },
                { label: 'Pending',       value: totals.pending,  color: S.deferred },
              ].map(r => (
                <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                  <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>{r.label}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: r.color }}>{r.value.toLocaleString()}</span>
                </div>
              ))}
            </div>
            <div className="card">
              <div className="card-header"><span className="card-title">Delivery table breakdown</span></div>
              {[
                { label: 'Matched records', value: totals.delivered,   color: '#2563eb' },
                { label: 'Confirmed sent',  value: totals.success,     color: S.success },
                { label: 'Failed',          value: totals.failed,      color: S.failed  },
                { label: 'Bounced',         value: totals.bounced,     color: S.bounced },
                { label: 'Not tracked',     value: totals.not_tracked, color: S.missing },
              ].map(r => (
                <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                  <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>{r.label}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: r.color }}>{r.value.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {/* ===== CAMPAIGNS TAB ===== */}
      {activeTab === 'campaigns' && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Campaign ID</th>
                  <th>Queued</th>
                  <th>Q. Sent</th>
                  <th>Q. Pending</th>
                  <th>Matched</th>
                  <th style={{ color: S.success }}>Success</th>
                  <th style={{ color: S.failed  }}>Failed</th>
                  <th style={{ color: S.bounced }}>Bounced</th>
                  <th style={{ color: S.missing }}>Not Tracked</th>
                  <th>Track Rate</th>
                  <th>Overall %</th>
                  <th>First</th>
                  <th>Last</th>
                </tr>
              </thead>
              <tbody>
                {campaigns.map(c => (
                  <tr key={c.campaign_id}
                    style={{ cursor: 'pointer', background: selectedCampaign === c.campaign_id ? 'rgba(37,99,235,0.05)' : undefined }}
                    onClick={() => setSelectedCampaign(prev => prev === c.campaign_id ? '' : c.campaign_id)}
                  >
                    <td><span className="mono" style={{ fontSize: 12, color: 'var(--accent-blue-light)' }}>{c.campaign_id}</span></td>
                    <td className="mono" style={{ fontSize: 12 }}>{Number(c.total_queued || 0).toLocaleString()}</td>
                    <td style={{ color: '#0891b2', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(c.queue_sent || 0).toLocaleString()}</td>
                    <td style={{ color: S.deferred, fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(c.queue_pending || 0).toLocaleString()}</td>
                    <td className="mono" style={{ fontSize: 12 }}>{Number(c.total_delivered || 0).toLocaleString()}</td>
                    <td style={{ color: S.success, fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(c.delivery_success || 0).toLocaleString()}</td>
                    <td style={{ color: S.failed,  fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(c.delivery_failed  || 0).toLocaleString()}</td>
                    <td style={{ color: S.bounced, fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(c.delivery_bounced || 0).toLocaleString()}</td>
                    <td style={{ color: S.missing, fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(c.sent_not_tracked || 0).toLocaleString()}</td>
                    <td>
                      <span style={{
                        color: Number(c.tracking_rate) >= 95 ? S.success : Number(c.tracking_rate) >= 80 ? S.deferred : S.failed,
                        fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600
                      }}>{Number(c.tracking_rate || 0).toFixed(1)}%</span>
                    </td>
                    <td>
                      <span style={{
                        color: Number(c.overall_success_rate) >= 90 ? S.success : Number(c.overall_success_rate) >= 70 ? S.deferred : S.failed,
                        fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600
                      }}>{Number(c.overall_success_rate || 0).toFixed(1)}%</span>
                    </td>
                    <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{c.first_date}</td>
                    <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{c.last_date}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ===== DATE BREAKDOWN TAB ===== */}
      {activeTab === 'datewise' && (
        <>
          <div className="card mb-16" style={{ marginTop: 16 }}>
            <div className="card-header"><span className="card-title">Queue vs delivery by date {selectedCampaign ? `— Campaign ${selectedCampaign}` : ''}</span></div>
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={summary} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="create_date" tick={{ fill: '#6e7681', fontSize: 11 }} tickFormatter={v => v?.slice(5)} />
                <YAxis tick={{ fill: '#6e7681', fontSize: 11 }} />
                <Tooltip contentStyle={TT} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Bar dataKey="queued"          name="Queued"       fill="#2563eb" />
                <Bar dataKey="delivery_success" name="Delivered"   fill={S.success} />
                <Bar dataKey="delivery_bounced" name="Bounced"     fill={S.bounced} />
                <Bar dataKey="sent_but_missing" name="Not Tracked" fill={S.missing} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Date</th><th>Campaign</th><th>Queued</th>
                    <th>Q.Sent</th><th>Q.Pending</th><th>Matched</th>
                    <th style={{ color: S.success }}>Success</th>
                    <th style={{ color: S.failed  }}>Failed</th>
                    <th style={{ color: S.bounced }}>Bounced</th>
                    <th style={{ color: S.deferred }}>Deferred</th>
                    <th style={{ color: S.missing }}>Not Tracked</th>
                    <th>Avg Dur</th>
                  </tr>
                </thead>
                <tbody>
                  {summary.map((r, i) => (
                    <tr key={i}>
                      <td className="mono" style={{ fontSize: 12 }}>{r.create_date}</td>
                      <td><span className="mono" style={{ fontSize: 11 }}>{r.campaign_id}</span></td>
                      <td className="mono" style={{ fontSize: 12 }}>{Number(r.queued || 0).toLocaleString()}</td>
                      <td style={{ color: '#0891b2', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(r.queue_sent || 0).toLocaleString()}</td>
                      <td style={{ color: S.deferred, fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(r.queue_pending || 0).toLocaleString()}</td>
                      <td className="mono" style={{ fontSize: 12 }}>{Number(r.delivered_records || 0).toLocaleString()}</td>
                      <td style={{ color: S.success, fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(r.delivery_success || 0).toLocaleString()}</td>
                      <td style={{ color: S.failed,  fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(r.delivery_failed  || 0).toLocaleString()}</td>
                      <td style={{ color: S.bounced, fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(r.delivery_bounced || 0).toLocaleString()}</td>
                      <td style={{ color: S.deferred,fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(r.delivery_deferred|| 0).toLocaleString()}</td>
                      <td style={{ color: S.missing, fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(r.sent_but_missing || 0).toLocaleString()}</td>
                      <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{r.avg_duration ? `${r.avg_duration}s` : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* ===== MISSING DELIVERIES TAB ===== */}
      {activeTab === 'missing' && (
        <div style={{ marginTop: 16 }}>
          <div className="flex-between mb-16">
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
              {missingTotal.toLocaleString()} sent mails with no delivery record
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <div style={{ position: 'relative' }}>
                <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input className="input" style={{ paddingLeft: 30, width: 220 }}
                  placeholder="Search email, campaign, subject..."
                  value={searchMissing}
                  onChange={e => setSearchMissing(e.target.value)} />
              </div>
              <button className="btn btn-ghost btn-sm" onClick={exportMissing}>
                <Download size={13} /> Export CSV
              </button>
            </div>
          </div>
          <div className="card">
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Queue ID</th><th>Campaign</th><th>From</th><th>To Email</th>
                    <th>Subject</th><th>Template</th><th>Queue Status</th><th>Sent At</th><th>Date</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredMissing.map(m => (
                    <tr key={m.id}>
                      <td className="mono" style={{ fontSize: 11 }}>{m.id}</td>
                      <td><span className="mono" style={{ fontSize: 11 }}>{m.campaign_id}</span></td>
                      <td style={{ fontSize: 12, maxWidth: 140 }}><div className="truncate">{m.fromMail}</div></td>
                      <td style={{ fontSize: 12, maxWidth: 160 }}><div className="truncate" title={m.contact_email}>{m.contact_email}</div></td>
                      <td style={{ fontSize: 12, maxWidth: 200 }}><div className="truncate" title={m.subject}>{m.subject}</div></td>
                      <td><span className="badge badge-processing">{m.template_type}</span></td>
                      <td><span className="badge badge-sent">{m.queue_status}</span></td>
                      <td className="mono" style={{ fontSize: 11 }}>{m.sent_at ? new Date(m.sent_at).toLocaleString('en-IN') : '—'}</td>
                      <td className="mono" style={{ fontSize: 11 }}>{m.create_date}</td>
                    </tr>
                  ))}
                  {filteredMissing.length === 0 && (
                    <tr><td colSpan={9} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
                      {missingTotal === 0 ? '✅ All sent mails have delivery records' : 'No results match search'}
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
            {missingTotal > 100 && (
              <div className="flex-between" style={{ marginTop: 12, padding: '0 4px' }}>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Page {missingPage} · {missingTotal.toLocaleString()} total</span>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button className="btn btn-ghost btn-sm" disabled={missingPage <= 1} onClick={() => setMissingPage(p => p-1)}>← Prev</button>
                  <button className="btn btn-ghost btn-sm" disabled={missingPage * 100 >= missingTotal} onClick={() => setMissingPage(p => p+1)}>Next →</button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ===== MISMATCH TAB ===== */}
      {activeTab === 'mismatch' && (
        <div style={{ marginTop: 16 }}>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16 }}>
            {mismatch.length.toLocaleString()} records where queue=sent but delivery shows failure
          </div>
          <div className="card">
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Campaign</th><th>To Email</th><th>Subject</th>
                    <th>Queue Status</th><th>Delivery Status</th><th>Final</th>
                    <th>DSN</th><th>Reason</th><th>Duration</th><th>Date</th>
                  </tr>
                </thead>
                <tbody>
                  {mismatch.map((m, i) => (
                    <tr key={i}>
                      <td><span className="mono" style={{ fontSize: 11 }}>{m.campaign_id}</span></td>
                      <td style={{ fontSize: 12 }}><div className="truncate" style={{ maxWidth: 160 }} title={m.contact_email}>{m.contact_email}</div></td>
                      <td style={{ fontSize: 12 }}><div className="truncate" style={{ maxWidth: 160 }} title={m.subject}>{m.subject}</div></td>
                      <td><span className="badge badge-sent">{m.queue_status}</span></td>
                      <td><span className="badge badge-failed">{m.delivery_status}</span></td>
                      <td><span className="badge badge-failed">{m.final_status}</span></td>
                      <td><span className="mono" style={{ fontSize: 11, color: '#f87171' }}>{m.dsn || '—'}</span></td>
                      <td style={{ fontSize: 11, color: '#fbbf24', maxWidth: 200 }}><div className="truncate" title={m.reason}>{m.reason || '—'}</div></td>
                      <td className="mono" style={{ fontSize: 11 }}>{m.duration ? `${m.duration}s` : '—'}</td>
                      <td className="mono" style={{ fontSize: 11 }}>{m.log_date}</td>
                    </tr>
                  ))}
                  {mismatch.length === 0 && (
                    <tr><td colSpan={10} style={{ textAlign: 'center', padding: 40, color: '#4ade80' }}>
                      ✅ No status mismatches found
                    </td></tr>
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
