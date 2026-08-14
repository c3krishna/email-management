import { useState, useEffect, useCallback } from 'react';
import {
  BarChart, Bar, LineChart, Line, AreaChart, Area,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, Cell
} from 'recharts';
import { RefreshCw, ChevronDown, ChevronUp, Maximize2, Minimize2 } from 'lucide-react';
import { statsApi } from '../utils/api';

// Status colors consistent across all charts
const S = {
  success:  '#16a34a',
  failed:   '#dc2626',
  bounced:  '#ea580c',
  deferred: '#d97706',
  timedout: '#7c3aed',
  invalid:  '#b91c1c',
};

// Expandable chart card wrapper
function ChartCard({ title, subtitle, children, defaultExpanded = true }) {
  const [expanded, setExpanded]     = useState(defaultExpanded);
  const [fullscreen, setFullscreen] = useState(false);

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid ${fullscreen ? 'var(--accent-blue)' : 'var(--border)'}`,
      borderRadius: 12,
      marginBottom: 16,
      overflow: 'hidden',
      ...(fullscreen ? {
        position: 'fixed', inset: '16px', zIndex: 999,
        display: 'flex', flexDirection: 'column'
      } : {})
    }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '14px 20px',
        borderBottom: expanded ? '1px solid var(--border)' : 'none',
        cursor: 'pointer', userSelect: 'none',
        background: 'var(--bg-secondary)'
      }}
        onClick={() => !fullscreen && setExpanded(e => !e)}
      >
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{title}</div>
          {subtitle && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{subtitle}</div>}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={e => { e.stopPropagation(); setFullscreen(f => !f); setExpanded(true); }}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}
          >
            {fullscreen ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
          </button>
          {!fullscreen && (
            <button
              onClick={e => { e.stopPropagation(); setExpanded(e => !e); }}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}
            >
              {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </button>
          )}
        </div>
      </div>

      {/* Content */}
      {(expanded || fullscreen) && (
        <div style={{
          padding: '16px 20px',
          ...(fullscreen ? { flex: 1, overflow: 'auto' } : {})
        }}>
          {children}
        </div>
      )}

      {/* Fullscreen backdrop */}
      {fullscreen && (
        <div
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 998 }}
          onClick={() => setFullscreen(false)}
        />
      )}
    </div>
  );
}

const TOOLTIP_STYLE = {
  background: '#1c2230', border: '1px solid #2d3748', borderRadius: 8, fontSize: 12
};

const TABS = ['date', 'campaign', 'failure', 'sender', 'dsn'];
const TAB_LABELS = {
  date:     'Date Trend',
  campaign: 'By Campaign',
  failure:  'Failure Reasons',
  sender:   'By Sender',
  dsn:      'DSN Codes',
};

export default function CampaignPage({ server, range }) {
  const [tab, setTab]         = useState('date');
  const [loading, setLoading] = useState(true);

  // Data states
  const [trend,    setTrend]    = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [reasons,  setReasons]  = useState([]);
  const [senders,  setSenders]  = useState([]);
  const [dsnData,  setDsnData]  = useState([]);

  // Campaign detail drill-down
  const [selectedCampaign, setSelectedCampaign] = useState(null);
  const [campaignDetail,   setCampaignDetail]   = useState([]);
  const [detailLoading,    setDetailLoading]    = useState(false);

  // Date range filter for campaign detail
  const [detailRange, setDetailRange] = useState('7d');

  const r = range === '30d' ? '30d' : '7d';

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [t, c, f, s, d] = await Promise.all([
        statsApi.getTrend({ range: r, server }),
        statsApi.getByCampaign({ range: r, server, limit: 30 }),
        statsApi.getFailureReasons({ range: r, server }),
        statsApi.getBySender({ range: r, server }),
        statsApi.getDsnBreakdown({ range: r, server }),
      ]);
      setTrend((t.data || []).map(r => ({
        ...r,
        success:     Number(r.success     || 0),
        failed:      Number(r.failed      || 0),
        bounced:     Number(r.bounced     || 0),
        deferred:    Number(r.deferred    || 0),
        spam_blocked:Number(r.spam_blocked|| 0),
        total:       Number(r.total       || 0),
      })));
      setCampaigns(c.data);
      setReasons(f.data);
      setSenders(s.data);
      setDsnData(d.data);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [server, range]);

  useEffect(() => { load(); }, [load]);

  // Load per-campaign date breakdown when campaign selected
  const loadCampaignDetail = useCallback(async (campaignId) => {
    if (!campaignId) return;
    setDetailLoading(true);
    try {
      const r2 = await statsApi.getTrend({ range: detailRange, server, campaign_id: campaignId });
      setCampaignDetail(r2.data || []);
    } catch (e) { console.error(e); }
    finally { setDetailLoading(false); }
  }, [server, detailRange]);

  useEffect(() => {
    if (selectedCampaign) loadCampaignDetail(selectedCampaign);
  }, [selectedCampaign, detailRange, loadCampaignDetail]);

  const serverLabel = server === 'campaign' ? '🟠 Campaign' : '🔵 App Mail';

  // Totals from campaigns array
  const totals = campaigns.reduce((acc, c) => ({
    total:    acc.total    + Number(c.total    || 0),
    success:  acc.success  + Number(c.success  || 0),
    failed:   acc.failed   + Number(c.failed   || 0),
    bounced:  acc.bounced  + Number(c.bounced  || 0),
    deferred: acc.deferred + Number(c.deferred || 0),
  }), { total: 0, success: 0, failed: 0, bounced: 0, deferred: 0 });

  if (loading) return (
    <div className="loading-state">
      <RefreshCw size={20} className="spin" />
      <div style={{ marginTop: 12 }}>Loading campaign analytics...</div>
    </div>
  );

  return (
    <div>
      {/* Header */}
      <div className="flex-between mb-16">
        <div>
          <div className="section-title">Campaign Analytics</div>
          <div className="section-sub">
            {serverLabel} · {r === '30d' ? '30' : '7'} day view
            · {campaigns.length} campaigns · {totals.total.toLocaleString()} total mails
          </div>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {/* KPI summary row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Total',    value: totals.total,    color: '#2563eb' },
          { label: 'Success',  value: totals.success,  color: S.success  },
          { label: 'Failed',   value: totals.failed,   color: S.failed   },
          { label: 'Bounced',  value: totals.bounced,  color: S.bounced  },
          { label: 'Deferred', value: totals.deferred, color: S.deferred },
        ].map(k => (
          <div key={k.label} style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, padding: '12px 16px'
          }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: 0.5 }}>{k.label}</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: k.color, fontFamily: 'var(--font-mono)' }}>
              {k.value.toLocaleString()}
            </div>
          </div>
        ))}
      </div>

      {/* Tab bar */}
      <div className="tab-bar">
        {TABS.map(t => (
          <button key={t} className={`tab-item ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {TAB_LABELS[t]}
          </button>
        ))}
      </div>

      {/* ===== DATE TREND TAB ===== */}
      {tab === 'date' && (
        <>
          <ChartCard
            title="Daily delivery trend"
            subtitle="Success, Failed, Bounced, Deferred over time"
          >
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={trend} margin={{ top: 4, right: 8, left: -20, bottom: 0 }} syncId='campaign'>
                <defs>
                  {Object.entries(S).map(([k, v]) => (
                    <linearGradient key={k} id={`ag-${k}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor={v} stopOpacity={0.35} />
                      <stop offset="95%" stopColor={v} stopOpacity={0}    />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="log_date" tick={{ fill: '#6e7681', fontSize: 11 }} tickFormatter={v => { if (!v) return ''; const d = v.includes('T') ? new Date(v) : new Date(v + 'T00:00:00'); return (d.getMonth()+1).toString().padStart(2,'0') + '-' + d.getDate().toString().padStart(2,'0'); }} />
                <YAxis tick={{ fill: '#6e7681', fontSize: 11 }} domain={[0, 'auto']} allowDataKey={true} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Area type="monotone" dataKey="success"  stroke={S.success}  fill={`url(#ag-success)`}  name="Success"  />
                <Area type="monotone" dataKey="failed"   stroke={S.failed}   fill={`url(#ag-failed)`}   name="Failed"   />
                <Area type="monotone" dataKey="bounced"  stroke={S.bounced}  fill={`url(#ag-bounced)`}  name="Bounced"  />
                <Area type="monotone" dataKey="deferred" stroke={S.deferred} fill={`url(#ag-deferred)`} name="Deferred" />
                <Area type="monotone" dataKey="spam_blocked" stroke={S.timedout} fill={`url(#ag-timedout)`} name="Spam"  />
              </AreaChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard
            title="Daily stacked volume"
            subtitle="Total mail volume breakdown per day"
            defaultExpanded={false}
          >
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={trend} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="log_date" tick={{ fill: '#6e7681', fontSize: 11 }} tickFormatter={v => { if (!v) return ''; const d = v.includes('T') ? new Date(v) : new Date(v + 'T00:00:00'); return (d.getMonth()+1).toString().padStart(2,'0') + '-' + d.getDate().toString().padStart(2,'0'); }} />
                <YAxis tick={{ fill: '#6e7681', fontSize: 11 }} domain={[0, 'auto']} allowDataKey={true} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Bar dataKey="success"  fill={S.success}  name="Success"  stackId="a" />
                <Bar dataKey="failed"   fill={S.failed}   name="Failed"   stackId="a" />
                <Bar dataKey="bounced"  fill={S.bounced}  name="Bounced"  stackId="a" />
                <Bar dataKey="deferred" fill={S.deferred} name="Deferred" stackId="a" radius={[2,2,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>
        </>
      )}

      {/* ===== CAMPAIGN TAB ===== */}
      {tab === 'campaign' && (
        <>
          <ChartCard title="Campaign performance" subtitle="Top 15 by volume — click a bar to drill down">
            <ResponsiveContainer width="100%" height={300}>
              <BarChart
                data={campaigns.slice(0, 15)}
                margin={{ top: 4, right: 8, left: -20, bottom: 50 }}
                onClick={d => d?.activePayload && setSelectedCampaign(d.activePayload[0]?.payload?.campaign_id)}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="campaign_id" tick={{ fill: '#6e7681', fontSize: 10 }} angle={-35} textAnchor="end" />
                <YAxis tick={{ fill: '#6e7681', fontSize: 11 }} domain={[0, 'auto']} allowDataKey={true} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Bar dataKey="success"  fill={S.success}  name="Success"  stackId="a" />
                <Bar dataKey="failed"   fill={S.failed}   name="Failed"   stackId="a" />
                <Bar dataKey="bounced"  fill={S.bounced}  name="Bounced"  stackId="a" />
                <Bar dataKey="deferred" fill={S.deferred} name="Deferred" stackId="a" radius={[2,2,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>

          {/* Success rate comparison */}
          <ChartCard
            title="Success rate by campaign"
            subtitle="Green = good (≥90%), Yellow = warning (70–90%), Red = poor (<70%)"
            defaultExpanded={true}
          >
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={campaigns.slice(0,20)} margin={{ top: 4, right: 8, left: -20, bottom: 50 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="campaign_id" tick={{ fill: '#6e7681', fontSize: 10 }} angle={-35} textAnchor="end" />
                <YAxis tick={{ fill: '#6e7681', fontSize: 11 }} domain={[0, 100]} tickFormatter={v => `${v}%`} />
                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  formatter={(v) => [`${Number(v).toFixed(1)}%`, 'Success Rate']}
                />
                <Bar dataKey="success_rate" name="Success Rate" radius={[4,4,0,0]}>
                  {campaigns.slice(0,20).map((c, i) => (
                    <Cell
                      key={i}
                      fill={
                        Number(c.success_rate) >= 90 ? S.success :
                        Number(c.success_rate) >= 70 ? S.deferred :
                        S.failed
                      }
                      cursor="pointer"
                      onClick={() => setSelectedCampaign(c.campaign_id)}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>

          {/* Campaign drill-down */}
          {selectedCampaign && (
            <ChartCard
              title={`Campaign ${selectedCampaign} — daily breakdown`}
              subtitle="Date-wise delivery detail for selected campaign"
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Range:</span>
                {['7d','30d'].map(rv => (
                  <button key={rv}
                    className={`btn btn-sm ${detailRange === rv ? 'btn-primary' : 'btn-ghost'}`}
                    onClick={() => setDetailRange(rv)}>
                    {rv === '7d' ? '7 Days' : '30 Days'}
                  </button>
                ))}
                <button className="btn btn-ghost btn-sm" onClick={() => setSelectedCampaign(null)}>
                  × Clear
                </button>
              </div>

              {detailLoading ? (
                <div className="loading-state"><RefreshCw size={16} className="spin" /></div>
              ) : campaignDetail.length > 0 ? (
                <ResponsiveContainer width="100%" height={240}>
                  <LineChart data={campaignDetail} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis dataKey="log_date" tick={{ fill: '#6e7681', fontSize: 11 }} tickFormatter={v => { if (!v) return ''; const d = v.includes('T') ? new Date(v) : new Date(v + 'T00:00:00'); return (d.getMonth()+1).toString().padStart(2,'0') + '-' + d.getDate().toString().padStart(2,'0'); }} />
                    <YAxis tick={{ fill: '#6e7681', fontSize: 11 }} domain={[0, 'auto']} allowDataKey={true} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    <Line type="monotone" dataKey="success"  stroke={S.success}  dot={false} name="Success"  strokeWidth={2} />
                    <Line type="monotone" dataKey="failed"   stroke={S.failed}   dot={false} name="Failed"   strokeWidth={1.5} />
                    <Line type="monotone" dataKey="bounced"  stroke={S.bounced}  dot={false} name="Bounced"  strokeWidth={1.5} />
                    <Line type="monotone" dataKey="deferred" stroke={S.deferred} dot={false} name="Deferred" strokeWidth={1.5} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)', fontSize: 13 }}>
                  No date-level data for campaign {selectedCampaign} in this range.
                  <br />
                  <span style={{ fontSize: 11 }}>Note: campaign_id filter in trend API must be supported in backend stats route.</span>
                </div>
              )}

              {/* Campaign detail table */}
              <div className="table-wrapper" style={{ marginTop: 16 }}>
                <table>
                  <thead>
                    <tr>
                      <th>Date</th>
                      <th style={{ color: S.success }}>Success</th>
                      <th style={{ color: S.failed }}>Failed</th>
                      <th style={{ color: S.bounced }}>Bounced</th>
                      <th style={{ color: S.deferred }}>Deferred</th>
                      <th style={{ color: S.timedout }}>Spam</th>
                      <th>Total</th>
                    </tr>
                  </thead>
                  <tbody>
                    {campaignDetail.map((r, i) => (
                      <tr key={i}>
                        <td className="mono" style={{ fontSize: 12 }}>{r.log_date}</td>
                        <td style={{ color: S.success,  fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(r.success  || 0).toLocaleString()}</td>
                        <td style={{ color: S.failed,   fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(r.failed   || 0).toLocaleString()}</td>
                        <td style={{ color: S.bounced,  fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(r.bounced  || 0).toLocaleString()}</td>
                        <td style={{ color: S.deferred, fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(r.deferred || 0).toLocaleString()}</td>
                        <td style={{ color: S.timedout, fontFamily: 'var(--font-mono)', fontSize: 12 }}>{Number(r.spam_blocked || 0).toLocaleString()}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600 }}>
                          {(Number(r.success||0)+Number(r.failed||0)+Number(r.bounced||0)+Number(r.deferred||0)).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </ChartCard>
          )}

          {/* Full campaign table */}
          <ChartCard title="All campaigns" subtitle="Click campaign ID to drill down" defaultExpanded={true}>
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Campaign ID</th>
                    <th>Total</th>
                    <th style={{ color: S.success  }}>Success</th>
                    <th style={{ color: S.failed   }}>Failed</th>
                    <th style={{ color: S.bounced  }}>Bounced</th>
                    <th style={{ color: S.deferred }}>Deferred</th>
                    <th>Rate</th>
                    <th>First</th>
                    <th>Last</th>
                  </tr>
                </thead>
                <tbody>
                  {campaigns.map(c => (
                    <tr key={c.campaign_id}
                      style={{ cursor: 'pointer' }}
                      onClick={() => { setSelectedCampaign(c.campaign_id); window.scrollTo({ top: 0, behavior: 'smooth' }); }}
                    >
                      <td>
                        <span className="mono" style={{ fontSize: 12, color: 'var(--accent-blue-light)' }}>
                          {c.campaign_id}
                        </span>
                      </td>
                      <td>{Number(c.total).toLocaleString()}</td>
                      <td style={{ color: S.success  }}>{Number(c.success).toLocaleString()}</td>
                      <td style={{ color: S.failed   }}>{Number(c.failed).toLocaleString()}</td>
                      <td style={{ color: S.bounced  }}>{Number(c.bounced).toLocaleString()}</td>
                      <td style={{ color: S.deferred }}>{Number(c.deferred).toLocaleString()}</td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{
                            color: Number(c.success_rate) >= 90 ? S.success : Number(c.success_rate) >= 70 ? S.deferred : S.failed,
                            fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600
                          }}>
                            {Number(c.success_rate).toFixed(1)}%
                          </span>
                          <div style={{ flex: 1, background: 'var(--border)', borderRadius: 4, height: 4, minWidth: 60 }}>
                            <div style={{
                              width: `${Math.min(Number(c.success_rate), 100)}%`, height: '100%',
                              background: Number(c.success_rate) >= 90 ? S.success : Number(c.success_rate) >= 70 ? S.deferred : S.failed,
                              borderRadius: 4
                            }} />
                          </div>
                        </div>
                      </td>
                      <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{c.first_seen}</td>
                      <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{c.last_seen}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </ChartCard>
        </>
      )}

      {/* ===== FAILURE REASONS TAB ===== */}
      {tab === 'failure' && (
        <>
          <ChartCard title="Top failure reasons" subtitle="By count — hover for details">
            <ResponsiveContainer width="100%" height={280}>
              <BarChart
                data={reasons.slice(0, 15)}
                layout="vertical"
                margin={{ top: 4, right: 20, left: 8, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#6e7681', fontSize: 11 }} />
                <YAxis type="category" dataKey="reason" tick={{ fill: '#6e7681', fontSize: 10 }} width={200}
                  tickFormatter={v => v?.slice(0, 32)} />
                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  formatter={(v, n, p) => [v, `${p.payload.status || ''} ${p.payload.dsn || ''}`]}
                />
                <Bar dataKey="count" name="Count" radius={[0,4,4,0]}>
                  {reasons.slice(0,15).map((r, i) => (
                    <Cell key={i} fill={
                      r.status === 'failed'   ? S.failed   :
                      r.status === 'bounced'  ? S.bounced  :
                      r.status === 'deferred' ? S.deferred :
                      r.status === 'timeout'  ? S.timedout :
                      S.invalid
                    } />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard title="Failure details table" defaultExpanded={true}>
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr><th>#</th><th>Reason</th><th>Status</th><th>DSN</th><th>Count</th><th>Senders</th><th>Campaigns</th></tr>
                </thead>
                <tbody>
                  {reasons.map((r, i) => (
                    <tr key={i}>
                      <td style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{i+1}</td>
                      <td style={{ maxWidth: 400, fontSize: 12, color: '#fbbf24' }}>{r.reason}</td>
                      <td><span className="badge badge-failed">{r.status || r.delivery_status}</span></td>
                      <td><span className="mono" style={{ fontSize: 11 }}>{r.dsn || '—'}</span></td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{Number(r.count).toLocaleString()}</td>
                      <td>{r.affected_senders}</td>
                      <td>{r.affected_campaigns}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </ChartCard>
        </>
      )}

      {/* ===== SENDER TAB ===== */}
      {tab === 'sender' && (
        <ChartCard title="Top senders" subtitle="Failure rate highlights senders needing attention">
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>From Address</th><th>Total</th>
                  <th style={{ color: S.success }}>Success</th>
                  <th style={{ color: S.failed  }}>Failed</th>
                  <th style={{ color: S.bounced }}>Bounced</th>
                  <th>Failure Rate</th>
                </tr>
              </thead>
              <tbody>
                {senders.map((s, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ fontSize: 12 }}>{s.mail_from}</td>
                    <td>{Number(s.total).toLocaleString()}</td>
                    <td style={{ color: S.success }}>{Number(s.success).toLocaleString()}</td>
                    <td style={{ color: S.failed  }}>{Number(s.failed).toLocaleString()}</td>
                    <td style={{ color: S.bounced }}>{Number(s.bounced).toLocaleString()}</td>
                    <td>
                      <span style={{
                        color: Number(s.failure_rate) >= 20 ? S.failed : Number(s.failure_rate) >= 10 ? S.deferred : S.success,
                        fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600
                      }}>
                        {Number(s.failure_rate).toFixed(1)}%
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </ChartCard>
      )}

      {/* ===== DSN TAB ===== */}
      {tab === 'dsn' && (
        <>
          <ChartCard title="DSN code distribution" subtitle="2xx = success, 4xx = temporary, 5xx = permanent failure">
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={dsnData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="dsn" tick={{ fill: '#6e7681', fontSize: 11 }} />
                <YAxis tick={{ fill: '#6e7681', fontSize: 11 }} domain={[0, 'auto']} allowDataKey={true} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="count" name="Count" radius={[4,4,0,0]}>
                  {dsnData.map((d, i) => (
                    <Cell key={i} fill={
                      d.category === 'Success'           ? S.success  :
                      d.category === 'Temporary Failure' ? S.deferred :
                      S.failed
                    } />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard title="DSN details" defaultExpanded={true}>
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr><th>DSN Code</th><th>Category</th><th>Count</th><th>Description</th></tr>
                </thead>
                <tbody>
                  {dsnData.map((d, i) => (
                    <tr key={i}>
                      <td>
                        <span className="mono" style={{
                          fontSize: 13, fontWeight: 600,
                          color: d.category === 'Success' ? S.success : d.category === 'Temporary Failure' ? S.deferred : S.failed
                        }}>{d.dsn}</span>
                      </td>
                      <td>
                        <span className={`badge ${d.category === 'Success' ? 'badge-sent' : d.category === 'Temporary Failure' ? 'badge-deferred' : 'badge-failed'}`}>
                          {d.category}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{Number(d.count).toLocaleString()}</td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{getDsnDescription(d.dsn)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </ChartCard>
        </>
      )}
    </div>
  );
}

function getDsnDescription(dsn) {
  const map = {
    '2.0.0': 'Successful delivery',      '2.1.5': 'Destination address valid',
    '4.0.0': 'General temporary failure', '4.1.1': 'Mailbox full (temp)',
    '4.2.1': 'Mailbox disabled (temp)',   '4.3.1': 'Insufficient storage',
    '4.4.1': 'Connection timeout',        '4.4.2': 'Connection dropped',
    '4.7.1': 'Delivery not authorized',   '4.7.28': 'IP reputation issue',
    '5.0.0': 'Permanent failure',         '5.1.0': 'Address rejected',
    '5.1.1': 'User / mailbox not found',  '5.1.2': 'Bad destination address',
    '5.1.3': 'Invalid address',           '5.2.1': 'Mailbox disabled',
    '5.2.2': 'Mailbox full',              '5.3.4': 'Message too large',
    '5.4.1': 'No answer from host',       '5.7.1': 'Blacklisted / SPF fail',
    '5.7.25': 'Reverse DNS fail',         '5.7.26': 'DKIM signature failure',
    '5.7.28': 'IP reputation blocked'
  };
  return map[dsn] || 'See RFC 3463 / 5321';
}
