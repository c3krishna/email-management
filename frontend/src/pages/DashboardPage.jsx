import { useState, useEffect, useCallback } from 'react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, LineChart, Line
} from 'recharts';
import {
  RefreshCw, Mail, Shield, AlertTriangle, ArrowUpRight,
  ArrowDownRight, TrendingUp, Download, Filter,
  Inbox, Send, Ban, XCircle, CheckCircle, Clock,
  ChevronDown, Activity
} from 'lucide-react';
import { statsApi } from '../utils/api';
import { decodeEmailSubject } from '../utils/decodeSubject';

// ---- Design tokens ----
const C = {
  blue:    '#2563eb',
  green:   '#16a34a',
  red:     '#dc2626',
  orange:  '#ea580c',
  yellow:  '#d97706',
  purple:  '#7c3aed',
  pink:    '#be185d',
  cyan:    '#0891b2',
  teal:    '#0d9488',
};

const TT_STYLE = {
  background: '#0d1117', border: '1px solid #2d3748',
  borderRadius: 8, fontSize: 12, color: '#e6edf3'
};

// ---- KPI Card with vs-yesterday ----
function KpiCard({ label, value, icon: Icon, color, vsYesterday, sub, pulse }) {
  const isUp   = vsYesterday > 0;
  const isDown = vsYesterday < 0;
  const isGood = (label === 'Delivered' || label === 'Inbound' || label === 'Outbound') ? isUp : isDown;

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid var(--border)`,
      borderRadius: 12,
      padding: '18px 20px',
      position: 'relative',
      overflow: 'hidden',
      borderTop: `3px solid ${color}`,
    }}>
      {pulse && (
        <div style={{
          position: 'absolute', top: 12, right: 12,
          width: 8, height: 8, borderRadius: '50%',
          background: color,
          boxShadow: `0 0 0 3px ${color}33`,
          animation: 'pulse 2s infinite'
        }} />
      )}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 10 }}>
        <div style={{
          width: 36, height: 36, borderRadius: 8,
          background: `${color}18`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0
        }}>
          <Icon size={18} color={color} />
        </div>
        {vsYesterday !== undefined && vsYesterday !== 0 && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 3,
            fontSize: 11, fontWeight: 600,
            color: isGood ? '#4ade80' : '#f87171',
          }}>
            {isUp ? <ArrowUpRight size={13} /> : <ArrowDownRight size={13} />}
            {Math.abs(vsYesterday)}% vs yesterday
          </div>
        )}
      </div>
      <div style={{ fontSize: 28, fontWeight: 800, color, fontFamily: 'var(--font-mono)', lineHeight: 1, marginBottom: 4 }}>
        {value !== undefined ? Number(value).toLocaleString() : '—'}
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 500 }}>{label}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 3, opacity: 0.7 }}>{sub}</div>}
    </div>
  );
}

// ---- Mini bar for top senders/recipients ----
function MiniBar({ value, max, color }) {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return (
    <div style={{ flex: 1, height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
      <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2, transition: 'width 0.5s' }} />
    </div>
  );
}

// ---- Direction badge ----
function DirectionBadge({ dir }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 8px', borderRadius: 20, fontSize: 11, fontWeight: 600,
      background: dir === 'Outbound' ? 'rgba(37,99,235,0.15)' : 'rgba(8,145,178,0.15)',
      color: dir === 'Outbound' ? '#60a5fa' : '#67e8f9',
    }}>
      {dir === 'Outbound' ? <Send size={10} /> : <Inbox size={10} />}
      {dir}
    </span>
  );
}

// ---- Result badge ----
function ResultBadge({ action, threat }) {
  const map = {
    'Delivered': { bg: 'rgba(22,163,74,0.15)',   color: '#4ade80', label: '✓ Clean' },
    'Bounced':   { bg: 'rgba(234,88,12,0.15)',   color: '#fb923c', label: '⟳ Bounced' },
    'Failed':    { bg: 'rgba(220,38,38,0.15)',   color: '#f87171', label: '✕ Failed' },
    'Blocked':   { bg: 'rgba(190,24,93,0.15)',   color: '#f472b6', label: '⊘ Blocked' },
    'Deferred':  { bg: 'rgba(217,119,6,0.15)',   color: '#fbbf24', label: '⏸ Deferred' },
    'Processing':{ bg: 'rgba(8,145,178,0.15)',   color: '#67e8f9', label: '… Processing' },
  };
  const threats = {
    'Spam':        { color: '#f97316' },
    'Phishing':    { color: '#f43f5e' },
    'Malware':     { color: '#a855f7' },
    'Blacklisted': { color: '#ef4444' },
    'Clean':       { color: '#22c55e' },
  };
  const s = map[action] || map['Processing'];
  const t = threats[threat];

  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
      <span style={{ padding: '2px 8px', borderRadius: 20, fontSize: 11, fontWeight: 600, background: s.bg, color: s.color }}>
        {s.label}
      </span>
      {threat && threat !== 'Other' && (
        <span style={{ padding: '2px 8px', borderRadius: 20, fontSize: 11, fontWeight: 600, background: `${t?.color}22`, color: t?.color || '#9ca3af' }}>
          {threat}
        </span>
      )}
    </div>
  );
}

// ---- Custom tooltip for charts ----
const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: '#0d1117', border: '1px solid #2d3748', borderRadius: 8, padding: '10px 14px', fontSize: 12 }}>
      <div style={{ color: '#8b949e', marginBottom: 6, fontWeight: 600 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color, display: 'flex', gap: 8, alignItems: 'center', marginBottom: 2 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: p.color, flexShrink: 0 }} />
          <span style={{ color: '#8b949e' }}>{p.name}:</span>
          <span style={{ fontWeight: 700, fontFamily: 'monospace' }}>{Number(p.value).toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
};

// Format duration ms → human readable
function formatDur(ms) {
  if (!ms && ms !== 0) return '—';
  const n = Number(ms);
  if (isNaN(n)) return '—';
  if (n < 1000) return `${n}ms`;
  if (n < 60000) return `${(n/1000).toFixed(1)}s`;
  return `${Math.floor(n/60000)}m${Math.floor((n%60000)/1000)}s`;
}
export default function DashboardPage({ server, range, selectedDate, dateFrom, dateTo }) {
  const [summary,      setSummary]      = useState(null);
  const [trend,        setTrend]        = useState([]);
  const [hourly,       setHourly]       = useState([]);
  const [topSenders,   setTopSenders]   = useState([]);
  const [topRecipients,setTopRecipients]= useState([]);
  const [wrongHits,    setWrongHits]    = useState([]);
  const [threatData,   setThreatData]   = useState(null);
  const [recentLogs,   setRecentLogs]   = useState([]);
  const [loading,      setLoading]      = useState(true);
  const [lastRefresh,  setLastRefresh]  = useState(new Date());
  const [activeChart,  setActiveChart]  = useState(range === 'today' ? 'hourly' : 'trend'); // trend | hourly

  useEffect(() => {
    setActiveChart(range === 'today' ? 'hourly' : 'trend');
  }, [range]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const p = { range, server };
      if (range === 'today') p.date = selectedDate;
      if (range === 'custom') { p.from = dateFrom; p.to = dateTo; }

      // Charts use the same Topbar range as KPIs (no silent 7d override)
      const chartParams = { ...p };

      const [s, t, h, ts, tr, wh, th, rl] = await Promise.all([
        statsApi.getEnhancedSummary ? statsApi.getEnhancedSummary(p) : statsApi.getSummary(p),
        statsApi.getTrend(chartParams),
        statsApi.getHourly({ date: selectedDate || p.date, server, range }),
        statsApi.getTopSenders({ ...p, limit: 8 }),
        statsApi.getTopRecipients({ ...p, limit: 8 }),
        statsApi.getWrongHitsTrend(chartParams),
        statsApi.getThreatBreakdown(p),
        statsApi.getRecentLogs({ ...p, limit: 20 }),
      ]);

      setSummary(s.data);
      setTrend((t.data || []).map(r => ({
        ...r,
        success:      Number(r.success      || 0),
        failed:       Number(r.failed       || 0),
        bounced:      Number(r.bounced      || 0),
        deferred:     Number(r.deferred     || 0),
        spam_blocked: Number(r.spam_blocked || 0),
        total:        Number(r.total        || 0),
      })));
      setHourly(h.data || []);
      setTopSenders(ts.data || []);
      setTopRecipients(tr.data || []);
      setWrongHits((wh.data || []).map(r => ({
        ...r,
        failed:      Number(r.failed      || 0),
        bounced:     Number(r.bounced     || 0),
        spam:        Number(r.spam        || 0),
        invalid:     Number(r.invalid     || 0),
        timeout:     Number(r.timeout     || 0),
        total_wrong: Number(r.total_wrong || 0),
      })));
      setThreatData(th.data || {});
      setRecentLogs(rl.data || []);
      setLastRefresh(new Date());
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [server, range, selectedDate, dateFrom, dateTo]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const t = setInterval(load, 120000);
    return () => clearInterval(t);
  }, [load]);

  const serverLabel = server === 'campaign' ? '🟠 Campaign Bulk Mail' : '🔵 App Mail Transactional';
  const vs = summary?.vs_yesterday || {};

  // Pie data for email breakdown
  const pieData = threatData ? [
    { name: 'Clean',       value: Number(threatData.clean     || 0), color: C.green  },
    { name: 'Spam',        value: Number(threatData.spam      || 0), color: C.orange },
    { name: 'Bounced',     value: Number(threatData.bounced   || 0), color: C.red    },
    { name: 'Failed',      value: Number(threatData.failed    || 0), color: C.pink   },
    { name: 'Blocked',     value: Number(threatData.blocked   || 0), color: C.purple },
    { name: 'Deferred',    value: Number(threatData.deferred  || 0), color: C.yellow },
    { name: 'Phishing',    value: Number(threatData.phishing  || 0), color: '#f43f5e'},
    { name: 'Malware',     value: Number(threatData.malware   || 0), color: '#a855f7'},
  ].filter(d => d.value > 0) : [];

  const totalEmails = Number(summary?.total || 0);

  // Max for mini bars
  const maxSender    = Math.max(...topSenders.map(s => Number(s.total || 0)), 1);
  const maxRecipient = Math.max(...topRecipients.map(r => Number(r.total || 0)), 1);

  const dateLabel = v => {
    if (!v) return '';
    const d = v.includes('T') ? new Date(v) : new Date(v + 'T00:00:00');
    return `${(d.getMonth()+1).toString().padStart(2,'0')}-${d.getDate().toString().padStart(2,'0')}`;
  };

  if (loading && !summary) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 400, gap: 12, color: 'var(--text-muted)' }}>
      <RefreshCw size={20} className="spin" />
      <span>Loading dashboard...</span>
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* ---- Header ---- */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.5px' }}>
            Email Logs & Analytics
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
            {serverLabel} · Real-time overview of email traffic, threats and activity
            <span style={{ marginLeft: 12, color: 'var(--text-muted)', fontSize: 11 }}>
              Last refreshed: {lastRefresh.toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata' })}
            </span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-ghost btn-sm" onClick={load} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* ---- KPI Row 1: Main metrics ---- */}
      {totalEmails === 0 && !loading && (
        <div style={{
          padding: '12px 16px', borderRadius: 10, marginBottom: 4,
          background: 'rgba(234,88,12,0.08)', border: '1px solid rgba(234,88,12,0.25)',
          fontSize: 13, color: 'var(--text-muted)',
        }}>
          No delivery records for this {range === 'today' ? 'day' : 'range'} on {serverLabel}.
          {summary?.fallback === false ? ' Charts below only show days that have data.' : ''}
          {range === 'today' ? ' Try 7 Days or 30 Days if Campaign traffic ran earlier this week.' : ''}
        </div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12 }}>
        <KpiCard label="Total Emails"     value={totalEmails}             icon={Mail}         color={C.blue}   vsYesterday={vs.total}       pulse sub="All delivery records" />
        <KpiCard label="Inbound"          value={summary?.inbound}        icon={Inbox}        color={C.cyan}   sub="To us (excl. from us)" />
        <KpiCard label="Outbound"         value={summary?.outbound}       icon={Send}         color={C.teal}   sub="From our domains"      />
        <KpiCard label="Blocked/Rejected" value={summary?.spam_blocked}   icon={Ban}          color={C.pink}   vsYesterday={vs.spam_blocked} />
        <KpiCard label="Wrong Hits"       value={summary?.wrong_hits}     icon={AlertTriangle} color={C.red}   vsYesterday={vs.wrong_hits}  sub="Failed+Bounced+Invalid" />
        <KpiCard label="Threats"          value={summary?.threats}        icon={Shield}       color={C.purple} sub="Spam/Phish/Malware"     />
      </div>

      {/* Direction check: Inbound + Outbound (+ other) should equal Total */}
      {totalEmails > 0 && (
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: -4, marginBottom: 4 }}>
          Direction: Inbound {Number(summary?.inbound || 0).toLocaleString()}
          {' + '}Outbound {Number(summary?.outbound || 0).toLocaleString()}
          {Number(summary?.other_direction || 0) > 0 && (
            <>{' + '}Other {Number(summary.other_direction).toLocaleString()}</>
          )}
          {' = '}{(Number(summary?.inbound || 0) + Number(summary?.outbound || 0) + Number(summary?.other_direction || 0)).toLocaleString()}
          {' · '}Status: Delivered {Number(summary?.success || 0).toLocaleString()}
          {' + '}Failed {Number(summary?.failed || 0).toLocaleString()}
          {' + '}Bounced {Number(summary?.bounced || 0).toLocaleString()}
          {' + '}Deferred {Number(summary?.deferred || 0).toLocaleString()}
          {' + '}other statuses
          {' ≈ '}Total {totalEmails.toLocaleString()}
        </div>
      )}

      {/* ---- KPI Row 2: Delivery metrics ---- */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12 }}>
        <KpiCard label="Delivered"     value={summary?.success}    icon={CheckCircle}  color={C.green}  vsYesterday={vs.success}  sub="Of total records" />
        <KpiCard label="Failed"        value={summary?.failed}     icon={XCircle}      color={C.red}    vsYesterday={vs.failed}   />
        <KpiCard label="Bounced"       value={summary?.bounced}    icon={AlertTriangle} color={C.orange} />
        <KpiCard label="Deferred"      value={summary?.deferred}   icon={Clock}        color={C.yellow} />
        <KpiCard label="Timed Out"     value={summary?.timedout}   icon={Clock}        color={C.purple} />
        <KpiCard label="Invalid Addr"  value={summary?.invalid_addr} icon={XCircle}    color={'#b91c1c'} />
      </div>

      {/* ---- Traffic + Breakdown row ---- */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 16 }}>
        {/* Traffic chart */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 700 }}>Email Traffic Overview</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                {range === 'today' ? 'Today' : range === '30d' ? '30-day' : range === 'custom' ? 'Custom range' : '7-day'} delivery vs failures trend
                {summary?.fallback ? ' · live log fallback' : ''}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              {['trend', 'hourly'].map(c => (
                <button key={c} className={`btn btn-sm ${activeChart === c ? 'btn-primary' : 'btn-ghost'}`}
                  onClick={() => setActiveChart(c)}>
                  {c === 'trend' ? (range === 'today' ? 'By Day' : range === '30d' ? '30-Day' : range === 'custom' ? 'Range' : '7-Day') : 'Hourly'}
                </button>
              ))}
            </div>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            {activeChart === 'trend' ? (
              <AreaChart data={trend} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <defs>
                  {[['success',C.green],['bounced',C.orange],['failed',C.red],['spam_blocked',C.pink],['deferred',C.yellow]].map(([k,v]) => (
                    <linearGradient key={k} id={`g-${k}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor={v} stopOpacity={0.4} />
                      <stop offset="95%" stopColor={v} stopOpacity={0}   />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="log_date" tick={{ fill:'#6e7681', fontSize:11 }} tickFormatter={dateLabel} />
                <YAxis tick={{ fill:'#6e7681', fontSize:11 }} domain={[0,'auto']} allowDecimals={false} />
                <Tooltip content={<CustomTooltip />} />
                <Legend wrapperStyle={{ fontSize:11 }} />
                <Area type="monotone" dataKey="success"      stroke={C.green}  fill="url(#g-success)"      name="Delivered"  strokeWidth={2} />
                <Area type="monotone" dataKey="bounced"      stroke={C.orange} fill="url(#g-bounced)"      name="Bounced"    strokeWidth={1.5} />
                <Area type="monotone" dataKey="failed"       stroke={C.red}    fill="url(#g-failed)"       name="Failed"     strokeWidth={1.5} />
                <Area type="monotone" dataKey="spam_blocked" stroke={C.pink}   fill="url(#g-spam_blocked)" name="Blocked"    strokeWidth={1.5} />
                <Area type="monotone" dataKey="deferred"     stroke={C.yellow} fill="url(#g-deferred)"     name="Deferred"   strokeWidth={1} />
              </AreaChart>
            ) : (
              <BarChart data={Array.from({length:24},(_,h) => {
                const f = hourly.find(r => r.hour === h) || {};
                return { hour:`${String(h).padStart(2,'0')}:00`,
                  success:  Number(f.success  || 0),
                  failed:   Number(f.failed   || 0),
                  bounced:  Number(f.bounced  || 0),
                  deferred: Number(f.deferred || 0),
                };
              })} margin={{ top:4, right:8, left:-20, bottom:0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="hour" tick={{ fill:'#6e7681', fontSize:10 }} />
                <YAxis tick={{ fill:'#6e7681', fontSize:11 }} domain={[0,'auto']} allowDecimals={false} />
                <Tooltip content={<CustomTooltip />} />
                <Legend wrapperStyle={{ fontSize:11 }} />
                <Bar dataKey="success"  fill={C.green}  name="Delivered" stackId="a" />
                <Bar dataKey="bounced"  fill={C.orange} name="Bounced"   stackId="a" />
                <Bar dataKey="failed"   fill={C.red}    name="Failed"    stackId="a" />
                <Bar dataKey="deferred" fill={C.yellow} name="Deferred"  stackId="a" radius={[2,2,0,0]} />
              </BarChart>
            )}
          </ResponsiveContainer>
        </div>

        {/* Email breakdown donut */}
        <div className="card">
          <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 4 }}>Email Breakdown</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12 }}>Classification of all traffic</div>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie data={pieData} cx="40%" cy="50%" innerRadius={50} outerRadius={75} dataKey="value" paddingAngle={2}>
                {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Pie>
              <Tooltip contentStyle={TT_STYLE} formatter={(v, n) => [v.toLocaleString(), n]} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 4 }}>
            {pieData.map((d, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: d.color, flexShrink: 0 }} />
                  <span style={{ color: 'var(--text-muted)' }}>{d.name}</span>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: d.color, fontWeight: 700 }}>
                    {d.value.toLocaleString()}
                  </span>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                    ({totalEmails > 0 ? ((d.value/totalEmails)*100).toFixed(1) : 0}%)
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ---- Top Senders + Recipients + Wrong Hits ---- */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>

        {/* Top Senders */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <div style={{ fontSize: 14, fontWeight: 700 }}>Top Senders</div>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-primary)', padding: '3px 8px', borderRadius: 20 }}>
              {range === 'today' ? selectedDate : `Last ${range === '30d' ? '30' : '7'} days`}
            </span>
          </div>
          {topSenders.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 20, color: 'var(--text-muted)', fontSize: 12 }}>No data</div>
          ) : topSenders.map((s, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', width: 16, textAlign: 'right', flexShrink: 0 }}>{i+1}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: 4 }}>
                  {s.email}
                </div>
                <MiniBar value={Number(s.total)} max={maxSender} color={C.blue} />
              </div>
              <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', fontWeight: 700, color: C.blue, flexShrink: 0 }}>
                {Number(s.total).toLocaleString()}
              </span>
            </div>
          ))}
        </div>

        {/* Top Recipients */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <div style={{ fontSize: 14, fontWeight: 700 }}>Top Recipients</div>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-primary)', padding: '3px 8px', borderRadius: 20 }}>
              {range === 'today' ? selectedDate : `Last ${range === '30d' ? '30' : '7'} days`}
            </span>
          </div>
          {topRecipients.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 20, color: 'var(--text-muted)', fontSize: 12 }}>No data</div>
          ) : topRecipients.map((r, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', width: 16, textAlign: 'right', flexShrink: 0 }}>{i+1}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: 4 }}>
                  {r.email}
                </div>
                <MiniBar value={Number(r.total)} max={maxRecipient} color={C.cyan} />
              </div>
              <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', fontWeight: 700, color: C.cyan, flexShrink: 0 }}>
                {Number(r.total).toLocaleString()}
              </span>
            </div>
          ))}
        </div>

        {/* Wrong Hits Trend */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 700 }}>Wrong Hits Trend</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Rejected / failed / spam attempts</div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={wrongHits} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
              <XAxis dataKey="log_date" tick={{ fill: '#6e7681', fontSize: 10 }} tickFormatter={dateLabel} />
              <YAxis tick={{ fill: '#6e7681', fontSize: 10 }} domain={[0, 'auto']} allowDecimals={false} />
              <Tooltip content={<CustomTooltip />} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              <Line type="monotone" dataKey="total_wrong" stroke={C.red}    dot={{ r: 3, fill: C.red }}    name="Total Wrong" strokeWidth={2} />
              <Line type="monotone" dataKey="spam"        stroke={C.pink}   dot={false}                     name="Spam"        strokeWidth={1.5} strokeDasharray="4 2" />
              <Line type="monotone" dataKey="bounced"     stroke={C.orange} dot={false}                     name="Bounced"     strokeWidth={1.5} strokeDasharray="4 2" />
              <Line type="monotone" dataKey="invalid"     stroke={C.purple} dot={false}                     name="Invalid"     strokeWidth={1} strokeDasharray="2 2" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ---- Recent Email Logs ---- */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700 }}>Recent Email Logs</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Live feed of latest mail activity with direction and threat classification</div>
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Showing last {recentLogs.length} entries</div>
        </div>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Direction</th>
                <th>From</th>
                <th>To</th>
                <th>Subject / Campaign</th>
                <th>Action</th>
                <th>Result</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody>
              {recentLogs.map((log, i) => (
                <tr key={i}>
                  <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                    {log.log_date} {String(log.log_time || '').slice(0, 8)}
                  </td>
                  <td><DirectionBadge dir={log.direction} /></td>
                  <td style={{ maxWidth: 160 }}>
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 12 }} title={log.mail_from}>
                      {log.mail_from || '—'}
                    </div>
                  </td>
                  <td style={{ maxWidth: 160 }}>
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 12 }} title={log.mail_to}>
                      {log.mail_to || '—'}
                    </div>
                  </td>
                  <td style={{ maxWidth: 220 }}>
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 12, color: log.subject ? 'var(--text-primary)' : 'var(--text-muted)' }}
                      title={log.subject ? decodeEmailSubject(log.subject) : (log.campaign_id ? `Campaign: ${log.campaign_id}` : '')}>
                      {log.subject
                        ? decodeEmailSubject(log.subject)
                        : log.campaign_id
                          ? `Campaign: ${log.campaign_id}`
                          : '—'}
                    </div>
                  </td>
                  <td>
                    <span style={{
                      padding: '2px 8px', borderRadius: 20, fontSize: 11, fontWeight: 600,
                      background: log.action === 'Delivered' ? 'rgba(22,163,74,0.15)'  :
                                  log.action === 'Blocked'   ? 'rgba(190,24,93,0.15)'  :
                                  log.action === 'Bounced'   ? 'rgba(234,88,12,0.15)'  :
                                  log.action === 'Failed'    ? 'rgba(220,38,38,0.15)'  :
                                  'rgba(217,119,6,0.15)',
                      color: log.action === 'Delivered' ? '#4ade80' :
                             log.action === 'Blocked'   ? '#f472b6' :
                             log.action === 'Bounced'   ? '#fb923c' :
                             log.action === 'Failed'    ? '#f87171' :
                             '#fbbf24'
                    }}>
                      {log.action}
                    </span>
                  </td>
                  <td><ResultBadge action={log.action} threat={log.threat_type} /></td>
                  <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {log.duration ? (log.duration < 1000 ? log.duration + 'ms' : (log.duration/1000).toFixed(1) + 's') : '—'}
                  </td>
                </tr>
              ))}
              {recentLogs.length === 0 && (
                <tr><td colSpan={8} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>No recent logs</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ---- Delivery Health + Wrong Hits breakdown ---- */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="card">
          <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 16 }}>Delivery Health Metrics</div>
          {[
            { label: 'Delivery Rate', value: totalEmails > 0 ? ((Number(summary?.success||0)/totalEmails)*100).toFixed(1) : 0, color: C.green, threshold: 90 },
            { label: 'Bounce Rate',   value: totalEmails > 0 ? ((Number(summary?.bounced||0)/totalEmails)*100).toFixed(1) : 0, color: C.orange, threshold: 2, invert: true },
            { label: 'Failure Rate',  value: totalEmails > 0 ? ((Number(summary?.failed||0)/totalEmails)*100).toFixed(1)  : 0, color: C.red,    threshold: 5, invert: true },
            { label: 'Wrong Hit Rate',value: totalEmails > 0 ? ((Number(summary?.wrong_hits||0)/totalEmails)*100).toFixed(1) : 0, color: C.pink, threshold: 10, invert: true },
          ].map(m => {
            const pct  = parseFloat(m.value);
            const good = m.invert ? pct <= m.threshold : pct >= m.threshold;
            const col  = good ? C.green : pct > m.threshold * 2 ? C.red : C.yellow;
            return (
              <div key={m.label} style={{ marginBottom: 14 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{m.label}</span>
                  <span style={{ fontSize: 16, fontWeight: 800, color: col, fontFamily: 'var(--font-mono)' }}>{m.value}%</span>
                </div>
                <div style={{ background: 'var(--border)', borderRadius: 4, height: 6, overflow: 'hidden' }}>
                  <div style={{ width: `${Math.min(pct, 100)}%`, height: '100%', background: col, borderRadius: 4, transition: 'width 0.5s' }} />
                </div>
              </div>
            );
          })}
          <div style={{ borderTop: '1px solid var(--border)', paddingTop: 12, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Avg Duration<br/><span style={{ fontSize: 18, fontWeight: 800, color: C.cyan, fontFamily: 'var(--font-mono)' }}>{summary?.avg_duration ? (Number(summary.avg_duration) < 1000 ? `${Math.round(summary.avg_duration)}ms` : `${(Number(summary.avg_duration)/1000).toFixed(1)}s`) : '0ms'}</span></div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Unique Senders<br/><span style={{ fontSize: 18, fontWeight: 800, color: C.blue, fontFamily: 'var(--font-mono)' }}>{Number(summary?.unique_senders || 0).toLocaleString()}</span></div>
          </div>
        </div>

        {/* Wrong hits breakdown */}
        <div className="card">
          <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 4 }}>Wrong Hits Breakdown</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 14 }}>All rejected, blocked and failed attempts</div>
          {[
            { label: 'Spam / Blocked',  value: summary?.spam_blocked,  color: C.pink,   icon: '⊘' },
            { label: 'Hard Bounce',     value: summary?.bounced,        color: C.orange, icon: '⟳' },
            { label: 'Failed Delivery', value: summary?.failed,         color: C.red,    icon: '✕' },
            { label: 'Invalid Address', value: summary?.invalid_addr,   color: '#b91c1c',icon: '?' },
            { label: 'Timed Out',       value: summary?.timedout,       color: C.purple, icon: '⏱' },
            { label: 'Threats',         value: summary?.threats,        color: C.purple, icon: '⚠' },
          ].map(item => {
            const val = Number(item.value || 0);
            const max = Number(summary?.wrong_hits || 1);
            return (
              <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                <span style={{ fontSize: 14, width: 20, flexShrink: 0, color: item.color }}>{item.icon}</span>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                    <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{item.label}</span>
                    <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', fontWeight: 700, color: item.color }}>{val.toLocaleString()}</span>
                  </div>
                  <div style={{ background: 'var(--border)', borderRadius: 3, height: 4, overflow: 'hidden' }}>
                    <div style={{ width: `${max > 0 ? (val/max)*100 : 0}%`, height: '100%', background: item.color, borderRadius: 3 }} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { box-shadow: 0 0 0 3px rgba(37,99,235,0.3); }
          50%       { box-shadow: 0 0 0 6px rgba(37,99,235,0.1); }
        }
      `}</style>
    </div>
  );
}
