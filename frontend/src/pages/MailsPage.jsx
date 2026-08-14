import { useState, useEffect, useCallback, useRef } from 'react';
import { Search, RefreshCw, Download, Filter } from 'lucide-react';
import { mailsApi } from '../utils/api';
import StatusBadge from '../components/StatusBadge';

function formatDuration(ms) {
  if (ms === null || ms === undefined) return '—';
  const s = Number(ms) / 1000;
  if (isNaN(s)) return '—';
  if (s < 60)   return s.toFixed(1) + 's';
  return Math.floor(s/60) + 'm ' + Math.floor(s%60) + 's';
}

export default function MailsPage({ server, range, selectedDate, dateFrom, dateTo }) {
  const [mails, setMails]           = useState([]);
  const [pagination, setPagination] = useState({ total: 0, page: 1, limit: 50, pages: 0 });
  const [loading, setLoading]       = useState(true);
  const [search, setSearch]         = useState('');
  const [statusFilter, setStatusFilter]     = useState('');
  const [campaignFilter, setCampaignFilter] = useState('');
  const [dsnFilter, setDsnFilter]           = useState('');
  const [filterValues, setFilterValues]     = useState({ statuses: [], campaigns: [], dsn_codes: [] });
  const [expanded, setExpanded]     = useState(null);
  const [page, setPage]             = useState(1);

  // Track previous server to detect switch
  const prevServer = useRef(server);

  // Reset everything when server switches
  useEffect(() => {
    if (prevServer.current !== server) {
      prevServer.current = server;
      setPage(1);
      setSearch('');
      setStatusFilter('');
      setCampaignFilter('');
      setDsnFilter('');
      setExpanded(null);
      setMails([]);
      // Load filter values for new server
      mailsApi.getFilterValues({ server }).then(r => setFilterValues(r)).catch(() => {});
    }
  }, [server]);

  // Load filter values on mount
  useEffect(() => {
    mailsApi.getFilterValues({ server }).then(r => setFilterValues(r)).catch(() => {});
  }, [server]);

  const load = useCallback(async (pg = 1) => {
    setLoading(true);
    try {
      const params = {
        page: pg, limit: 50, range, server,
        ...(search         && { search }),
        ...(statusFilter   && { status: statusFilter }),
        ...(campaignFilter && { campaign_id: campaignFilter }),
        ...(dsnFilter      && { dsn: dsnFilter }),
      };
      if (range === 'today')  params.date = selectedDate;
      if (range === 'custom') { params.from = dateFrom; params.to = dateTo; }

      const r = await mailsApi.getList(params);
      setMails(r.data);
      setPagination(r.pagination);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [server, range, selectedDate, dateFrom, dateTo, search, statusFilter, campaignFilter, dsnFilter]);

  // Reload when server, range, date, or filters change — always reset to page 1
  useEffect(() => {
    setPage(1);
    load(1);
  }, [server, range, selectedDate, dateFrom, dateTo, statusFilter, campaignFilter, dsnFilter]);

  // Reload when page changes
  useEffect(() => {
    load(page);
  }, [page]);

  const handleSearch = (e) => {
    e.preventDefault();
    setPage(1);
    load(1);
  };

  const handleClear = () => {
    setSearch('');
    setStatusFilter('');
    setCampaignFilter('');
    setDsnFilter('');
    setPage(1);
    setTimeout(() => load(1), 50);
  };

  const exportCSV = () => {
    const headers = ['ID','Date','Time','From','To','Campaign','Queue ID','Status','Delivery Status','DSN','Duration(s)','Reason'];
    const rows = mails.map(m => [
      m.id, m.log_date, m.log_time, m.mail_from, m.mail_to, m.campaign_id,
      m.queue_id, m.status, m.delivery_status, m.dsn, m.duration,
      (m.reason || '').replace(/,/g, ';').replace(/\n/g, ' ')
    ]);
    const csv  = [headers, ...rows].map(r => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `email-mails-${server}-${selectedDate}.csv`;
    a.click();
  };

  const serverLabel = server === 'campaign' ? '🟠 Campaign' : '🔵 App Mail';

  return (
    <div>
      <div className="flex-between mb-24">
        <div>
          <div className="section-title">All Mail Records</div>
          <div className="section-sub">
            {serverLabel} &nbsp;·&nbsp; Total: {pagination.total.toLocaleString()} records
          </div>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={exportCSV}>
          <Download size={14} /> Export CSV
        </button>
      </div>

      {/* Server indicator banner */}
      <div style={{
        background: server === 'campaign' ? 'rgba(234,88,12,0.08)' : 'rgba(8,145,178,0.08)',
        border: `1px solid ${server === 'campaign' ? 'rgba(234,88,12,0.25)' : 'rgba(8,145,178,0.25)'}`,
        borderRadius: 8, padding: '8px 16px', marginBottom: 16,
        display: 'flex', alignItems: 'center', gap: 10, fontSize: 13
      }}>
        <span style={{ color: server === 'campaign' ? '#ea580c' : '#0891b2', fontWeight: 600 }}>
          {serverLabel}
        </span>
        <span style={{ color: 'var(--text-muted)' }}>
          {server === 'campaign' ? 'Bulk / Campaign mail server — 10.180.0.203' : 'Transactional / App mail server — 10.180.0.84'}
        </span>
      </div>

      {/* Filters */}
      <div className="card mb-24">
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ flex: 1, minWidth: 220 }}>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>SEARCH</label>
            <div style={{ position: 'relative' }}>
              <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input className="input" style={{ paddingLeft: 32 }}
                placeholder="Email, Queue ID, Message ID, Campaign..."
                value={search} onChange={e => setSearch(e.target.value)} />
            </div>
          </div>
          <div style={{ minWidth: 150 }}>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>STATUS</label>
            <select className="input" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
              <option value="">All Statuses</option>
              {filterValues.statuses?.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div style={{ minWidth: 160 }}>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>CAMPAIGN</label>
            <select className="input" value={campaignFilter} onChange={e => setCampaignFilter(e.target.value)}>
              <option value="">All Campaigns</option>
              {filterValues.campaigns?.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <div style={{ minWidth: 120 }}>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>DSN CODE</label>
            <select className="input" value={dsnFilter} onChange={e => setDsnFilter(e.target.value)}>
              <option value="">All DSN</option>
              {filterValues.dsn_codes?.map(d => <option key={d} value={d}>{d}</option>)}
            </select>
          </div>
          <button type="submit" className="btn btn-primary btn-sm"><Filter size={13} /> Filter</button>
          <button type="button" className="btn btn-ghost btn-sm" onClick={handleClear}>Clear</button>
        </form>
      </div>

      {/* Table */}
      <div className="card">
        {loading ? (
          <div className="loading-state">
            <RefreshCw size={20} className="spin" />
            <div style={{ marginTop: 12 }}>Loading {serverLabel} mails...</div>
          </div>
        ) : (
          <>
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>ID</th><th>Date / Time</th><th>From</th><th>To</th>
                    <th>Campaign</th><th>Status</th><th>Delivery</th>
                    <th>DSN</th><th>Duration</th><th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {mails.map(m => (
                    <>
                      <tr key={m.id} onClick={() => setExpanded(expanded === m.id ? null : m.id)}
                        style={{ cursor: 'pointer' }}>
                        <td className="mono" style={{ color: 'var(--text-muted)' }}>{m.id}</td>
                        <td className="mono" style={{ whiteSpace: 'nowrap', fontSize: 12 }}>
                          {m.log_date}<br />
                          <span style={{ color: 'var(--text-muted)' }}>{String(m.log_time || '').slice(0,8)}</span>
                        </td>
                        <td style={{ maxWidth: 180 }}><div className="truncate" title={m.mail_from}>{m.mail_from || '—'}</div></td>
                        <td style={{ maxWidth: 180 }}><div className="truncate" title={m.mail_to}>{m.mail_to || '—'}</div></td>
                        <td><span className="mono" style={{ fontSize: 11 }}>{m.campaign_id || '—'}</span></td>
                        <td><StatusBadge status={m.status} /></td>
                        <td><StatusBadge status={m.delivery_status} /></td>
                        <td><span className="mono" style={{ fontSize: 11, color: getDsnColor(m.dsn) }}>{m.dsn || '—'}</span></td>
                        <td className="mono" style={{ fontSize: 11 }}>{m.duration ? (m.duration/1000).toFixed(1) + 's' : '—'}</td>
                        <td style={{ maxWidth: 240 }}>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 220 }} title={m.reason}>
                            {m.reason || '—'}
                          </div>
                        </td>
                      </tr>
                      {expanded === m.id && (
                        <tr key={`${m.id}-exp`} style={{ background: 'rgba(37,99,235,0.05)' }}>
                          <td colSpan={10} style={{ padding: '12px 16px' }}>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12, fontSize: 12 }}>
                              <div><span style={{ color: 'var(--text-muted)' }}>Queue ID:</span> <span className="mono">{m.queue_id || '—'}</span></div>
                              <div><span style={{ color: 'var(--text-muted)' }}>Message ID:</span> <span className="mono">{m.message_id || '—'}</span></div>
                              <div><span style={{ color: 'var(--text-muted)' }}>Mail ID:</span> <span className="mono">{m.mail_id || '—'}</span></div>
                              <div><span style={{ color: 'var(--text-muted)' }}>Queued As:</span> <span className="mono">{m.queued_as || '—'}</span></div>
                              <div><span style={{ color: 'var(--text-muted)' }}>Domain ID:</span> {m.domain_id || '—'}</div>
                              <div><span style={{ color: 'var(--text-muted)' }}>Duration:</span> {m.duration ? (m.duration/1000).toFixed(1) + 's' : '—'}</div>
                              <div style={{ gridColumn: '1 / -1' }}>
                                <span style={{ color: 'var(--text-muted)' }}>Full Reason: </span>
                                <span style={{ color: '#fbbf24', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{m.reason || '—'}</span>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                  {mails.length === 0 && (
                    <tr><td colSpan={10} className="text-center" style={{ padding: 40, color: 'var(--text-muted)' }}>
                      No records found for {serverLabel}
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="flex-between" style={{ marginTop: 16, padding: '0 4px' }}>
              <div className="page-info">
                Showing {((pagination.page-1)*pagination.limit)+1}–{Math.min(pagination.page*pagination.limit, pagination.total)} of {pagination.total.toLocaleString()}
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <button className="btn btn-ghost btn-sm" disabled={page <= 1} onClick={() => setPage(p => p-1)}>← Prev</button>
                <span style={{ padding: '5px 10px', fontSize: 12, color: 'var(--text-muted)' }}>
                  Page {pagination.page} of {pagination.pages}
                </span>
                <button className="btn btn-ghost btn-sm" disabled={page >= pagination.pages} onClick={() => setPage(p => p+1)}>Next →</button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function getDsnColor(dsn) {
  if (!dsn) return 'var(--text-muted)';
  if (dsn.startsWith('2')) return '#4ade80';
  if (dsn.startsWith('4')) return '#fbbf24';
  if (dsn.startsWith('5')) return '#f87171';
  return 'var(--text-muted)';
}
