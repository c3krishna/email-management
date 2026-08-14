import { useState } from 'react';
import { FileText, Download, RefreshCw, Calendar, Filter } from 'lucide-react';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const REPORT_TYPES = [
  { id:'delivery_summary',  label:'Delivery Summary',       icon:'📊', desc:'Total sent, delivered, bounced, failed by day' },
  { id:'threat_report',     label:'Threat Intelligence',    icon:'🛡️', desc:'New indicators, threat types, AI classifications' },
  { id:'top_senders',       label:'Top Senders',            icon:'📤', desc:'Most active senders with delivery rates' },
  { id:'bounce_analysis',   label:'Bounce Analysis',        icon:'⟳',  desc:'Hard/soft bounces with DSN codes and reasons' },
  { id:'spam_report',       label:'Spam & Rejection',       icon:'🚫', desc:'Blocked emails, spam scores, rejection reasons' },
  { id:'campaign_report',   label:'Campaign Performance',   icon:'📣', desc:'Per-campaign delivery, bounce, success rates' },
];

export default function ReportingPage({ server }) {
  const [reportType, setReportType] = useState('delivery_summary');
  const [dateFrom,   setDateFrom]   = useState(() => {
    const d = new Date(); d.setDate(d.getDate()-30);
    return d.toISOString().slice(0,10);
  });
  const [dateTo,  setDateTo]    = useState(new Date().toISOString().slice(0,10));
  const [format,  setFormat]    = useState('csv');
  const [loading, setLoading]   = useState(false);
  const [preview, setPreview]   = useState(null);
  const [error,   setError]     = useState('');

  const serverLabel = server === 'campaign' ? 'Campaign Bulk Mail' : 'App Mail Transactional';

  const generatePreview = async () => {
    setLoading(true); setError(''); setPreview(null);
    try {
      const r = await api.get('/reports/generate', {
        params: { type: reportType, from: dateFrom, to: dateTo, server, format: 'json', limit: 20 }
      });
      setPreview(r.data);
    } catch(e) {
      setError(e.response?.data?.error || e.message);
    } finally { setLoading(false); }
  };

  const downloadReport = async () => {
    setLoading(true); setError('');
    try {
      const r = await api.get('/reports/generate', {
        params: { type: reportType, from: dateFrom, to: dateTo, server, format },
        responseType: format === 'csv' ? 'blob' : 'json',
      });

      if (format === 'csv') {
        const url = URL.createObjectURL(new Blob([r.data], { type: 'text/csv' }));
        const a   = document.createElement('a');
        a.href    = url;
        a.download = `${reportType}_${dateFrom}_${dateTo}.csv`;
        a.click();
      } else {
        // JSON download
        const url = URL.createObjectURL(new Blob([JSON.stringify(r.data, null, 2)], { type: 'application/json' }));
        const a   = document.createElement('a');
        a.href    = url;
        a.download = `${reportType}_${dateFrom}_${dateTo}.json`;
        a.click();
      }
    } catch(e) {
      setError(e.response?.data?.error || e.message);
    } finally { setLoading(false); }
  };

  const selected = REPORT_TYPES.find(r => r.id === reportType);

  return (
    <div>
      <div className="mb-24">
        <div className="section-title">Reporting</div>
        <div className="section-sub">{serverLabel} · Generate and export reports for any date range</div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'280px 1fr', gap:16 }}>

        {/* Left: report type selector */}
        <div>
          <div style={{ fontSize:11, color:'var(--text-muted)', textTransform:'uppercase',
            letterSpacing:0.8, marginBottom:10 }}>Report Type</div>
          {REPORT_TYPES.map(rt => (
            <div key={rt.id}
              onClick={() => { setReportType(rt.id); setPreview(null); }}
              style={{
                padding:'12px 14px', borderRadius:8, marginBottom:8,
                cursor:'pointer', border:'1px solid var(--border)',
                background: reportType===rt.id ? 'rgba(37,99,235,0.1)' : 'var(--bg-card)',
                borderColor: reportType===rt.id ? 'var(--accent-blue)' : 'var(--border)',
                transition:'all 0.15s',
              }}>
              <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:4 }}>
                <span style={{ fontSize:18 }}>{rt.icon}</span>
                <span style={{ fontSize:13, fontWeight:600,
                  color: reportType===rt.id ? 'var(--accent-blue-light)' : 'var(--text-primary)' }}>
                  {rt.label}
                </span>
              </div>
              <div style={{ fontSize:11, color:'var(--text-muted)', paddingLeft:28 }}>{rt.desc}</div>
            </div>
          ))}
        </div>

        {/* Right: config + preview */}
        <div>
          {/* Config panel */}
          <div className="card mb-16">
            <div style={{ fontSize:14, fontWeight:700, marginBottom:16 }}>
              {selected?.icon} {selected?.label}
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr auto auto', gap:10, alignItems:'end' }}>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>From Date</label>
                <input type="date" className="input" style={{ marginTop:4 }}
                  value={dateFrom} onChange={e => setDateFrom(e.target.value)} />
              </div>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>To Date</label>
                <input type="date" className="input" style={{ marginTop:4 }}
                  value={dateTo} onChange={e => setDateTo(e.target.value)} />
              </div>
              <div>
                <label style={{ fontSize:11, color:'var(--text-muted)' }}>Format</label>
                <select className="input" style={{ marginTop:4 }} value={format}
                  onChange={e => setFormat(e.target.value)}>
                  <option value="csv">CSV</option>
                  <option value="json">JSON</option>
                </select>
              </div>
              <button className="btn btn-ghost btn-sm" onClick={generatePreview} disabled={loading}>
                <RefreshCw size={13} className={loading ? 'spin' : ''}/> Preview
              </button>
              <button className="btn btn-primary btn-sm" onClick={downloadReport} disabled={loading}>
                <Download size={13}/> Download
              </button>
            </div>

            {/* Quick ranges */}
            <div style={{ display:'flex', gap:8, marginTop:12 }}>
              <span style={{ fontSize:11, color:'var(--text-muted)' }}>Quick:</span>
              {[
                { label:'Today',    days:0  },
                { label:'7 days',   days:7  },
                { label:'30 days',  days:30 },
                { label:'90 days',  days:90 },
                { label:'1 year',   days:365 },
              ].map(q => (
                <button key={q.label} className="btn btn-ghost btn-sm"
                  style={{ padding:'2px 10px', fontSize:11 }}
                  onClick={() => {
                    const to = new Date();
                    const from = new Date();
                    from.setDate(from.getDate() - q.days);
                    setDateFrom(from.toISOString().slice(0,10));
                    setDateTo(to.toISOString().slice(0,10));
                  }}>
                  {q.label}
                </button>
              ))}
            </div>

            {error && (
              <div style={{ marginTop:10, padding:'8px 12px', background:'rgba(220,38,38,0.1)',
                border:'1px solid rgba(220,38,38,0.3)', borderRadius:6, fontSize:12, color:'#f87171' }}>
                ❌ {error}
              </div>
            )}
          </div>

          {/* Preview */}
          {loading && (
            <div className="card" style={{ textAlign:'center', padding:48 }}>
              <RefreshCw size={24} className="spin" style={{ marginBottom:12 }}/>
              <div style={{ color:'var(--text-muted)' }}>Generating report...</div>
            </div>
          )}

          {preview && !loading && (
            <div className="card">
              <div className="flex-between mb-16">
                <div>
                  <div style={{ fontSize:14, fontWeight:700 }}>Preview — first 20 rows</div>
                  <div style={{ fontSize:11, color:'var(--text-muted)', marginTop:2 }}>
                    {preview.total?.toLocaleString()} total records · {dateFrom} to {dateTo}
                  </div>
                </div>
                <button className="btn btn-primary btn-sm" onClick={downloadReport}>
                  <Download size={13}/> Download Full Report
                </button>
              </div>

              {/* Summary stats if available */}
              {preview.summary && (
                <div style={{ display:'flex', gap:12, flexWrap:'wrap', marginBottom:16 }}>
                  {Object.entries(preview.summary).map(([k,v]) => (
                    <div key={k} style={{ background:'var(--bg-primary)', borderRadius:8,
                      padding:'8px 14px', minWidth:100 }}>
                      <div style={{ fontSize:10, color:'var(--text-muted)', textTransform:'uppercase',
                        letterSpacing:0.5 }}>{k.replace(/_/g,' ')}</div>
                      <div style={{ fontSize:18, fontWeight:700, color:'var(--text-primary)',
                        fontFamily:'var(--font-mono)' }}>{typeof v === 'number' ? v.toLocaleString() : v}</div>
                    </div>
                  ))}
                </div>
              )}

              {/* Data table */}
              {preview.data && preview.data.length > 0 && (
                <div className="table-wrapper">
                  <table>
                    <thead>
                      <tr>
                        {Object.keys(preview.data[0]).map(k => (
                          <th key={k} style={{ fontSize:10 }}>{k.replace(/_/g,' ').toUpperCase()}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {preview.data.map((row, i) => (
                        <tr key={i}>
                          {Object.values(row).map((v, j) => (
                            <td key={j} style={{ fontSize:11, fontFamily: typeof v === 'number' ? 'var(--font-mono)' : undefined }}>
                              {v === null || v === undefined ? '—' :
                               typeof v === 'number' ? v.toLocaleString() : String(v).slice(0,100)}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {!preview && !loading && (
            <div className="card" style={{ textAlign:'center', padding:64 }}>
              <FileText size={40} style={{ opacity:0.15, marginBottom:16 }}/>
              <div style={{ fontSize:14, color:'var(--text-muted)' }}>
                Select a report type and date range, then click Preview
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
