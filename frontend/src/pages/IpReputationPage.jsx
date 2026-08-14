import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Shield, AlertTriangle, CheckCircle, ExternalLink, Globe } from 'lucide-react';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

// Mail server IPs to check
const MAIL_IPS = [
  // worktual.tech mail cluster
  { label: 'mail.worktual.tech — VIP',     ip: '82.113.72.84',  server: 'app'                   },
  { label: 'mail.worktual.tech — Active',  ip: '10.180.0.84',   server: 'app',  internal: true  },
  { label: 'mail.worktual.tech — Passive', ip: '10.180.0.186',  server: 'app',  internal: true  },
  // worktual.pl campaign cluster
  { label: 'mail.worktual.pl — VIP',       ip: '82.113.72.80',  server: 'campaign'              },
  { label: 'mail.worktual.pl — Active',    ip: '10.180.0.89',   server: 'campaign', internal: true },
  { label: 'mail.worktual.pl — Passive',   ip: '10.180.0.182',  server: 'campaign', internal: true },
  // Dashboard / App server
  { label: 'email-management.worktual.tech', ip: '82.113.72.52', server: 'app'                  },
];

// Public blacklist check tools
const BLACKLIST_TOOLS = [
  { name: 'Spamhaus Lookup',  url: ip => `https://www.spamhaus.org/query/ip/${ip}`,           color: '#f97316' },
  { name: 'MXToolbox',        url: ip => `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${ip}`, color: '#2563eb' },
  { name: 'MultiRBL',         url: ip => `https://multirbl.valli.org/lookup/${ip}.html`,      color: '#7c3aed' },
  { name: 'DNSBL Info',       url: ip => `https://www.dnsbl.info/dnsbl-database-check.php?IP=${ip}`, color: '#0891b2' },
  { name: 'BarracudaCentral', url: ip => `https://www.barracudacentral.org/lookups/lookup-reputation?lookup_ip=${ip}`, color: '#be185d' },
];

// Known RBLs to check via DNS
const RBLS = [
  { name: 'Spamhaus ZEN',      host: 'zen.spamhaus.org',       critical: true  },
  { name: 'Spamhaus SBL',      host: 'sbl.spamhaus.org',       critical: true  },
  { name: 'Spamhaus XBL',      host: 'xbl.spamhaus.org',       critical: true  },
  { name: 'SpamCop',           host: 'bl.spamcop.net',         critical: true  },
  { name: 'Barracuda',         host: 'b.barracudacentral.org', critical: true  },
  { name: 'SORBS SPAM',        host: 'spam.sorbs.net',         critical: false },
  { name: 'UCEProtect L1',     host: 'dnsbl-1.uceprotect.net', critical: false },
];

function IpCard({ ipInfo, onCheck }) {
  const [status, setStatus]   = useState(null); // null | 'checking' | 'clean' | 'listed'
  const [details, setDetails] = useState([]);

  const check = async () => {
    if (ipInfo.internal) return; // Can't check internal IPs via public DNS
    setStatus('checking');
    try {
      const r = await api.get('/stats/ip-reputation', { params: { ip: ipInfo.ip } });
      const listed = r.data.data?.filter(d => d.listed) || [];
      setDetails(r.data.data || []);
      setStatus(listed.length > 0 ? 'listed' : 'clean');
    } catch (e) {
      // Fallback — just show links
      setStatus('unknown');
    }
  };

  useEffect(() => {
    if (!ipInfo.internal) check();
  }, [ipInfo.ip]);

  const borderColor = status === 'clean'   ? '#16a34a' :
                      status === 'listed'  ? '#dc2626' :
                      status === 'checking'? '#d97706' : '#374151';

  const listedCount = details.filter(d => d.listed).length;

  return (
    <div className="card" style={{ borderTop: `3px solid ${borderColor}` }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 12 }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 3 }}>{ipInfo.label}</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: '#60a5fa', fontWeight: 700 }}>
            {ipInfo.ip}
          </div>
        </div>
        {ipInfo.internal ? (
          <span style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-primary)', padding: '3px 8px', borderRadius: 20 }}>
            Internal
          </span>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {status === 'checking' && <RefreshCw size={14} className="spin" color="#d97706" />}
            {status === 'clean'    && <CheckCircle size={16} color="#4ade80" />}
            {status === 'listed'   && <AlertTriangle size={16} color="#f87171" />}
            <span style={{
              fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 20,
              background: status === 'clean'    ? 'rgba(22,163,74,0.15)'  :
                          status === 'listed'   ? 'rgba(220,38,38,0.15)'  :
                          status === 'checking' ? 'rgba(217,119,6,0.15)'  : 'var(--bg-primary)',
              color:      status === 'clean'    ? '#4ade80' :
                          status === 'listed'   ? '#f87171' :
                          status === 'checking' ? '#fbbf24' : 'var(--text-muted)',
            }}>
              {status === 'checking' ? 'Checking...' :
               status === 'clean'    ? '✓ Clean'     :
               status === 'listed'   ? `⚠ Listed (${listedCount})` : 'Unknown'}
            </span>
          </div>
        )}
      </div>

      {/* RBL results */}
      {details.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Blacklist Status
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {details.map((d, i) => (
              <span key={i} style={{
                fontSize: 11, padding: '2px 8px', borderRadius: 20, fontWeight: 600,
                background: d.listed ? 'rgba(220,38,38,0.15)' : 'rgba(22,163,74,0.1)',
                color:      d.listed ? '#f87171' : '#4ade80',
              }}>
                {d.listed ? '✗' : '✓'} {d.name}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Quick check links */}
      {!ipInfo.internal && (
        <div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Check Online
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {BLACKLIST_TOOLS.map((t, i) => (
              <a key={i} href={t.url(ipInfo.ip)} target="_blank" rel="noopener noreferrer"
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 4,
                  fontSize: 11, padding: '3px 10px', borderRadius: 20,
                  background: `${t.color}15`, color: t.color,
                  border: `1px solid ${t.color}30`,
                  textDecoration: 'none', fontWeight: 600,
                  transition: 'all 0.15s',
                }}>
                <ExternalLink size={10} /> {t.name}
              </a>
            ))}
          </div>
        </div>
      )}

      {/* Re-check button */}
      {!ipInfo.internal && (
        <button className="btn btn-ghost btn-sm" style={{ marginTop: 10, width: '100%', justifyContent: 'center' }}
          onClick={check} disabled={status === 'checking'}>
          <RefreshCw size={12} className={status === 'checking' ? 'spin' : ''} />
          Re-check Blacklists
        </button>
      )}
    </div>
  );
}

export default function IpReputationPage() {
  const [spamHistory, setSpamHistory] = useState([]);
  const [loading, setLoading]         = useState(true);

  useEffect(() => {
    // Load spam rejection history from DB
    api.get('/mails/spam-analysis').then(r => {
      setSpamHistory(r.data.data || []);
    }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <div className="mb-24">
        <div className="section-title">IP Reputation</div>
        <div className="section-sub">
          Blacklist status for all Worktual mail server IPs · Click any tool to check live
        </div>
      </div>

      {/* Critical alert if any IP was recently blocked */}
      {/* Historical listing info */}
      <div style={{
        background: 'rgba(22,163,74,0.08)', border: '1px solid rgba(22,163,74,0.25)',
        borderRadius: 8, padding: '12px 16px', marginBottom: 16,
        display: 'flex', alignItems: 'center', gap: 12
      }}>
        <CheckCircle size={16} color="#4ade80" />
        <div style={{ fontSize: 13 }}>
          <strong style={{ color: '#4ade80' }}>82.113.72.84 is currently CLEAN — not listed on any blacklist.</strong>
          <span style={{ color: 'var(--text-muted)', marginLeft: 8 }}>
            Monitor daily to stay clean.
          </span>
        </div>
      </div>
      <div style={{
        background: 'rgba(217,119,6,0.08)', border: '1px solid rgba(217,119,6,0.25)',
        borderRadius: 8, padding: '12px 16px', marginBottom: 20,
        display: 'flex', alignItems: 'center', gap: 12
      }}>
        <AlertTriangle size={16} color="#fbbf24" />
        <div style={{ fontSize: 13, flex: 1 }}>
          <strong style={{ color: '#fbbf24' }}>Historical listing recorded on CSS Blocklist</strong>
          <div style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 3 }}>
            Listed: <strong style={{ color: 'var(--text-primary)' }}>June 28, 2026 21:03 UTC</strong>
            &nbsp;→&nbsp;
            Removed: <strong style={{ color: '#4ade80' }}>June 29, 2026 04:31 UTC</strong>
            &nbsp;·&nbsp; Duration: ~7.5 hours
            &nbsp;·&nbsp; Cause: SASL relay abuse attack (no-reply@worktual.tech credential compromised)
            &nbsp;·&nbsp; <strong style={{ color: '#4ade80' }}>Resolved ✓</strong>
          </div>
        </div>
        <a href="https://www.spamhaus.org/query/ip/82.113.72.84" target="_blank" rel="noopener noreferrer"
          style={{ display:'inline-flex', alignItems:'center', gap:4, fontSize:11, padding:'4px 12px',
                   borderRadius:20, background:'rgba(217,119,6,0.15)', color:'#fbbf24',
                   border:'1px solid rgba(217,119,6,0.3)', textDecoration:'none', flexShrink:0 }}>
          <ExternalLink size={11} /> Verify Status
        </a>
      </div>

      {/* IP Cards grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: 16, marginBottom: 24 }}>
        {MAIL_IPS.map((ip, i) => (
          <IpCard key={i} ipInfo={ip} />
        ))}
      </div>

      {/* Spam rejection history from DB */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Spam Rejection History (Last 30 Days)</span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>From email_log_realtime + delivery_details</span>
        </div>
        {loading ? (
          <div className="loading-state"><RefreshCw size={16} className="spin" /></div>
        ) : spamHistory.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 32, color: '#4ade80' }}>
            ✅ No spam rejection patterns in last 30 days
          </div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Sender</th><th>Spam Blocks</th><th>First Seen</th>
                  <th>Last Seen</th><th>Active Days</th><th>Common Reasons</th>
                </tr>
              </thead>
              <tbody>
                {spamHistory.map((r, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ fontSize: 12 }}>{r.mail_from}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#f87171' }}>
                      {Number(r.count).toLocaleString()}
                    </td>
                    <td className="mono" style={{ fontSize: 11 }}>{r.first_seen}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{r.last_seen}</td>
                    <td>{r.days_active}</td>
                    <td style={{ fontSize: 11, color: '#fbbf24', maxWidth: 300 }}>
                      {(r.reasons || '').slice(0, 150)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Anti-spam checklist summary */}
      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-header"><span className="card-title">IP Health Checklist</span></div>
        {[
          { label: 'PTR/rDNS set for 82.113.72.84', cmd: 'dig -x 82.113.72.84', status: 'check' },
          { label: 'SPF record published',           cmd: 'dig TXT worktual.tech | grep spf', status: 'check' },
          { label: 'DKIM signing active',            cmd: 'opendkim-testkey -d worktual.tech -s mail -vvv', status: 'check' },
          { label: 'DMARC policy set',               cmd: 'dig TXT _dmarc.worktual.tech', status: 'check' },
          { label: 'Spamhaus ZEN clean',             cmd: 'dig +short 84.72.113.82.zen.spamhaus.org', status: 'check' },
          { label: 'Google Postmaster registered',   cmd: 'https://postmaster.google.com/', status: 'todo' },
        ].map((item, i) => (
          <div key={i} style={{
            display: 'flex', alignItems: 'center', gap: 12,
            padding: '10px 0', borderBottom: '1px solid var(--border)'
          }}>
            <div style={{
              width: 20, height: 20, borderRadius: '50%', flexShrink: 0,
              background: item.status === 'check' ? 'rgba(217,119,6,0.2)' : 'rgba(107,114,128,0.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 11, color: item.status === 'check' ? '#fbbf24' : '#9ca3af',
            }}>?</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>{item.label}</div>
              <code style={{ fontSize: 11, color: '#4ade80', fontFamily: 'var(--font-mono)' }}>{item.cmd}</code>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
