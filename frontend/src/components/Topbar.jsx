import { Calendar } from 'lucide-react';
import { ThemeSwitcher } from './ThemeAndDate';

const PAGE_LABELS = {
  dashboard:        'Dashboard Overview',
  'email-logs':     'Email Logs',
  threats:          'Threat Intelligence',
  quarantine:       'Quarantine',
  'delivery-status':'Delivery Status',
  campaigns:        'Campaign Analytics',
  reporting:        'Reporting',
  analytics:        'Analytics',
  compare:          'Queue vs Delivery',
  problematic:      'Bounce Analysis',
  mails:            'All Mails',
  inbox:            'Inbox',
  policies:         'Policies',
  'threat-management':'Threat Management',
  firewall:         'Firewall Security',
  spamguard:        'Spam Guard',
  'ip-reputation':  'IP Reputation',
  alerts:           'Alerts & Notifications',
  settings:         'Settings',
  customers:        'Customer Management',
  users:            'User Management',
};

const SERVERS = [
  { id: 'app',      label: 'App Mail',  color: '#0891b2', desc: 'Transactional' },
  { id: 'campaign', label: 'Campaign',  color: '#ea580c', desc: 'Bulk Mail'     },
];

export default function Topbar({
  page,
  range, setRange,
  selectedDate, setSelectedDate,
  dateFrom, setDateFrom,
  dateTo, setDateTo,
  server, setServer,
  user, onLogout
}) {
  const showDateFilters = [
    'dashboard','mails','problematic','campaigns',
    'email-logs','reporting','analytics','compare'
  ].includes(page);

  return (
    <div className="topbar" style={{ flexWrap:'wrap', gap:10 }}>

      {/* Page title */}
      <div style={{ flex:1, minWidth:140 }}>
        <div style={{ fontSize:16, fontWeight:700 }}>
          {PAGE_LABELS[page] || (page ? page.replace(/-/g,' ').replace(/\b\w/g,c=>c.toUpperCase()) : 'Dashboard')}
        </div>
      </div>

      {/* Server switcher */}
      <div style={{
        display:'flex', alignItems:'center', gap:4,
        background:'var(--bg-primary)',
        border:'1px solid var(--border)',
        borderRadius:8, padding:'3px 4px'
      }}>
        {SERVERS.map(s => (
          <button key={s.id} onClick={() => setServer(s.id)} style={{
            padding:'4px 12px', borderRadius:6,
            border:'none', cursor:'pointer',
            fontSize:12, fontWeight:600,
            background: server===s.id ? s.color : 'transparent',
            color:      server===s.id ? '#ffffff' : 'var(--text-muted)',
            transition: 'all 0.15s', lineHeight:1.4
          }}>
            {s.label}
            <span style={{ display:'block', fontSize:10, fontWeight:400,
              opacity: server===s.id ? 0.85 : 0.6 }}>{s.desc}</span>
          </button>
        ))}
      </div>

      {/* Date range filters */}
      {showDateFilters && (
        <div className="filter-bar">
          {[
            { val:'today', label:'Today'   },
            { val:'7d',    label:'7 Days'  },
            { val:'30d',   label:'30 Days' },
            { val:'custom',label:'Custom'  },
          ].map(r => (
            <button key={r.val}
              className={`btn btn-sm ${range===r.val ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setRange(r.val)}>
              {r.label}
            </button>
          ))}
          {range === 'today' && (
            <input type="date" className="input" style={{ width:160 }}
              value={selectedDate}
              onChange={e => setSelectedDate(e.target.value)}/>
          )}
          {range === 'custom' && (
            <>
              <input type="date" className="input" style={{ width:150 }}
                value={dateFrom} onChange={e => setDateFrom(e.target.value)}/>
              <span style={{ color:'var(--text-muted)' }}>to</span>
              <input type="date" className="input" style={{ width:150 }}
                value={dateTo} onChange={e => setDateTo(e.target.value)}/>
            </>
          )}
        </div>
      )}

      {/* Theme switcher */}
      <ThemeSwitcher />

      {/* Clock */}
      <div style={{ display:'flex', alignItems:'center', gap:6,
        fontSize:12, color:'var(--text-muted)', whiteSpace:'nowrap' }}>
        <Calendar size={12}/>
        {new Date().toLocaleString('en-IN', {
          timeZone:'Asia/Kolkata',
          dateStyle:'medium', timeStyle:'short'
        })} IST
      </div>
    </div>
  );
}
