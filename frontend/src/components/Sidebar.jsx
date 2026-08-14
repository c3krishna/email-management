import { useState } from 'react';
import {
  BarChart3, Mail, AlertTriangle, Shield, Megaphone,
  Bell, Users, Inbox, GitCompare, List, Clock,
  Globe, ChevronDown, ChevronRight, Activity,
  FileText, Settings, ShieldAlert, Filter, Building
, Cpu , Code , Bug } from 'lucide-react';

const NAV_SECTIONS = [
  {
    section: 'DASHBOARD',
    items: [
      { id: 'dashboard', label: 'Overview', icon: BarChart3 },
    ]
  },
  {
    section: 'EMAIL LOGS',
    items: [
      { id: 'email-logs',      label: 'Email Logs',      icon: List,        badge: 'LIVE', badgeColor: '#16a34a' },
      { id: 'threats',         label: 'Threats',         icon: ShieldAlert, badge: 'NEW',  badgeColor: '#be185d' },
      { id: 'quarantine',      label: 'Quarantine',      icon: Filter       },
      { id: 'delivery-status', label: 'Delivery Status', icon: Clock        },
    ]
  },
  {
    section: 'ANALYTICS',
    items: [
      { id: 'campaigns',   label: 'Campaign Reports',  icon: Megaphone     },
      { id: 'spam-analysis', label: 'Spam Analysis',  icon: ShieldAlert },
      { id: 'reporting',   label: 'Reporting',         icon: FileText      },
      { id: 'compare',     label: 'Queue vs Delivery', icon: GitCompare    },
      { id: 'problematic', label: 'Bounce Analysis',   icon: AlertTriangle },
    ]
  },
  {
    section: 'MANAGEMENT',
    items: [
      { id: 'mails',    label: 'All Mails', icon: Mail  },
      { id: 'inbox',    label: 'Inbox',     icon: Inbox, roles: ['super_admin','admin'] },
      { id: 'policies', label: 'Policies',  icon: FileText },
    ]
  },
  {
    section: 'SECURITY',
    items: [
      { id: 'platform-overview', label: 'Platform Overview', icon: Globe },
      { id: 'vr-platform', label: 'VR Threat Platform', icon: Shield },
      { id: 'ai-orchestration', label: 'AI Orchestration', icon: Cpu },
      { id: 'validation-api', label: 'Validation API', icon: Code },
      { id: 'threat-intelligence-platform', label: 'Threat Intelligence', icon: Shield },
      { id: 'threat-management', label: 'AI Threat Engine',    icon: ShieldAlert },
      { id: 'vip-protection', label: 'VIP Protection', icon: ShieldAlert, badge: 'NEW', badgeColor: '#0891b2' },
      { id: 'mailbox-monitors', label: 'Mailbox Monitors', icon: Inbox, roles: ['super_admin','admin'] },
      { id: 'wazuh-siem', label: 'Wazuh SIEM', icon: Bug },
      { id: 'firewall', label: 'Firewall Security', icon: Shield },
      { id: 'spamguard',         label: 'Spam Guard',          icon: Shield      },
      { id: 'ip-reputation',     label: 'IP Reputation',       icon: Globe, roles: ['super_admin','admin'] },
    ]
  },
  {
    section: 'MONITORING',
    items: [
      { id: 'alerts',   label: 'Alerts',   icon: Bell     },
      { id: 'settings', label: 'Settings', icon: Settings, roles: ['super_admin'] },
    ]
  },
  {
    section: 'ADMIN',
    items: [
      { id: 'customers', label: 'Customers',       icon: Building, roles: ['super_admin']        },
      { id: 'users',     label: 'User Management', icon: Users,    roles: ['super_admin','admin'] },
    ]
  },
];

const QUICK_LINKS = [
  { id: 'top-senders',     label: 'Top Senders',    icon: BarChart3 },
  { id: 'top-recipients',  label: 'Top Recipients', icon: Users     },
  { id: 'threat-map',      label: 'Threat Map',     icon: Globe     },
];

const ROLE_COLORS = {
  super_admin: { bg: 'rgba(249,115,22,0.15)', color: '#f97316' },
  admin:       { bg: 'rgba(96,165,250,0.15)', color: '#60a5fa' },
  viewer:      { bg: 'rgba(74,222,128,0.15)', color: '#4ade80' },
};

export default function Sidebar({ activePage, onNavigate, alertCount, user, onLogout, agentStatus, mobileOpen}) {
  const [collapsed, setCollapsed] = useState({});
  const toggle = s => setCollapsed(p => ({ ...p, [s]: !p[s] }));
  const canSee = item => !item.roles || (user?.role && item.roles.includes(user.role));

  return (
    <div className={`sidebar${mobileOpen ? ' open' : ''}`} style={{ display:'flex', flexDirection:'column', height:'100vh', userSelect:'none' }}>

      {/* Logo */}
      <div className="sidebar-logo" style={{ flexShrink:0 }}>
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <div style={{ width:36, height:36, borderRadius:8, flexShrink:0,
            background:'linear-gradient(135deg,#0891b2,#0d1220)',
            display:'flex', alignItems:'center', justifyContent:'center', fontSize:18 }}>📧</div>
          <div>
            <div style={{ fontSize:13, fontWeight:700, color:'var(--text-primary)' }}>Email Management</div>
            <div style={{ fontSize:10, color:'var(--text-muted)' }}>Email Security Gateway</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <div style={{ flex:1, overflowY:'auto', overflowX:'hidden' }}>
        {NAV_SECTIONS.map(({ section, items }) => {
          const visible = items.filter(canSee);
          if (!visible.length) return null;
          const isColl = collapsed[section];
          return (
            <div key={section}>
              <div onClick={() => toggle(section)} style={{
                display:'flex', alignItems:'center', justifyContent:'space-between',
                padding:'8px 16px 3px', cursor:'pointer' }}>
                <span style={{ fontSize:10, fontWeight:700, color:'var(--text-muted)',
                  letterSpacing:1, textTransform:'uppercase' }}>{section}</span>
                {isColl ? <ChevronRight size={10} color="var(--text-muted)"/> : <ChevronDown size={10} color="var(--text-muted)"/>}
              </div>
              {!isColl && visible.map(item => {
                const Icon = item.icon;
                const isActive = activePage === item.id;
                return (
                  <button key={item.id} onClick={() => onNavigate(item.id)} style={{
                    width:'100%', display:'flex', alignItems:'center', gap:9,
                    padding:'8px 16px 8px 13px', border:'none', cursor:'pointer', textAlign:'left',
                    background: isActive ? 'rgba(37,99,235,0.12)' : 'transparent',
                    color: isActive ? '#60a5fa' : 'var(--text-secondary)',
                    borderLeft: `3px solid ${isActive ? 'var(--accent-blue)' : 'transparent'}`,
                    fontSize:13, fontWeight: isActive ? 600 : 400,
                  }}>
                    <Icon size={15} style={{ flexShrink:0 }}/>
                    <span style={{ flex:1 }}>{item.label}</span>
                    {item.badge && (
                      <span style={{ fontSize:9, fontWeight:700, padding:'1px 5px', borderRadius:10,
                        background:`${item.badgeColor}22`, color:item.badgeColor,
                        border:`1px solid ${item.badgeColor}44` }}>{item.badge}</span>
                    )}
                    {item.id === 'alerts' && alertCount > 0 && (
                      <span style={{ fontSize:10, fontWeight:700, padding:'1px 6px', borderRadius:10,
                        background:'var(--danger)', color:'#fff' }}>{alertCount}</span>
                    )}
                  </button>
                );
              })}
            </div>
          );
        })}

        {/* Quick Links */}
        <div style={{ marginTop:8 }}>
          <div style={{ padding:'8px 16px 3px' }}>
            <span style={{ fontSize:10, fontWeight:700, color:'var(--text-muted)',
              letterSpacing:1, textTransform:'uppercase' }}>QUICK LINKS</span>
          </div>
          {QUICK_LINKS.map(item => {
            const Icon = item.icon;
            const isActive = activePage === item.id;
            return (
              <button key={item.id} onClick={() => onNavigate(item.id)} style={{
                width:'100%', display:'flex', alignItems:'center', gap:9,
                padding:'7px 16px 7px 13px', border:'none', cursor:'pointer',
                background: isActive ? 'rgba(37,99,235,0.12)' : 'transparent',
                color: isActive ? '#60a5fa' : 'var(--text-muted)',
                borderLeft: `3px solid ${isActive ? 'var(--accent-blue)' : 'transparent'}`,
                fontSize:12, fontWeight:400, textAlign:'left' }}>
                <Icon size={14} style={{ flexShrink:0 }}/>
                {item.label}
              </button>
            );
          })}
        </div>

        {/* Agent status */}
        {agentStatus && (
          <div style={{ margin:'12px 12px 0', background:'var(--bg-secondary)',
            borderRadius:8, padding:'10px 12px', border:'1px solid var(--border)' }}>
            <div style={{ fontSize:10, color:'var(--text-muted)', textTransform:'uppercase',
              letterSpacing:0.8, marginBottom:6 }}>Live Agents</div>
            {[
              { key:'app',      label:'mail.worktual.tech' },
              { key:'campaign', label:'mail.worktual.pl'   },
            ].map(s => {
              const online = agentStatus?.[s.key]?.online;
              const qCount = agentStatus?.[s.key]?.queue?.queue_count || 0;
              return (
                <div key={s.key} style={{ display:'flex', alignItems:'center', gap:7, marginBottom:5 }}>
                  <div style={{ width:7, height:7, borderRadius:'50%', flexShrink:0,
                    background: online ? '#4ade80' : '#6b7280',
                    boxShadow: online ? '0 0 5px #4ade80' : 'none' }}/>
                  <span style={{ fontSize:11, flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap',
                    color: online ? 'var(--text-primary)' : 'var(--text-muted)' }}>{s.label}</span>
                  {qCount > 0 && <span style={{ fontSize:10, color:'#fbbf24', fontFamily:'var(--font-mono)' }}>{qCount}q</span>}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Bottom */}
      <div style={{ flexShrink:0, borderTop:'1px solid var(--border)', padding:'10px 14px' }}>
        {user && (
          <div style={{ marginBottom:10 }}>
            <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:5 }}>
              <div style={{ width:28, height:28, borderRadius:'50%', flexShrink:0,
                background:'linear-gradient(135deg,#0891b2,#0d1220)',
                display:'flex', alignItems:'center', justifyContent:'center',
                fontSize:12, fontWeight:700, color:'#fff' }}>
                {(user.name||'A').charAt(0).toUpperCase()}
              </div>
              <div style={{ minWidth:0 }}>
                <div style={{ fontSize:12, fontWeight:600, color:'var(--text-primary)',
                  overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{user.name}</div>
                <div style={{ fontSize:10, color:'var(--text-muted)',
                  overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{user.email}</div>
              </div>
            </div>
            <span style={{ display:'inline-block', fontSize:10, fontWeight:700,
              padding:'2px 8px', borderRadius:20,
              background: ROLE_COLORS[user.role]?.bg || 'rgba(107,114,128,0.2)',
              color:      ROLE_COLORS[user.role]?.color || '#9ca3af' }}>
              {(user.role||'').replace('_',' ').toUpperCase()}
            </span>
          </div>
        )}
        <div style={{ display:'flex', alignItems:'center', gap:6, marginBottom:4 }}>
          <Activity size={11} color="#4ade80"/>
          <span style={{ fontSize:11, color:'#4ade80', fontWeight:600 }}>All Systems Operational</span>
        </div>
        <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:8, lineHeight:1.5 }}>
          Postfix · Dovecot · OpenDKIM<br/>
          Worktual Innovations, Chennai
        </div>
        <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:8 }}>Version 2.1.0</div>
        {onLogout && (
          <button onClick={onLogout} style={{
            width:'100%', padding:'6px 0', fontSize:12, fontWeight:500,
            background:'rgba(220,38,38,0.1)', color:'#f87171',
            border:'1px solid rgba(220,38,38,0.2)', borderRadius:6, cursor:'pointer' }}>
            Sign Out
          </button>
        )}
      </div>
    </div>
  );
}
