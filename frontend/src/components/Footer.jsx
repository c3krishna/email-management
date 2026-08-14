import { Activity, Shield, Mail, ExternalLink } from 'lucide-react';

const YEAR = new Date().getFullYear();

export default function Footer({ agentStatus = null }) {
  const allOnline = agentStatus?.app?.online && agentStatus?.campaign?.online;
  const anyOnline = agentStatus?.app?.online  || agentStatus?.campaign?.online;

  return (
    <footer className="app-footer-bar" style={{
      background:    'var(--bg-secondary)',
      borderTop:     '1px solid var(--border)',
      padding:       '10px 24px',
      display:       'flex',
      alignItems:    'center',
      justifyContent:'space-between',
      flexWrap:      'wrap',
      gap:           '8px',
      fontSize:      '11px',
      color:         'var(--text-muted)',
    }}>
      {/* Left: brand + copyright */}
      <div style={{ display:'flex', alignItems:'center', gap:12, flexWrap:'wrap' }}>
        <div style={{ display:'flex', alignItems:'center', gap:7 }}>
          <div style={{
            width:20, height:20, borderRadius:5, fontSize:11,
            background:'linear-gradient(135deg,#2563eb,#7c3aed)',
            display:'flex', alignItems:'center', justifyContent:'center',
          }}>📧</div>
          <span style={{ fontWeight:700, color:'var(--text-secondary)' }}>
            Worktual Email Management
          </span>
        </div>
        <span>© {YEAR} Worktual Innovations Pvt Ltd · Chennai, India</span>
        <span style={{ color:'var(--border-strong)' }}>·</span>
        <span>Version 2.1.0</span>
        <span style={{ color:'var(--border-strong)' }}>·</span>
        <span>All rights reserved</span>
      </div>

      {/* Center: quick links */}
      <div style={{ display:'flex', gap:14 }}>
        {[
          { label:'MiniAI',       url:'https://miniai.worktual.tech'      },
          { label:'VoiceMG',      url:'https://voicemg.worktual.tech'     },
          { label:'BackupVault',  url:'https://backupvault.worktual.tech' },
          { label:'ServerVault',  url:'https://servers.worktual.tech'     },
        ].map(l=>(
          <a key={l.label} href={l.url} target="_blank" rel="noreferrer"
            style={{ color:'var(--text-muted)', textDecoration:'none', fontSize:11 }}
            onMouseOver={e=>e.target.style.color='var(--text-primary)'}
            onMouseOut={e=>e.target.style.color='var(--text-muted)'}>
            {l.label}
          </a>
        ))}
      </div>

      {/* Right: status */}
      <div style={{ display:'flex', alignItems:'center', gap:14 }}>
        {[
          { label:'App Mail',  online: agentStatus?.app?.online      },
          { label:'Campaign',  online: agentStatus?.campaign?.online  },
        ].map(s=>(
          <div key={s.label} style={{ display:'flex', alignItems:'center', gap:5 }}>
            <Mail size={10}/>
            <span>{s.label}</span>
            <div style={{
              width:6, height:6, borderRadius:'50%',
              background: s.online ? '#4ade80' : '#6b7280',
              boxShadow:  s.online ? '0 0 4px #4ade80' : 'none',
            }}/>
          </div>
        ))}

        <div style={{ display:'flex', alignItems:'center', gap:5,
          fontWeight:600, color:'#4ade80' }}>
          <Activity size={10}/>
          {allOnline ? 'All Systems Operational'
            : anyOnline ? 'Partial Outage'
            : agentStatus ? 'Checking...'
            : 'All Systems Operational'}
        </div>

        <div style={{
          display:'flex', alignItems:'center', gap:4,
          background:'rgba(37,99,235,0.1)', border:'1px solid rgba(37,99,235,0.25)',
          padding:'2px 8px', borderRadius:20, fontSize:10, fontWeight:600, color:'#60a5fa',
        }}>
          <Shield size={9}/> Secured by iptables + Fail2Ban
        </div>
      </div>
    </footer>
  );
}
