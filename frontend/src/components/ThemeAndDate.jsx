import { useState, useEffect, useRef } from 'react';
import { Sun, Moon, Palette, Calendar, ChevronDown, Check } from 'lucide-react';

// ── THEMES ───────────────────────────────────────────────────
const THEMES = [
  { id:'dark',     label:'Dark',     icon:'🌑', preview:'#0d1117' },
  { id:'worktual', label:'Worktual', icon:'🔷', preview:'#0a0e1a' },
  { id:'light',    label:'Light',    icon:'☀️', preview:'#f6f8fa' },
  { id:'blue',     label:'Ocean',    icon:'🌊', preview:'#060d1f' },
  { id:'midnight', label:'Midnight', icon:'🌃', preview:'#0d0d1f' },
];

export function ThemeSwitcher() {
  const [theme,  setTheme]  = useState(() => localStorage.getItem('em_theme') || 'dark');
  const [open,   setOpen]   = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('em_theme', theme);
  }, [theme]);

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const current = THEMES.find(t => t.id === theme) || THEMES[0];

  return (
    <div ref={ref} style={{ position:'relative' }}>
      <button className="btn btn-ghost btn-sm" onClick={() => setOpen(o => !o)}
        title="Change theme" style={{ gap:6 }}>
        <Palette size={14}/>
        <span style={{ fontSize:12 }}>{current.icon} {current.label}</span>
        <ChevronDown size={11}/>
      </button>

      {open && (
        <div style={{
          position:'absolute', top:'calc(100% + 6px)', right:0,
          background:'var(--bg-card)', border:'1px solid var(--border)',
          borderRadius:10, padding:8, zIndex:1000, width:160,
          boxShadow:'0 8px 32px rgba(0,0,0,0.4)',
        }}>
          <div style={{ fontSize:10, color:'var(--text-muted)', fontWeight:700,
            textTransform:'uppercase', letterSpacing:0.8, padding:'4px 8px 8px' }}>
            Color Theme
          </div>
          {THEMES.map(t => (
            <button key={t.id} onClick={() => { setTheme(t.id); setOpen(false); }}
              style={{
                width:'100%', display:'flex', alignItems:'center', gap:10,
                padding:'8px 10px', background: theme===t.id ? 'rgba(37,99,235,0.12)' : 'transparent',
                border:'none', borderRadius:7, cursor:'pointer',
                color: theme===t.id ? 'var(--accent-blue-light)' : 'var(--text-secondary)',
                fontSize:13, fontFamily:'inherit',
              }}>
              <div style={{ width:16, height:16, borderRadius:4, background:t.preview,
                border:'1px solid var(--border)', flexShrink:0 }}/>
              <span style={{ flex:1, textAlign:'left' }}>{t.icon} {t.label}</span>
              {theme === t.id && <Check size={12} color="var(--accent-blue-light)"/>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── DATE RANGE PICKER ─────────────────────────────────────────
const PRESETS = [
  { label:'Today',       value:'today',    days:0   },
  { label:'Yesterday',   value:'yesterday',days:1   },
  { label:'Last 7 days', value:'7d',       days:7   },
  { label:'Last 30 days',value:'30d',      days:30  },
  { label:'Last 90 days',value:'90d',      days:90  },
  { label:'This month',  value:'month',    days:null },
  { label:'Last month',  value:'lmonth',   days:null },
  { label:'Last 6 months',value:'6m',      days:180 },
  { label:'This year',   value:'year',     days:null },
  { label:'Custom',      value:'custom',   days:null },
];

function getPresetDates(preset) {
  const now   = new Date();
  const today = now.toISOString().slice(0,10);

  switch(preset) {
    case 'today':     return { from: today, to: today };
    case 'yesterday': {
      const d = new Date(now); d.setDate(d.getDate()-1);
      const s = d.toISOString().slice(0,10);
      return { from:s, to:s };
    }
    case '7d': {
      const d = new Date(now); d.setDate(d.getDate()-6);
      return { from: d.toISOString().slice(0,10), to: today };
    }
    case '30d': {
      const d = new Date(now); d.setDate(d.getDate()-29);
      return { from: d.toISOString().slice(0,10), to: today };
    }
    case '90d': {
      const d = new Date(now); d.setDate(d.getDate()-89);
      return { from: d.toISOString().slice(0,10), to: today };
    }
    case '6m': {
      const d = new Date(now); d.setMonth(d.getMonth()-6);
      return { from: d.toISOString().slice(0,10), to: today };
    }
    case 'month': {
      const d = new Date(now.getFullYear(), now.getMonth(), 1);
      return { from: d.toISOString().slice(0,10), to: today };
    }
    case 'lmonth': {
      const s = new Date(now.getFullYear(), now.getMonth()-1, 1);
      const e = new Date(now.getFullYear(), now.getMonth(), 0);
      return { from: s.toISOString().slice(0,10), to: e.toISOString().slice(0,10) };
    }
    case 'year': {
      return { from: `${now.getFullYear()}-01-01`, to: today };
    }
    default: return { from: today, to: today };
  }
}

export function DateRangePicker({ value, onChange, showHours = false }) {
  const [open,    setOpen]    = useState(false);
  const [preset,  setPreset]  = useState('7d');
  const [custom,  setCustom]  = useState({ from:'', to:'' });
  const [hourVal, setHourVal] = useState(24);
  const ref = useRef(null);

  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  const applyPreset = (p) => {
    setPreset(p);
    if (p === 'custom') return;
    const dates = getPresetDates(p);
    onChange?.(dates);
    setOpen(false);
  };

  const applyCustom = () => {
    if (!custom.from || !custom.to) return;
    onChange?.(custom);
    setOpen(false);
  };

  const currentPreset = PRESETS.find(p => p.value === preset);
  const displayLabel  = preset === 'custom'
    ? `${custom.from||'?'} → ${custom.to||'?'}`
    : currentPreset?.label || '7 Days';

  return (
    <div ref={ref} style={{ position:'relative', display:'inline-flex', gap:6 }}>
      {/* Hour selector (for firewall/waveform) */}
      {showHours && (
        <select className="input" style={{ width:80, fontSize:12 }}
          value={hourVal}
          onChange={e => { setHourVal(parseInt(e.target.value)); onChange?.({ hours: parseInt(e.target.value) }); }}>
          <option value={1}>1h</option>
          <option value={6}>6h</option>
          <option value={12}>12h</option>
          <option value={24}>24h</option>
          <option value={48}>2d</option>
          <option value={168}>7d</option>
        </select>
      )}

      {/* Date preset button */}
      {!showHours && (
        <button className="btn btn-ghost btn-sm" onClick={() => setOpen(o => !o)}>
          <Calendar size={13}/>
          <span>{displayLabel}</span>
          <ChevronDown size={11}/>
        </button>
      )}

      {open && !showHours && (
        <div style={{
          position:'absolute', top:'calc(100% + 6px)', right:0,
          background:'var(--bg-card)', border:'1px solid var(--border)',
          borderRadius:10, padding:10, zIndex:1000, width:220,
          boxShadow:'0 8px 32px rgba(0,0,0,0.4)',
        }}>
          <div style={{ fontSize:10, color:'var(--text-muted)', fontWeight:700,
            textTransform:'uppercase', letterSpacing:0.8, padding:'2px 6px 8px' }}>
            Date Range
          </div>
          {PRESETS.filter(p => p.value !== 'custom').map(p => (
            <button key={p.value} onClick={() => applyPreset(p.value)}
              style={{
                width:'100%', display:'flex', alignItems:'center', justifyContent:'space-between',
                padding:'7px 8px', background: preset===p.value ? 'rgba(37,99,235,0.12)' : 'transparent',
                border:'none', borderRadius:6, cursor:'pointer',
                color: preset===p.value ? 'var(--accent-blue-light)' : 'var(--text-secondary)',
                fontSize:13, fontFamily:'inherit',
              }}>
              {p.label}
              {preset === p.value && <Check size={11} color="var(--accent-blue-light)"/>}
            </button>
          ))}
          <div style={{ borderTop:'1px solid var(--border)', marginTop:8, paddingTop:8 }}>
            <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:6 }}>Custom range</div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:6 }}>
              <input type="date" className="input" style={{ fontSize:11 }}
                value={custom.from} onChange={e=>setCustom(p=>({...p,from:e.target.value}))}/>
              <input type="date" className="input" style={{ fontSize:11 }}
                value={custom.to}   onChange={e=>setCustom(p=>({...p,to:e.target.value}))}/>
            </div>
            <button className="btn btn-primary btn-sm" onClick={applyCustom}
              style={{ width:'100%', marginTop:8 }} disabled={!custom.from||!custom.to}>
              Apply Custom Range
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── ICON MAP for dashboard KPI sections ───────────────────────
export const DASHBOARD_ICONS = {
  total:       { emoji:'📊', color:'#2563eb' },
  inbound:     { emoji:'📥', color:'#0891b2' },
  outbound:    { emoji:'📤', color:'#059669' },
  delivered:   { emoji:'✅', color:'#16a34a' },
  blocked:     { emoji:'🚫', color:'#dc2626' },
  failed:      { emoji:'❌', color:'#ef4444' },
  bounced:     { emoji:'↩️', color:'#d97706' },
  deferred:    { emoji:'⏳', color:'#7c3aed' },
  spam:        { emoji:'⚠️', color:'#f59e0b' },
  threats:     { emoji:'🛡️', color:'#be185d' },
  quarantine:  { emoji:'🔒', color:'#0891b2' },
  wronghits:   { emoji:'💥', color:'#f97316' },
  timedout:    { emoji:'⏰', color:'#6b7280' },
  invalid:     { emoji:'🗑️', color:'#9ca3af' },
  clean:       { emoji:'✨', color:'#4ade80' },
  queue:       { emoji:'📋', color:'#60a5fa' },
  ssh:         { emoji:'🔑', color:'#dc2626' },
  firewall:    { emoji:'🔥', color:'#f97316' },
  banned:      { emoji:'🔨', color:'#ef4444' },
  countries:   { emoji:'🌍', color:'#0891b2' },
};
