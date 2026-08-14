import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, TrendingUp, Users, Download } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell
} from 'recharts';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('em_token');
  if (t) cfg.headers['Authorization'] = `Bearer ${t}`;
  return cfg;
});

const TT = { background:'#0d1117', border:'1px solid #2d3748', borderRadius:8, fontSize:12 };
const COLORS = ['#2563eb','#7c3aed','#0891b2','#d97706','#dc2626','#16a34a','#be185d','#0e7490'];

export default function AnalyticsPage({ server, defaultTab = 'senders' }) {
  const [activeTab, setActiveTab] = useState(defaultTab);
  const [senders,    setSenders]   = useState([]);
  const [recipients, setRecipients]= useState([]);
  const [loading,    setLoading]   = useState(true);
  const [days,       setDays]      = useState(7);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [s, r] = await Promise.all([
        api.get('/stats/top-senders',    { params: { server, limit: 20, days } }),
        api.get('/stats/top-recipients', { params: { server, limit: 20, days } }),
      ]);
      setSenders(   (s.data.data || s.data || []).map(x => ({
        ...x,
        label: (x.mail_from || x.sender || x.email || '').slice(0, 35),
        count: Number(x.count || x.total || x.email_count || 0),
      })));
      setRecipients((r.data.data || r.data || []).map(x => ({
        ...x,
        label: (x.mail_to || x.recipient || x.email || '').slice(0, 35),
        count: Number(x.count || x.total || x.email_count || 0),
      })));
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  }, [server, days]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setActiveTab(defaultTab); }, [defaultTab]);

  const exportCSV = (data, filename) => {
    const csv = ['Email,Count', ...data.map(d=>`${d.label},${d.count}`)].join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
    a.download = filename;
    a.click();
  };

  const renderList = (data, type) => (
    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
      {/* Bar chart */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Top {type} — bar chart</span>
        </div>
        <ResponsiveContainer width="100%" height={360}>
          <BarChart data={data.slice(0,10)} layout="vertical"
            margin={{top:4,right:20,left:0,bottom:0}}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" horizontal={false}/>
            <XAxis type="number" tick={{fill:'#6e7681',fontSize:10}} allowDecimals={false}/>
            <YAxis dataKey="label" type="category" width={180}
              tick={{fill:'#8b949e',fontSize:10}} tickLine={false}/>
            <Tooltip contentStyle={TT}/>
            <Bar dataKey="count" radius={[0,4,4,0]} name="Emails">
              {data.slice(0,10).map((_,i)=>(
                <Cell key={i} fill={COLORS[i % COLORS.length]}/>
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Table */}
      <div className="card">
        <div className="flex-between mb-12">
          <span className="card-title">Full list ({data.length})</span>
          <button className="btn btn-ghost btn-sm"
            onClick={()=>exportCSV(data, `top-${type.toLowerCase()}-${new Date().toISOString().slice(0,10)}.csv`)}>
            <Download size={13}/> CSV
          </button>
        </div>
        <div className="table-wrapper">
          <table>
            <thead><tr>
              <th>#</th><th>{type === 'Senders' ? 'Sender' : 'Recipient'}</th>
              <th>Emails</th><th>Share</th>
            </tr></thead>
            <tbody>
              {data.map((d,i) => {
                const total = data.reduce((a,x)=>a+x.count,0);
                const pct   = total > 0 ? (d.count/total*100).toFixed(1) : 0;
                return (
                  <tr key={i}>
                    <td style={{fontFamily:'var(--font-mono)',fontSize:11,color:'var(--text-muted)',width:32}}>
                      {i+1}
                    </td>
                    <td style={{maxWidth:260}}>
                      <div style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',fontSize:12}}
                        title={d.label}>{d.label||'—'}</div>
                    </td>
                    <td style={{fontFamily:'var(--font-mono)',fontWeight:700,fontSize:13,
                      color:COLORS[Math.min(i,COLORS.length-1)]}}>
                      {d.count.toLocaleString()}
                    </td>
                    <td>
                      <div style={{display:'flex',alignItems:'center',gap:6}}>
                        <div style={{width:60,height:4,background:'var(--border)',borderRadius:2}}>
                          <div style={{width:`${pct}%`,height:'100%',borderRadius:2,
                            background:COLORS[Math.min(i,COLORS.length-1)]}}/>
                        </div>
                        <span style={{fontSize:11,color:'var(--text-muted)'}}>{pct}%</span>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {data.length===0 && !loading && (
                <tr><td colSpan={4} style={{textAlign:'center',padding:40,color:'var(--text-muted)'}}>
                  No data for this period
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  return (
    <div>
      <div className="flex-between mb-16">
        <div>
          <div className="section-title">Analytics</div>
          <div className="section-sub">Top senders and recipients · {server === 'campaign' ? 'Campaign Mail' : 'App Mail'}</div>
        </div>
        <div style={{display:'flex',gap:8,alignItems:'center'}}>
          {[7,30,90].map(d=>(
            <button key={d} className={`btn btn-sm ${days===d?'btn-primary':'btn-ghost'}`}
              onClick={()=>setDays(d)}>{d}d</button>
          ))}
          <button className="btn btn-ghost btn-sm" onClick={load}>
            <RefreshCw size={13} className={loading?'spin':''}/> Refresh
          </button>
        </div>
      </div>

      <div className="tab-bar" style={{marginBottom:16}}>
        {[
          {id:'senders',    label:'Top Senders',    icon:<TrendingUp size={13}/>},
          {id:'recipients', label:'Top Recipients', icon:<Users size={13}/>},
        ].map(t=>(
          <button key={t.id} className={`tab-item ${activeTab===t.id?'active':''}`}
            onClick={()=>setActiveTab(t.id)}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="card" style={{textAlign:'center',padding:64}}>
          <RefreshCw size={24} className="spin" style={{marginBottom:12}}/>
          <div style={{color:'var(--text-muted)'}}>Loading analytics...</div>
        </div>
      ) : (
        <>
          {activeTab === 'senders'    && renderList(senders,    'Senders')}
          {activeTab === 'recipients' && renderList(recipients, 'Recipients')}
        </>
      )}
    </div>
  );
}
