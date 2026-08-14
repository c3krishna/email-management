import { useState, useEffect } from 'react';
import axios from 'axios';
import Footer         from './components/Footer';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import DashboardPage from './pages/DashboardPage';
import MailsPage from './pages/MailsPage';
import ProblematicPage from './pages/ProblematicPage';
import AlertsPage from './pages/AlertsPage';
import FirewallPage from './pages/FirewallPage';
import SpamGuardPage from './pages/SpamGuardPage';
import CampaignPage from './pages/CampaignPage';
import LoginPage from './pages/LoginPage';
import UsersPage from './pages/UsersPage';
import QuarantinePage      from './pages/QuarantinePage';
import SpamAnalysisPage from './pages/SpamAnalysisPage';
import ReportingPage       from './pages/ReportingPage';
import AnalyticsPage       from './pages/AnalyticsPage';
import PoliciesPage        from './pages/PoliciesPage';
import SettingsPage        from './pages/SettingsPage';
import VRThreatDashboard from './pages/VRThreatDashboard';
import PlatformOverviewPage from './pages/PlatformOverviewPage';
import WazuhSIEMPage from './pages/WazuhSIEMPage';
import AIOrchestrationPage from './pages/AIOrchestrationPage';
import EmailValidationAPIPage from './pages/EmailValidationAPIPage';
import ThreatIntelligencePage from './pages/ThreatIntelligencePage';
import ThreatManagementPage  from './pages/ThreatManagementPage';
import CustomerManagementPage from './pages/CustomerManagementPage';
import ThreatsPage        from './pages/ThreatsPage';
import IpReputationPage    from './pages/IpReputationPage';
import EmailLogsPage      from './pages/EmailLogsPage';
import DeliveryStatusPage  from './pages/DeliveryStatusPage';
import InboxPage       from './pages/InboxPage';
import ComparePage from './pages/ComparePage';
import VIPProtectionPage from './pages/VIPProtectionPage';
import MailboxMonitorsPage from './pages/MailboxMonitorsPage';

export default function App() {
  const [user, setUser]     = useState(null);
  const [token, setToken]   = useState(null);
  const [page, setPage]     = useState('dashboard');
  const [server, setServer] = useState('app');
  const [range, setRange]   = useState('today');
  const [selectedDate, setSelectedDate] = useState(new Date().toISOString().slice(0, 10));
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo]     = useState('');
  const [alertCount, setAlertCount] = useState(0);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [agentStatus, setAgentStatus] = useState(null);

  useEffect(() => {
    const savedToken = localStorage.getItem('em_token');
    const savedUser  = localStorage.getItem('em_user');
    if (savedToken && savedUser) {
      try {
        setUser(JSON.parse(savedUser));
        setToken(savedToken);
        axios.defaults.headers.common['Authorization'] = `Bearer ${savedToken}`;
      } catch (e) {
        localStorage.removeItem('em_token');
        localStorage.removeItem('em_user');
      }
    }
  }, []);

  useEffect(() => {
    if (!token) return undefined;
    let cancelled = false;
    const poll = async () => {
      try {
        const r = await axios.get('/api/agent/status');
        if (!cancelled) setAgentStatus(r.data.agents || null);
      } catch {
        if (!cancelled) setAgentStatus(null);
      }
    };
    poll();
    const id = setInterval(poll, 30000);
    return () => { cancelled = true; clearInterval(id); };
  }, [token]);

  const handleLogin = (u, t) => {
    setUser(u); setToken(t);
    axios.defaults.headers.common['Authorization'] = `Bearer ${t}`;
  };

  const handleLogout = async () => {
    try { await axios.post('/api/auth/logout'); } catch (e) {}
    localStorage.removeItem('em_token');
    localStorage.removeItem('em_user');
    delete axios.defaults.headers.common['Authorization'];
    setUser(null); setToken(null); setPage('dashboard'); setAgentStatus(null);
  };

  if (!user || !token) return <LoginPage onLogin={handleLogin} />;

  const pageProps = { server, range, selectedDate, dateFrom, dateTo };

  return (
    <div className="app">
      <button
        className="mobile-menu-btn"
        onClick={() => setMobileMenuOpen(v => !v)}
        aria-label="Toggle menu"
        style={{
          position: 'fixed', top: 12, left: 12, zIndex: 1001,
          width: 38, height: 38, borderRadius: 8,
          background: 'var(--bg-card, #1a1a2e)', border: '1px solid var(--border, #333)',
          color: 'var(--text-primary, #fff)', fontSize: 18, cursor: 'pointer',
          alignItems: 'center', justifyContent: 'center',
        }}
      >
        {mobileMenuOpen ? '✕' : '☰'}
      </button>

      <div
        className={`mobile-menu-backdrop${mobileMenuOpen ? ' open' : ''}`}
        onClick={() => setMobileMenuOpen(false)}
      />

      <Sidebar
        activePage={page}
        onNavigate={(p) => { setPage(p); setMobileMenuOpen(false); }}
        alertCount={alertCount} user={user} onLogout={handleLogout} agentStatus={agentStatus}
        mobileOpen={mobileMenuOpen}
      />
      <div className="main-content">
        <Topbar
          page={page}
          server={server} setServer={setServer}
          range={range} setRange={setRange}
          selectedDate={selectedDate} setSelectedDate={setSelectedDate}
          dateFrom={dateFrom} setDateFrom={setDateFrom}
          dateTo={dateTo} setDateTo={setDateTo}
          user={user} onLogout={handleLogout}
        />
        <div className="page-content">
          {page === 'dashboard'   && <DashboardPage   {...pageProps} />}
          {page === 'mails'       && <MailsPage        {...pageProps} />}
          {page === 'problematic' && <ProblematicPage  {...pageProps} />}
          {page === 'campaigns'   && <CampaignPage     {...pageProps} />}
          {page === 'compare'     && <ComparePage      {...pageProps} />}
          {page === 'quarantine'  && <QuarantinePage   server={server} />}
          {page === 'policies'    && <PoliciesPage server={server} />}
          {page === 'settings'    && <SettingsPage server={server} />}
          {page === 'spam-analysis' && <SpamAnalysisPage server={server} />}
          {page === 'reporting'        && <ReportingPage    server={server} />}
          {page === 'top-senders'      && <AnalyticsPage    server={server} />}
          {page === 'top-recipients'   && <AnalyticsPage    server={server} />}
          {page === 'threat-map'       && <ThreatsPage      server={server} range={range} selectedDate={selectedDate} />}
          {page === 'platform-overview' && <PlatformOverviewPage server={server} />}
          {page === 'wazuh-siem' && <WazuhSIEMPage server={server} />}
          {page === 'vr-platform' && <VRThreatDashboard server={server} />}
          {page === 'ai-orchestration' && <AIOrchestrationPage server={server} />}
          {page === 'validation-api' && <EmailValidationAPIPage server={server} />}
          {page === 'threat-intelligence-platform' && <ThreatIntelligencePage server={server} />}
          {page === 'threat-management' && <ThreatManagementPage server={server} />}
          {page === 'vip-protection' && <VIPProtectionPage />}
          {page === 'mailbox-monitors' && <MailboxMonitorsPage />}
          {page === 'customers'         && <CustomerManagementPage />}
          {page === 'threats'         && <ThreatsPage       server={server} range={range} selectedDate={selectedDate} />}
          {page === 'ip-reputation'   && <IpReputationPage  server={server} />}
          {page === 'email-logs'        && <EmailLogsPage       server={server} />}
          {page === 'delivery-status'  && <DeliveryStatusPage  server={server} />}
          {page === 'inbox'       && <InboxPage        currentUser={user} />}
          {page === 'alerts'      && <AlertsPage       {...pageProps} setAlertCount={setAlertCount} />}
          {page === 'firewall' && <FirewallPage server={server}/>}
          {page === 'spamguard'   && <SpamGuardPage    {...pageProps} />}
          {page === 'users'       && <UsersPage        currentUser={user} />}
        </div>
        <Footer agentStatus={agentStatus} />
      </div>
    </div>
  );
}
