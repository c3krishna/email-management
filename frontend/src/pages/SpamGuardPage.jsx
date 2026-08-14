import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, ExternalLink, RefreshCw, Lock } from 'lucide-react';
import { mailsApi } from '../utils/api';

const SPAM_CHECKLIST = [
  {
    category: '🔴 CRITICAL — Do Immediately (You Are Blacklisted)',
    items: [
      {
        title: 'Check IP on Spamhaus (ZEN)',
        desc: 'Your IP was blocked. Check immediately: lookup.dnsbl.info or mxtoolbox.com/blacklists.aspx',
        link: 'https://www.spamhaus.org/lookup/',
        linkLabel: 'Spamhaus Lookup',
        status: 'check'
      },
      {
        title: 'Submit Delisting Request to Spamhaus',
        desc: 'After fixing the root cause, submit a removal request. Requires PTR/rDNS, SPF, DKIM, DMARC all passing.',
        link: 'https://www.spamhaus.org/lookup/',
        linkLabel: 'Request Removal',
        status: 'check'
      },
      {
        title: 'Check All Major Blacklists',
        desc: 'MXToolbox, MultiRBL, DNSBL.info — check all 50+ blacklists to know full scope.',
        link: 'https://mxtoolbox.com/blacklists.aspx',
        linkLabel: 'MXToolbox Blacklist',
        status: 'check'
      },
    ]
  },
  {
    category: '📧 Email Authentication (SPF / DKIM / DMARC)',
    items: [
      {
        title: 'SPF Record — Authorize Your Sending IPs',
        desc: 'Add/verify your TXT record: v=spf1 ip4:YOUR_MAIL_IP include:_spf.google.com ~all\nTest: dig TXT yourdomain.com | grep spf',
        cmd: 'dig TXT worktual.tech | grep spf\nnslookup -type=TXT worktual.tech',
        status: 'fix'
      },
      {
        title: 'DKIM Signing — OpenDKIM Already Running',
        desc: 'Verify DKIM is active: mail.log should show "DKIM-Signature added". Check selector DNS is published.',
        cmd: 'postfix check\nopendkim-testkey -d worktual.tech -s mail -vvv\ndig TXT mail._domainkey.worktual.tech',
        status: 'verify'
      },
      {
        title: 'DMARC Policy — Set to Reject',
        desc: 'Start with p=none (monitoring), then p=quarantine, then p=reject. Add rua for daily reports.',
        cmd: 'dig TXT _dmarc.worktual.tech\n# DNS record: v=DMARC1; p=quarantine; rua=mailto:dmarc@worktual.tech; pct=100',
        status: 'fix'
      },
    ]
  },
  {
    category: '🖥️ IP Reputation & DNS Config',
    items: [
      {
        title: 'PTR / Reverse DNS (rDNS) Record',
        desc: 'Your mail server IP MUST have a PTR record matching hostname. Contact your ISP/DC provider to set it.',
        cmd: 'dig -x YOUR_MAIL_IP\n# Must return: mail.worktual.tech (or similar FQDN)\n# Contact Leaseweb/OCI support to set PTR record',
        status: 'fix'
      },
      {
        title: 'IP Warm-up — Gradual Volume Increase',
        desc: 'Never send 4000 emails/day from a new or cold IP. Start with 100/day → 500 → 1000 → 2000 → 4000 over 2-4 weeks.',
        status: 'process'
      },
      {
        title: 'Dedicated IP for Transactional vs Marketing',
        desc: 'Separate your transactional emails (OTPs, notifications) from marketing campaigns on different IPs/domains.',
        status: 'architecture'
      },
    ]
  },
  {
    category: '📋 List Hygiene & Bounce Management',
    items: [
      {
        title: 'Remove Hard Bounces Immediately',
        desc: 'DSN 5.x.x = permanent failure. Remove from all lists immediately. High bounce rate = spam signal.',
        cmd: "-- Query hard bounces:\nSELECT mail_to, COUNT(*) FROM email_delivery_details\nWHERE dsn LIKE '5%' OR status='bounced'\nGROUP BY mail_to HAVING COUNT(*) >= 2;",
        status: 'fix'
      },
      {
        title: 'Implement Email Validation Before Sending',
        desc: 'Validate format, MX record existence before inserting into your sending queue. Libraries: email-validator, py3-validate-email.',
        cmd: '# Python: pip install pyIsEmail py3dns\n# Node.js: npm install email-validator',
        status: 'fix'
      },
      {
        title: 'Unsubscribe / List-Unsubscribe Header',
        desc: 'Add List-Unsubscribe header in all marketing emails. Required by Gmail/Yahoo from 2024. Process unsubscribes within 2 days.',
        cmd: '# In postfix/application headers:\nList-Unsubscribe: <mailto:unsubscribe@worktual.tech?subject=unsubscribe>\nList-Unsubscribe-Post: List-Unsubscribe=One-Click',
        status: 'fix'
      },
      {
        title: 'Double Opt-In for All Marketing Lists',
        desc: 'Require email confirmation before adding to marketing lists. Dramatically reduces spam complaints and bounces.',
        status: 'process'
      },
    ]
  },
  {
    category: '⚙️ Postfix / Amavis / SpamD Tuning',
    items: [
      {
        title: 'Fix Unformatted / Malformed Emails from Application',
        desc: 'Check your Python email sender — ensure From/To/Subject headers are RFC-compliant. Verify MIME encoding.',
        cmd: "-- Find malformed patterns:\nSELECT reason, COUNT(*) FROM email_delivery_details\nWHERE reason LIKE '%format%' OR reason LIKE '%header%' OR reason LIKE '%encoding%'\nGROUP BY reason ORDER BY COUNT(*) DESC;",
        status: 'fix'
      },
      {
        title: 'Set Proper HELO/EHLO Hostname',
        desc: 'Must match your PTR record. In /etc/postfix/main.cf: myhostname = mail.worktual.tech',
        cmd: 'grep myhostname /etc/postfix/main.cf\n# Should match: $(hostname -f)\n# Also set: smtpd_banner = $myhostname ESMTP',
        status: 'fix'
      },
      {
        title: 'Rate Limiting — Throttle Outbound',
        desc: 'Limit sending rate to avoid triggering spam thresholds. Gmail accepts ~3000/day from new IPs.',
        cmd: '# /etc/postfix/main.cf:\ndefault_destination_rate_delay = 1s\ndefault_destination_concurrency_limit = 5\nsmtp_destination_rate_delay = 2s',
        status: 'fix'
      },
      {
        title: 'SpamAssassin / Amavis Content Scoring',
        desc: 'Check outbound mail score before sending. Target score < 5.0. Test with mail-tester.com.',
        cmd: 'spamassassin -t < test_email.eml\n# Or use: https://www.mail-tester.com/',
        link: 'https://www.mail-tester.com/',
        linkLabel: 'Test Email Score',
        status: 'verify'
      },
    ]
  },
  {
    category: '🔍 Monitoring & Ongoing Health',
    items: [
      {
        title: 'Google Postmaster Tools Registration',
        desc: 'Register your domain at postmaster.google.com. Monitor Domain Reputation, IP Reputation, Spam Rate daily.',
        link: 'https://postmaster.google.com/',
        linkLabel: 'Google Postmaster',
        status: 'setup'
      },
      {
        title: 'Monitor mail.log for Rejection Patterns',
        desc: 'Set up Graylog/Wazuh alerts on "reject", "blocked", "spam", "blacklist" keywords in Postfix logs.',
        cmd: "grep -E '(reject|blocked|spam|blacklist)' /var/log/mail.log | tail -100\n# In Wazuh: already deployed on 10.180.1.221",
        status: 'setup'
      },
      {
        title: 'Daily Complaint Rate < 0.1%',
        desc: 'Gmail requires spam complaint rate below 0.1%. Above 0.3% = bulk folder. Monitor via Postmaster Tools.',
        status: 'monitor'
      },
    ]
  },
];

const STATUS_STYLE = {
  fix: { color: '#f87171', bg: 'rgba(220,38,38,0.1)', label: '🔧 FIX NEEDED' },
  check: { color: '#f97316', bg: 'rgba(234,88,12,0.1)', label: '🔍 CHECK NOW' },
  verify: { color: '#fbbf24', bg: 'rgba(217,119,6,0.1)', label: '✅ VERIFY' },
  setup: { color: '#60a5fa', bg: 'rgba(37,99,235,0.1)', label: '⚙️ SETUP' },
  process: { color: '#a78bfa', bg: 'rgba(124,58,237,0.1)', label: '📋 PROCESS' },
  architecture: { color: '#34d399', bg: 'rgba(5,150,105,0.1)', label: '🏗️ ARCHITECTURE' },
  monitor: { color: '#4ade80', bg: 'rgba(22,163,74,0.1)', label: '👁️ MONITOR' },
};

export default function SpamGuardPage() {
  const [spamData, setSpamData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('checklist');
  const [expandedCmd, setExpandedCmd] = useState(null);

  useEffect(() => {
    mailsApi.getSpamAnalysis().then(r => {
      setSpamData(r.data);
    }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <div className="mb-24">
        <div className="section-title">Spam Guard & IP Health</div>
        <div className="section-sub">
          IP blacklist recovery guide, anti-spam checklist, and spam pattern analysis for your Postfix+OpenDKIM+Amavis stack
        </div>
        <div style={{ background: 'rgba(220,38,38,0.1)', border: '1px solid rgba(220,38,38,0.3)', borderRadius: 8, padding: '14px 18px', marginTop: 16 }}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
            <AlertTriangle size={18} color="#f87171" style={{ flexShrink: 0, marginTop: 2 }} />
            <div>
              <div style={{ fontWeight: 700, color: '#f87171', marginBottom: 4 }}>⚠️ Your IP is Currently Blacklisted on Spamhaus</div>
              <div style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.6 }}>
                Follow this checklist top-to-bottom. Fix root causes BEFORE requesting delisting — Spamhaus will reject repeat submissions.
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="tab-bar">
        <button className={`tab-item ${activeTab === 'checklist' ? 'active' : ''}`} onClick={() => setActiveTab('checklist')}>
          Recovery Checklist
        </button>
        <button className={`tab-item ${activeTab === 'spam-senders' ? 'active' : ''}`} onClick={() => setActiveTab('spam-senders')}>
          Spam Pattern Analysis (30d)
        </button>
        <button className={`tab-item ${activeTab === 'tools' ? 'active' : ''}`} onClick={() => setActiveTab('tools')}>
          Quick Diagnostic Commands
        </button>
      </div>

      {activeTab === 'checklist' && (
        <div>
          {SPAM_CHECKLIST.map((section, si) => (
            <div key={si} className="card mb-20">
              <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 16, color: 'var(--text-primary)' }}>{section.category}</div>
              {section.items.map((item, ii) => {
                const st = STATUS_STYLE[item.status] || STATUS_STYLE.verify;
                const key = `${si}-${ii}`;
                return (
                  <div key={ii} className="checklist-item">
                    <div className="check-icon">
                      <div style={{ background: st.bg, borderRadius: 6, padding: '4px 8px', fontSize: 10, fontWeight: 700, color: st.color, whiteSpace: 'nowrap' }}>
                        {st.label}
                      </div>
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 600, marginBottom: 4, fontSize: 14 }}>{item.title}</div>
                      <div style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6, whiteSpace: 'pre-line' }}>{item.desc}</div>
                      {item.cmd && (
                        <div style={{ marginTop: 8 }}>
                          <button style={{ fontSize: 11, color: 'var(--accent-blue-light)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
                            onClick={() => setExpandedCmd(expandedCmd === key ? null : key)}>
                            {expandedCmd === key ? '▼ Hide command' : '▶ Show command'}
                          </button>
                          {expandedCmd === key && (
                            <pre style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 14px', fontSize: 11, marginTop: 8, fontFamily: 'var(--font-mono)', color: '#4ade80', overflowX: 'auto', whiteSpace: 'pre-wrap' }}>
                              {item.cmd}
                            </pre>
                          )}
                        </div>
                      )}
                      {item.link && (
                        <a href={item.link} target="_blank" rel="noopener noreferrer" style={{ display: 'inline-flex', alignItems: 'center', gap: 4, marginTop: 8, fontSize: 12, color: 'var(--accent-blue-light)', textDecoration: 'none' }}>
                          <ExternalLink size={12} /> {item.linkLabel}
                        </a>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      )}

      {activeTab === 'spam-senders' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Senders with Spam Blocks (Last 30 Days)</span>
          </div>
          {loading ? (
            <div className="loading-state"><RefreshCw size={18} className="spin" /></div>
          ) : spamData.length === 0 ? (
            <div className="loading-state" style={{ color: '#4ade80' }}>✅ No spam-related rejections found in last 30 days</div>
          ) : (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr><th>Sender</th><th>Spam Blocks</th><th>First Seen</th><th>Last Seen</th><th>Active Days</th><th>Common Rejection Reasons</th></tr>
                </thead>
                <tbody>
                  {spamData.map((r, i) => (
                    <tr key={i}>
                      <td><span className="mono" style={{ fontSize: 12 }}>{r.mail_from}</span></td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#f87171' }}>{Number(r.count).toLocaleString()}</td>
                      <td className="mono" style={{ fontSize: 11 }}>{r.first_seen}</td>
                      <td className="mono" style={{ fontSize: 11 }}>{r.last_seen}</td>
                      <td>{r.days_active}</td>
                      <td style={{ fontSize: 11, color: '#fbbf24', maxWidth: 400 }}>{r.reasons?.slice(0, 200)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'tools' && (
        <div className="grid-2">
          {[
            {
              title: 'Check IP Blacklist Status',
              cmd: `# Replace YOUR_IP:\ndig +short YOUR_IP.zen.spamhaus.org\ndig +short YOUR_IP.bl.spamcop.net\ndig +short YOUR_IP.b.barracudacentral.org\n\n# Or use nslookup:\nnslookup -q=A YOUR_REVERSED_IP.zen.spamhaus.org`
            },
            {
              title: 'Verify SPF / DKIM / DMARC',
              cmd: `dig TXT worktual.tech | grep spf\ndig TXT mail._domainkey.worktual.tech\ndig TXT _dmarc.worktual.tech\n\n# Test DKIM key:\nopendkim-testkey -d worktual.tech -s mail -vvv`
            },
            {
              title: 'Postfix Queue & Log Analysis',
              cmd: `# Check mail queue:\nmailq | head -30\npostqueue -p | wc -l\n\n# Flush deferred:\npostqueue -f\n\n# Recent rejection logs:\ngrep 'reject\\|blocked\\|spam' /var/log/mail.log | tail -50\n\n# Failed delivery today:\ngrep "$(date +%b%e)" /var/log/mail.log | grep -E '(reject|bounced|failed)'`
            },
            {
              title: 'Check PTR / Reverse DNS',
              cmd: `# Your mail server IP reverse lookup:\nnslookup YOUR_MAIL_IP\ndig -x YOUR_MAIL_IP +short\n\n# HELO check:\npostconf myhostname\npostconf myorigin\n\n# Test full SMTP flow:\ntelnet mail.gmail.com 25`
            },
            {
              title: 'Test Email Authentication',
              cmd: `# Send test from CLI:\necho "Subject: test" | sendmail -v test@gmail.com\n\n# Check outbound scoring:\n# Send to check-auth@verifier.port25.com\n# Or use: https://www.mail-tester.com/\n\n# View DKIM signing in logs:\ngrep 'DKIM' /var/log/mail.log | tail -20`
            },
            {
              title: 'Find Malformed/Invalid Emails in DB',
              cmd: `-- Invalid addresses:\nSELECT mail_to, COUNT(*) as cnt FROM email_delivery_details\nWHERE (dsn='5.1.1' OR reason LIKE '%user unknown%' OR reason LIKE '%does not exist%')\nAND log_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)\nGROUP BY mail_to ORDER BY cnt DESC LIMIT 50;\n\n-- Unformatted mails:\nSELECT reason, COUNT(*) FROM email_delivery_details\nWHERE reason LIKE '%format%' OR reason LIKE '%header%'\nGROUP BY reason;`
            }
          ].map((t, i) => (
            <div key={i} className="card">
              <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 13 }}>{t.title}</div>
              <pre style={{
                background: 'var(--bg-primary)', border: '1px solid var(--border)',
                borderRadius: 6, padding: '12px 14px', fontSize: 11,
                fontFamily: 'var(--font-mono)', color: '#4ade80',
                overflowX: 'auto', whiteSpace: 'pre-wrap', lineHeight: 1.7
              }}>{t.cmd}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
