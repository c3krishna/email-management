require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

const statsRoutes   = require('./routes/stats');
const mailsRoutes   = require('./routes/mails');
const alertsRoutes  = require('./routes/alerts');
const healthRoutes  = require('./routes/health');
const authRoutes    = require('./routes/auth');
const usersRoutes   = require('./routes/users');
const { verifyToken } = require('./middleware/auth');
const compareRoutes = require('./routes/compare');
const inboxRoutes   = require('./routes/inbox');
const mailchimpWebhookRoutes = require('./routes/mailchimp-webhook');
const advancedDetectionRoutes = require('./routes/advanced-detection');
const apiActionsRoutes = require('./routes/api-actions');
const mailboxMonitorsRoutes = require('./routes/mailbox-monitors');
const validateRoutes = require('./routes/validate');
const vipProtectionRoutes = require('./routes/vip-protection');
const wazuhRoutes = require('./routes/wazuh');
const orchestrationRoutes = require('./routes/orchestration');
const connectorsRoutes = require('./routes/connectors');
const notificationsRoutes = require('./routes/notifications');
const spamRoutes = require('./routes/spam');
const firewallRoutes = require('./routes/firewall');
const reportsRoutes  = require('./routes/reports');
const threatRoutes   = require('./routes/threats');
const platformRoutes = require('./routes/platform');
const agentRoutes = require('./routes/agent');
const quarantineRoutes = require('./routes/quarantine');
const policiesRoutes = require('./routes/policies');

const app  = express();
const PORT = process.env.PORT || 5200;

if (!process.env.JWT_SECRET) {
  console.warn('⚠️  JWT_SECRET is not set — auth tokens will be rejected until it is configured');
}
if (!process.env.AGENT_SECRET) {
  console.warn('⚠️  AGENT_SECRET is not set — agent ingest endpoints will reject requests');
}

// ---- TRUST PROXY (required for X-Forwarded-For behind Nginx) ----
app.set('trust proxy', 1);

// ---- Security & performance ----
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors({
  origin: [
    process.env.FRONTEND_URL || 'https://email-management.worktual.tech',
    'http://localhost:3000',
    'http://localhost:5173'
  ],
  credentials: true
}));
app.use(express.json({ limit: '2mb' }));

// ---- Rate limiting ----
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', apiLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again after 15 minutes.' }
});

// ---- Public routes (no auth) ----
app.use('/api/health', healthRoutes);
app.use('/api/auth',   authLimiter, authRoutes);

// Agent ingest uses X-Agent-Secret; read endpoints require JWT (see agent.js)
app.use('/api/agent', agentRoutes);

// Public customer validate API (API-key auth inside router)
app.use('/api/v1', validateRoutes);

// Webhooks (connector-specific auth inside routers)
app.use('/api/connectors/webhook', mailchimpWebhookRoutes);

// Milter/agent policy pull (AGENT_SECRET) — must stay outside JWT mount
app.get('/api/policies/for-agent', (req, res, next) => {
  req.url = '/for-agent';
  policiesRoutes.handle(req, res, next);
});
app.get('/api/spam/whitelist/for-agent', (req, res, next) => {
  req.url = '/whitelist/for-agent';
  spamRoutes.handle(req, res, next);
});

// ---- Protected routes (JWT required) ----
app.use('/api/stats',  verifyToken, statsRoutes);
app.use('/api/mails',  verifyToken, mailsRoutes);
app.use('/api/alerts', verifyToken, alertsRoutes);
app.use('/api/users',  verifyToken, usersRoutes);
app.use('/api/compare', verifyToken, compareRoutes);
app.use('/api/inbox',   verifyToken, inboxRoutes);
app.use('/api/quarantine', verifyToken, quarantineRoutes);
app.use('/api/policies', verifyToken, policiesRoutes);
app.use('/api/advanced-detection', verifyToken, advancedDetectionRoutes);
app.use('/api/actions', verifyToken, apiActionsRoutes);
app.use('/api/mailbox-monitors', verifyToken, mailboxMonitorsRoutes);
app.use('/api/protection', verifyToken, vipProtectionRoutes);
app.use('/api/wazuh', verifyToken, wazuhRoutes);
app.use('/api/orchestration', verifyToken, orchestrationRoutes);
app.use('/api/connectors', verifyToken, connectorsRoutes);
app.use('/api/notifications', verifyToken, notificationsRoutes);
app.use('/api/spam', spamRoutes);           // mixed: agent notification + JWT inside router
app.use('/api/firewall', firewallRoutes);   // mixed: agent ingest + JWT inside router
app.use('/api/reports', verifyToken, reportsRoutes);
app.use('/api/threats', threatRoutes);      // mixed: flexAuth / JWT inside router
app.use('/api/platform', platformRoutes);   // mixed: API-key ingest + JWT inside router

// Alias: ip-reputation was being called at /api/stats/ip-reputation
app.get('/api/stats/ip-reputation', verifyToken, (req, res) => {
  req.url = '/ip-reputation';
  firewallRoutes(req, res, () => res.status(404).json({ error: 'not found' }));
});

app.get('/', (req, res) => {
  res.json({ service: 'Email Management API', version: '2.1.0', status: 'running' });
});

app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error', message: err.message });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Email Management API v2.1 running on port ${PORT}`);
});
