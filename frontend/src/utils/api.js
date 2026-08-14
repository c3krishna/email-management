import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' }
});

// Attach token on every request
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('em_token');
    if (token) config.headers['Authorization'] = `Bearer ${token}`;
    return config;
  },
  (error) => Promise.reject(error)
);

// Auto logout on 401
api.interceptors.response.use(
  (response) => response.data,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('em_token');
      localStorage.removeItem('em_user');
      window.location.reload();
    }
    return Promise.reject(new Error(error.response?.data?.error || error.message || 'API error'));
  }
);

export const statsApi = {
  // Existing
  getSummary:          (params) => api.get('/stats/summary',          { params }),
  getTrend:            (params) => api.get('/stats/trend',            { params }),
  getHourly:           (params) => api.get('/stats/hourly',           { params }),
  getByCampaign:       (params) => api.get('/stats/by-campaign',      { params }),
  getFailureReasons:   (params) => api.get('/stats/failure-reasons',  { params }),
  getBySender:         (params) => api.get('/stats/by-sender',        { params }),
  getDsnBreakdown:     (params) => api.get('/stats/dsn-breakdown',    { params }),

  // New enhanced endpoints
  getEnhancedSummary:  (params) => api.get('/stats/enhanced-summary', { params }),
  getTopSenders:       (params) => api.get('/stats/top-senders',      { params }),
  getTopRecipients:    (params) => api.get('/stats/top-recipients',   { params }),
  getWrongHitsTrend:   (params) => api.get('/stats/wrong-hits-trend', { params }),
  getThreatBreakdown:  (params) => api.get('/stats/threat-breakdown', { params }),
  getRecentLogs:       (params) => api.get('/stats/recent-logs',      { params }),
};

export const mailsApi = {
  getList:         (params) => api.get('/mails',              { params }),
  getProblematic:  (params) => api.get('/mails/problematic',  { params }),
  getSpamAnalysis: (params) => api.get('/mails/spam-analysis',{ params }),
  getFilterValues: (params) => api.get('/mails/filter-values',{ params }),
};

export const alertsApi = {
  getThresholds: (params) => api.get('/alerts/thresholds',   { params }),
  sendNotify:    (data)   => api.post('/alerts/notify',      data),
  autoNotify:    (data)   => api.post('/alerts/auto-notify', data),
};

export const healthApi = {
  check: () => api.get('/health'),
};

export default api;
