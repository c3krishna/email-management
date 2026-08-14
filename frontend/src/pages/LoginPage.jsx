import { useState } from 'react';
import axios from 'axios';

const API = '/api/auth';

export default function LoginPage({ onLogin }) {
  const [view, setView] = useState('login'); // login | forgot | otp | reset
  const [form, setForm] = useState({ email: '', password: '', otp: '', new_password: '', confirm_password: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [resetToken, setResetToken] = useState('');

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));
  const clear = () => { setError(''); setSuccess(''); };

  // ---- LOGIN ----
  const handleLogin = async (e) => {
    e.preventDefault();
    clear();
    if (!form.email || !form.password) return setError('Email and password required.');
    setLoading(true);
    try {
      const r = await axios.post(`${API}/login`, { email: form.email, password: form.password });
      localStorage.setItem('em_token', r.data.token);
      localStorage.setItem('em_user', JSON.stringify(r.data.user));
      onLogin(r.data.user, r.data.token);
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed.');
    } finally {
      setLoading(false);
    }
  };

  // ---- FORGOT PASSWORD ----
  const handleForgot = async (e) => {
    e.preventDefault();
    clear();
    if (!form.email) return setError('Email required.');
    setLoading(true);
    try {
      await axios.post(`${API}/forgot-password`, { email: form.email });
      setSuccess('OTP sent to your email. Check inbox.');
      setView('otp');
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to send OTP.');
    } finally {
      setLoading(false);
    }
  };

  // ---- VERIFY OTP ----
  const handleOTP = async (e) => {
    e.preventDefault();
    clear();
    if (!form.otp) return setError('OTP required.');
    setLoading(true);
    try {
      const r = await axios.post(`${API}/verify-otp`, { email: form.email, otp: form.otp });
      setResetToken(r.data.reset_token);
      setSuccess('OTP verified. Set your new password.');
      setView('reset');
    } catch (err) {
      setError(err.response?.data?.error || 'Invalid or expired OTP.');
    } finally {
      setLoading(false);
    }
  };

  // ---- RESET PASSWORD ----
  const handleReset = async (e) => {
    e.preventDefault();
    clear();
    if (form.new_password !== form.confirm_password) return setError('Passwords do not match.');
    if (form.new_password.length < 8) return setError('Password must be at least 8 characters.');
    setLoading(true);
    try {
      await axios.post(`${API}/reset-password`, { reset_token: resetToken, new_password: form.new_password });
      setSuccess('Password reset successfully!');
      setTimeout(() => { setView('login'); setForm(f => ({ ...f, password: '' })); }, 1500);
    } catch (err) {
      setError(err.response?.data?.error || 'Reset failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh', background: 'var(--bg-primary)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontFamily: 'var(--font-sans)', padding: 20
    }}>
      <div style={{ width: '100%', maxWidth: 420 }}>

        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{
            width: 56, height: 56, borderRadius: 14,
            background: 'linear-gradient(135deg, #2563eb, #7c3aed)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 28, margin: '0 auto 16px'
          }}>📧</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)' }}>Email Management</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>email-management.worktual.tech</div>
        </div>

        <div className="card" style={{ padding: 32 }}>

          {/* ---- LOGIN VIEW ---- */}
          {view === 'login' && (
            <>
              <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 24 }}>Sign In</div>
              <form onSubmit={handleLogin}>
                <div style={{ marginBottom: 16 }}>
                  <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.5 }}>Email</label>
                  <input className="input" type="email" placeholder="admin@worktual.tech"
                    value={form.email} onChange={e => set('email', e.target.value)} autoFocus />
                </div>
                <div style={{ marginBottom: 8 }}>
                  <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.5 }}>Password</label>
                  <input className="input" type="password" placeholder="••••••••"
                    value={form.password} onChange={e => set('password', e.target.value)} />
                </div>
                <div style={{ textAlign: 'right', marginBottom: 20 }}>
                  <button type="button" onClick={() => { setView('forgot'); clear(); }}
                    style={{ background: 'none', border: 'none', color: 'var(--accent-blue-light)', fontSize: 12, cursor: 'pointer' }}>
                    Forgot password?
                  </button>
                </div>
                {error && <div className="alert-box alert-critical" style={{ marginBottom: 16 }}>❌ {error}</div>}
                <button type="submit" className="btn btn-primary" disabled={loading}
                  style={{ width: '100%', justifyContent: 'center', padding: '11px 0', fontSize: 14 }}>
                  {loading ? 'Signing in...' : 'Sign In'}
                </button>
              </form>
            </>
          )}

          {/* ---- FORGOT PASSWORD VIEW ---- */}
          {view === 'forgot' && (
            <>
              <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Forgot Password</div>
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 24 }}>Enter your email to receive a 6-digit OTP.</div>
              <form onSubmit={handleForgot}>
                <div style={{ marginBottom: 20 }}>
                  <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 6, textTransform: 'uppercase' }}>Email</label>
                  <input className="input" type="email" placeholder="your@email.com"
                    value={form.email} onChange={e => set('email', e.target.value)} autoFocus />
                </div>
                {error   && <div className="alert-box alert-critical" style={{ marginBottom: 16 }}>❌ {error}</div>}
                {success && <div className="alert-box alert-info"     style={{ marginBottom: 16 }}>✅ {success}</div>}
                <button type="submit" className="btn btn-primary" disabled={loading}
                  style={{ width: '100%', justifyContent: 'center', padding: '11px 0' }}>
                  {loading ? 'Sending OTP...' : 'Send OTP'}
                </button>
                <button type="button" onClick={() => { setView('login'); clear(); }}
                  style={{ width: '100%', marginTop: 10, background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: 13, cursor: 'pointer' }}>
                  ← Back to Login
                </button>
              </form>
            </>
          )}

          {/* ---- OTP VIEW ---- */}
          {view === 'otp' && (
            <>
              <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Enter OTP</div>
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 24 }}>
                OTP sent to <strong style={{ color: 'var(--text-primary)' }}>{form.email}</strong>. Valid for 10 minutes.
              </div>
              <form onSubmit={handleOTP}>
                <div style={{ marginBottom: 20 }}>
                  <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 6, textTransform: 'uppercase' }}>6-Digit OTP</label>
                  <input className="input" type="text" placeholder="123456" maxLength={6}
                    value={form.otp} onChange={e => set('otp', e.target.value.replace(/\D/g, ''))}
                    style={{ fontSize: 24, letterSpacing: 8, textAlign: 'center', fontFamily: 'var(--font-mono)' }}
                    autoFocus />
                </div>
                {error   && <div className="alert-box alert-critical" style={{ marginBottom: 16 }}>❌ {error}</div>}
                {success && <div className="alert-box alert-info"     style={{ marginBottom: 16 }}>✅ {success}</div>}
                <button type="submit" className="btn btn-primary" disabled={loading || form.otp.length !== 6}
                  style={{ width: '100%', justifyContent: 'center', padding: '11px 0' }}>
                  {loading ? 'Verifying...' : 'Verify OTP'}
                </button>
                <button type="button" onClick={handleForgot}
                  style={{ width: '100%', marginTop: 10, background: 'none', border: 'none', color: 'var(--accent-blue-light)', fontSize: 12, cursor: 'pointer' }}>
                  Resend OTP
                </button>
              </form>
            </>
          )}

          {/* ---- RESET PASSWORD VIEW ---- */}
          {view === 'reset' && (
            <>
              <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Set New Password</div>
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 24 }}>Minimum 8 characters.</div>
              <form onSubmit={handleReset}>
                <div style={{ marginBottom: 16 }}>
                  <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 6, textTransform: 'uppercase' }}>New Password</label>
                  <input className="input" type="password" placeholder="••••••••"
                    value={form.new_password} onChange={e => set('new_password', e.target.value)} autoFocus />
                </div>
                <div style={{ marginBottom: 20 }}>
                  <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 6, textTransform: 'uppercase' }}>Confirm Password</label>
                  <input className="input" type="password" placeholder="••••••••"
                    value={form.confirm_password} onChange={e => set('confirm_password', e.target.value)} />
                </div>
                {error   && <div className="alert-box alert-critical" style={{ marginBottom: 16 }}>❌ {error}</div>}
                {success && <div className="alert-box alert-info"     style={{ marginBottom: 16 }}>✅ {success}</div>}
                <button type="submit" className="btn btn-primary" disabled={loading}
                  style={{ width: '100%', justifyContent: 'center', padding: '11px 0' }}>
                  {loading ? 'Resetting...' : 'Reset Password'}
                </button>
              </form>
            </>
          )}
        </div>

        <div style={{ textAlign: 'center', marginTop: 20, fontSize: 12, color: 'var(--text-muted)' }}>
          Worktual Innovations Pvt Ltd, Chennai
        </div>
      </div>
    </div>
  );
}
