const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const pool     = require('../db');
const { JWT_SECRET, verifyToken } = require('../middleware/auth');

const SESSION_EXPIRES = process.env.SESSION_EXPIRES || '8h';

// Mailer for OTP
const mailer = nodemailer.createTransport({
  host: process.env.NOTIFY_SMTP_HOST || 'localhost',
  port: parseInt(process.env.NOTIFY_SMTP_PORT) || 25,
  secure: false,
  tls: { rejectUnauthorized: false }
});

// ---- POST /api/auth/login ----
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required.' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT * FROM email_mgmt_users WHERE email = ? AND is_active = 1',
      [email.toLowerCase().trim()]
    );

    if (rows.length === 0) {
      await auditLog(null, email, 'LOGIN_FAILED', 'User not found', ip);
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const user = rows[0];

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const remaining = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
      return res.status(423).json({ error: `Account locked. Try again in ${remaining} minutes.` });
    }

    // Verify password
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      // Increment failed attempts
      const attempts = (user.login_attempts || 0) + 1;
      let lockUntil = null;
      if (attempts >= 5) {
        lockUntil = new Date(Date.now() + 30 * 60 * 1000); // lock 30 min
      }
      await pool.query(
        'UPDATE email_mgmt_users SET login_attempts = ?, locked_until = ? WHERE id = ?',
        [attempts, lockUntil, user.id]
      );
      await auditLog(user.id, email, 'LOGIN_FAILED', `Attempt ${attempts}`, ip);
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Reset failed attempts on success
    await pool.query(
      'UPDATE email_mgmt_users SET login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = ?',
      [user.id]
    );

    // Generate JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: SESSION_EXPIRES }
    );

    await auditLog(user.id, email, 'LOGIN_SUCCESS', null, ip);

    res.json({
      success: true,
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    console.error('[AUTH LOGIN]', err.message);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// ---- POST /api/auth/forgot-password ----
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });

  try {
    const [rows] = await pool.query(
      'SELECT id, name FROM email_mgmt_users WHERE email = ? AND is_active = 1',
      [email.toLowerCase().trim()]
    );

    // Always return success (don't reveal if email exists)
    if (rows.length === 0) {
      return res.json({ success: true, message: 'If this email exists, an OTP has been sent.' });
    }

    const user = rows[0];

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await pool.query(
      'UPDATE email_mgmt_users SET otp_code = ?, otp_expires = ? WHERE id = ?',
      [otp, otpExpires, user.id]
    );

    // Send OTP email
    await mailer.sendMail({
      from: `"Email Management" <${process.env.NOTIFY_FROM || 'noreply@worktual.tech'}>`,
      to: email,
      subject: '[Email Management] Password Reset OTP',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;background:#0d1117;color:#e6edf3;padding:32px;border-radius:12px">
          <h2 style="color:#2563eb;margin-bottom:8px">Password Reset OTP</h2>
          <p>Hello ${user.name},</p>
          <p>Your OTP for password reset:</p>
          <div style="background:#1c2230;border:2px solid #2563eb;border-radius:8px;padding:20px;text-align:center;margin:20px 0">
            <span style="font-size:36px;font-weight:700;font-family:monospace;letter-spacing:8px;color:#60a5fa">${otp}</span>
          </div>
          <p style="color:#8b949e;font-size:13px">This OTP is valid for <strong>10 minutes</strong>.<br>
          If you did not request this, ignore this email.</p>
          <hr style="border-color:#2d3748;margin:20px 0">
          <p style="color:#6e7681;font-size:12px">Worktual Innovations — Email Management Dashboard</p>
        </div>
      `
    });

    res.json({ success: true, message: 'If this email exists, an OTP has been sent.' });
  } catch (err) {
    console.error('[AUTH FORGOT]', err.message);
    res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
  }
});

// ---- POST /api/auth/verify-otp ----
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required.' });

  try {
    const [rows] = await pool.query(
      'SELECT id FROM email_mgmt_users WHERE email = ? AND otp_code = ? AND otp_expires > NOW() AND is_active = 1',
      [email.toLowerCase().trim(), otp.trim()]
    );

    if (rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP.' });
    }

    // Generate a short-lived reset token
    const resetToken = jwt.sign(
      { id: rows[0].id, email, purpose: 'reset' },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.json({ success: true, reset_token: resetToken });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- POST /api/auth/reset-password ----
router.post('/reset-password', async (req, res) => {
  const { reset_token, new_password } = req.body;
  if (!reset_token || !new_password) {
    return res.status(400).json({ error: 'Reset token and new password required.' });
  }
  if (new_password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  try {
    const decoded = jwt.verify(reset_token, JWT_SECRET);
    if (decoded.purpose !== 'reset') {
      return res.status(400).json({ error: 'Invalid reset token.' });
    }

    const hash = await bcrypt.hash(new_password, 12);
    await pool.query(
      'UPDATE email_mgmt_users SET password_hash = ?, otp_code = NULL, otp_expires = NULL, login_attempts = 0, locked_until = NULL WHERE id = ?',
      [hash, decoded.id]
    );

    res.json({ success: true, message: 'Password reset successfully. Please login.' });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(400).json({ error: 'Reset token expired. Request a new OTP.' });
    }
    res.status(500).json({ error: err.message });
  }
});

// ---- POST /api/auth/change-password (logged in user) ----
router.post('/change-password', verifyToken, async (req, res) => {
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'Current and new password required.' });
  }
  if (new_password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  try {
    const [rows] = await pool.query('SELECT password_hash FROM email_mgmt_users WHERE id = ?', [req.user.id]);
    const valid = await bcrypt.compare(current_password, rows[0].password_hash);
    if (!valid) return res.status(400).json({ error: 'Current password is incorrect.' });

    const hash = await bcrypt.hash(new_password, 12);
    await pool.query('UPDATE email_mgmt_users SET password_hash = ? WHERE id = ?', [hash, req.user.id]);
    await auditLog(req.user.id, req.user.email, 'PASSWORD_CHANGED', null, req.ip);

    res.json({ success: true, message: 'Password changed successfully.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- GET /api/auth/me ----
router.get('/me', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, name, email, role, last_login, created_at FROM email_mgmt_users WHERE id = ?',
      [req.user.id]
    );
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- POST /api/auth/logout ----
router.post('/logout', verifyToken, async (req, res) => {
  await auditLog(req.user.id, req.user.email, 'LOGOUT', null, req.ip);
  res.json({ success: true, message: 'Logged out successfully.' });
});

// Helper
async function auditLog(userId, email, action, details, ip) {
  try {
    await pool.query(
      'INSERT INTO email_mgmt_audit (user_id, user_email, action, details, ip_address) VALUES (?, ?, ?, ?, ?)',
      [userId, email, action, details, ip]
    );
  } catch (e) { /* silent */ }
}

module.exports = router;
