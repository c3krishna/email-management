const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcrypt');
const pool    = require('../db');
const { requireRole, ROLES } = require('../middleware/auth');

// ---- GET /api/users — list all users (admin+) ----
router.get('/', requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, name, email, role, is_active, last_login, login_attempts,
              locked_until, created_at, created_by
       FROM email_mgmt_users
       ORDER BY created_at DESC`
    );
    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- POST /api/users — create user (super_admin only) ----
router.post('/', requireRole('super_admin'), async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).json({ error: 'name, email, password, role are required.' });
  }
  if (!['super_admin', 'admin', 'viewer'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role. Must be: super_admin, admin, viewer' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  try {
    const [existing] = await pool.query('SELECT id FROM email_mgmt_users WHERE email = ?', [email.toLowerCase()]);
    if (existing.length > 0) {
      return res.status(409).json({ error: 'Email already exists.' });
    }

    const hash = await bcrypt.hash(password, 12);
    const [result] = await pool.query(
      'INSERT INTO email_mgmt_users (name, email, password_hash, role, is_active, created_by) VALUES (?, ?, ?, ?, 1, ?)',
      [name.trim(), email.toLowerCase().trim(), hash, role, req.user.id]
    );

    // Send welcome email
    try {
      const nodemailer = require('nodemailer');
      const mailer = nodemailer.createTransport({
        host: process.env.NOTIFY_SMTP_HOST || 'localhost',
        port: parseInt(process.env.NOTIFY_SMTP_PORT) || 25,
        secure: false, tls: { rejectUnauthorized: false }
      });
      await mailer.sendMail({
        from: `"Email Management" <${process.env.NOTIFY_FROM}>`,
        to: email,
        subject: 'Welcome to Email Management Dashboard',
        html: `
          <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#0d1117;color:#e6edf3;border-radius:12px">
            <h2 style="color:#2563eb">Welcome, ${name}!</h2>
            <p>Your account has been created on the Email Management Dashboard.</p>
            <table style="width:100%;background:#1c2230;border-radius:8px;padding:16px;margin:16px 0">
              <tr><td style="color:#8b949e;padding:4px 0">URL</td><td><a href="${process.env.FRONTEND_URL}" style="color:#60a5fa">${process.env.FRONTEND_URL}</a></td></tr>
              <tr><td style="color:#8b949e;padding:4px 0">Email</td><td>${email}</td></tr>
              <tr><td style="color:#8b949e;padding:4px 0">Password</td><td style="font-family:monospace">${password}</td></tr>
              <tr><td style="color:#8b949e;padding:4px 0">Role</td><td>${role}</td></tr>
            </table>
            <p style="color:#f87171;font-size:12px">Please change your password after first login.</p>
          </div>
        `
      });
    } catch (e) { /* email optional */ }

    res.json({ success: true, id: result.insertId, message: `User ${email} created with role ${role}.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- PUT /api/users/:id — update user ----
router.put('/:id', requireRole('super_admin'), async (req, res) => {
  const { name, role, is_active, password } = req.body;
  const userId = parseInt(req.params.id);

  // Prevent super_admin from deactivating themselves
  if (userId === req.user.id && is_active === false) {
    return res.status(400).json({ error: 'Cannot deactivate your own account.' });
  }

  try {
    const updates = [];
    const values  = [];

    if (name)                    { updates.push('name = ?');      values.push(name.trim()); }
    if (role)                    { updates.push('role = ?');      values.push(role); }
    if (is_active !== undefined) { updates.push('is_active = ?'); values.push(is_active ? 1 : 0); }
    if (password) {
      if (password.length < 8) return res.status(400).json({ error: 'Password min 8 chars.' });
      const hash = await bcrypt.hash(password, 12);
      updates.push('password_hash = ?');
      values.push(hash);
    }

    if (updates.length === 0) return res.status(400).json({ error: 'Nothing to update.' });

    values.push(userId);
    await pool.query(`UPDATE email_mgmt_users SET ${updates.join(', ')} WHERE id = ?`, values);

    res.json({ success: true, message: 'User updated.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- DELETE /api/users/:id — delete user (super_admin only) ----
router.delete('/:id', requireRole('super_admin'), async (req, res) => {
  const userId = parseInt(req.params.id);
  if (userId === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own account.' });
  }
  try {
    await pool.query('DELETE FROM email_mgmt_users WHERE id = ?', [userId]);
    res.json({ success: true, message: 'User deleted.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- POST /api/users/:id/unlock — unlock locked account ----
router.post('/:id/unlock', requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    await pool.query(
      'UPDATE email_mgmt_users SET login_attempts = 0, locked_until = NULL WHERE id = ?',
      [parseInt(req.params.id)]
    );
    res.json({ success: true, message: 'Account unlocked.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- GET /api/users/audit — audit log ----
router.get('/audit', requireRole('super_admin', 'admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM email_mgmt_audit ORDER BY created_at DESC LIMIT 200`
    );
    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
