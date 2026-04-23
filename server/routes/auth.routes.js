const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const db = require('../db');
const authMiddleware = require('../middleware/auth');

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, first_name: user.first_name, last_name: user.last_name, instrument: user.instrument },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
}

// POST /api/auth/register
router.post('/register', (req, res) => {
  try {
    const { email, password, first_name, last_name, instrument } = req.body;
    if (!email || !password || !first_name || !last_name) {
      return res.status(400).json({ error: 'Email, password, first_name, and last_name are required' });
    }
    // Public self-registration is student-only. Instructor/admin accounts are created
    // via the admin CMS (POST /api/cms/instructors, POST /api/admin/users).
    const role = 'student';
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const password_hash = bcrypt.hashSync(password, 10);
    const avatar_initials = (first_name[0] + last_name[0]).toUpperCase();
    const otp = generateOTP();
    const otp_expires_at = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    const result = db.prepare(`
      INSERT INTO users (email, password_hash, first_name, last_name, role, instrument, avatar_initials, otp_code, otp_expires_at, verified)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    `).run(email, password_hash, first_name, last_name, role, instrument || null, avatar_initials, otp, otp_expires_at);

    res.status(201).json({ message: 'Registration successful. Please verify your email.', email, otp });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/verify-otp
router.post('/verify-otp', (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.otp_code !== otp) return res.status(400).json({ error: 'Invalid OTP' });
    if (new Date(user.otp_expires_at) < new Date()) return res.status(400).json({ error: 'OTP has expired' });

    db.prepare('UPDATE users SET verified = 1, otp_code = NULL, otp_expires_at = NULL WHERE id = ?').run(user.id);

    const token = signToken(user);
    const { password_hash, otp_code, otp_expires_at, reset_token, reset_expires_at, ...safeUser } = user;
    safeUser.verified = 1;
    res.json({ message: 'Email verified successfully', token, user: safeUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/resend-otp
router.post('/resend-otp', (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.verified) return res.status(400).json({ error: 'User already verified' });

    const otp = generateOTP();
    const otp_expires_at = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    db.prepare('UPDATE users SET otp_code = ?, otp_expires_at = ? WHERE id = ?').run(otp, otp_expires_at, user.id);

    res.json({ message: 'OTP resent successfully', email, otp });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/login
router.post('/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Invalid email or password' });
    if (!user.verified) return res.status(403).json({ error: 'Please verify your email before logging in', email: user.email });

    const token = signToken(user);
    const { password_hash, otp_code, otp_expires_at, reset_token, reset_expires_at, ...safeUser } = user;
    res.json({ message: 'Login successful', token, user: safeUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/forgot-password
router.post('/forgot-password', (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(200).json({ message: 'If that email is registered, a reset link has been sent.' });

    const reset_token = uuidv4();
    const reset_expires_at = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    db.prepare('UPDATE users SET reset_token = ?, reset_expires_at = ? WHERE id = ?').run(reset_token, reset_expires_at, user.id);

    res.json({ message: 'Password reset token generated (demo mode)', reset_token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/reset-password
router.post('/reset-password', (req, res) => {
  try {
    const { reset_token, password } = req.body;
    if (!reset_token || !password) return res.status(400).json({ error: 'Reset token and new password are required' });

    const user = db.prepare('SELECT * FROM users WHERE reset_token = ?').get(reset_token);
    if (!user) return res.status(400).json({ error: 'Invalid reset token' });
    if (new Date(user.reset_expires_at) < new Date()) return res.status(400).json({ error: 'Reset token has expired' });

    const password_hash = bcrypt.hashSync(password, 10);
    db.prepare('UPDATE users SET password_hash = ?, reset_token = NULL, reset_expires_at = NULL WHERE id = ?').run(password_hash, user.id);

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/auth/me
router.get('/me', authMiddleware, (req, res) => {
  try {
    const user = db.prepare('SELECT id, email, first_name, last_name, role, instrument, avatar_initials, bio, verified, created_at FROM users WHERE id = ?').get(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
