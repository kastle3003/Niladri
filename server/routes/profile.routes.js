const express = require('express');
const router = express.Router();
const multer = require('multer');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { persistUpload } = require('../lib/storage');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

function ensureProfile(userId) {
  const existing = db.prepare('SELECT * FROM user_profile WHERE user_id = ?').get(userId);
  if (!existing) {
    db.prepare('INSERT OR IGNORE INTO user_profile (user_id) VALUES (?)').run(userId);
  }
}

// GET /api/profile
router.get('/', (req, res) => {
  try {
    ensureProfile(req.user.id);
    const user = db.prepare('SELECT id, email, first_name, last_name, role, instrument, avatar_initials, bio, created_at FROM users WHERE id = ?').get(req.user.id);
    const profile = db.prepare('SELECT * FROM user_profile WHERE user_id = ?').get(req.user.id);
    res.json({
      user: {
        ...user,
        ...profile,
        social_links: JSON.parse(profile.social_links || '{}'),
        notification_prefs: JSON.parse(profile.notification_prefs || '{}')
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/profile
router.put('/', (req, res) => {
  try {
    ensureProfile(req.user.id);
    const {
      first_name, last_name, instrument, bio, phone, location,
      social_links, practice_goal_minutes, notification_prefs
    } = req.body;

    // Update users table fields
    const userUpdates = {};
    if (first_name !== undefined) userUpdates.first_name = first_name;
    if (last_name !== undefined) userUpdates.last_name = last_name;
    if (instrument !== undefined) userUpdates.instrument = instrument;
    if (bio !== undefined) userUpdates.bio = bio;

    if (Object.keys(userUpdates).length > 0) {
      const setClauses = Object.keys(userUpdates).map(k => `${k} = ?`).join(', ');
      db.prepare(`UPDATE users SET ${setClauses} WHERE id = ?`).run(...Object.values(userUpdates), req.user.id);
    }

    // Update user_profile table
    const profileUpdates = {};
    if (phone !== undefined) profileUpdates.phone = phone;
    if (location !== undefined) profileUpdates.location = location;
    if (social_links !== undefined) profileUpdates.social_links = JSON.stringify(social_links);
    if (practice_goal_minutes !== undefined) profileUpdates.practice_goal_minutes = practice_goal_minutes;
    if (notification_prefs !== undefined) profileUpdates.notification_prefs = JSON.stringify(notification_prefs);

    if (Object.keys(profileUpdates).length > 0) {
      const setClauses = Object.keys(profileUpdates).map(k => `${k} = ?`).join(', ');
      db.prepare(`UPDATE user_profile SET ${setClauses}, updated_at = datetime('now') WHERE user_id = ?`).run(...Object.values(profileUpdates), req.user.id);
    }

    const user = db.prepare('SELECT id, email, first_name, last_name, role, instrument, avatar_initials, bio, created_at FROM users WHERE id = ?').get(req.user.id);
    const profile = db.prepare('SELECT * FROM user_profile WHERE user_id = ?').get(req.user.id);
    res.json({
      user: {
        ...user,
        ...profile,
        social_links: JSON.parse(profile.social_links || '{}'),
        notification_prefs: JSON.parse(profile.notification_prefs || '{}')
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/profile/avatar
router.post('/avatar', upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    ensureProfile(req.user.id);
    const avatarUrl = await persistUpload(req.file, 'avatars');
    db.prepare("UPDATE user_profile SET avatar_url = ?, updated_at = datetime('now') WHERE user_id = ?").run(avatarUrl, req.user.id);
    res.json({ avatar_url: avatarUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/profile/password
router.put('/password', async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) {
      return res.status(400).json({ error: 'current_password and new_password are required' });
    }
    if (new_password.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' });
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    const valid = await bcrypt.compare(current_password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
    const hash = await bcrypt.hash(new_password, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
