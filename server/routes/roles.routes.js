const express = require('express');
const router = express.Router();
const db = require('../db');
const { VALID_ROLES } = require('../lib/roles');

// GET /api/roles/users  (admin only)
router.get('/users', (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });

    const users = db.prepare(`
      SELECT id, first_name, last_name, email, role, instrument, avatar_initials, created_at
      FROM users
      ORDER BY role, last_name, first_name
    `).all();

    res.json({ users });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/roles/users/:id  (admin only)
router.put('/users/:id', (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });

    const { role } = req.body;
    if (!role || !VALID_ROLES.includes(role)) {
      return res.status(400).json({ error: `Valid role required: ${VALID_ROLES.join(', ')}` });
    }

    const user = db.prepare('SELECT id, first_name, last_name, email FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id);

    const updated = db.prepare('SELECT id, first_name, last_name, email, role FROM users WHERE id = ?').get(req.params.id);
    res.json({ user: updated, message: `Role updated to ${role}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
