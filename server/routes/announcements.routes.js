const express = require('express');
const router = express.Router();
const db = require('../db');

// GET /api/announcements?course_id=:id
router.get('/', (req, res) => {
  try {
    const { course_id } = req.query;
    let announcements;

    if (course_id) {
      announcements = db.prepare(`
        SELECT a.*,
          u.first_name || ' ' || u.last_name AS instructor_name,
          u.avatar_initials AS instructor_initials,
          c.title AS course_title,
          c.cover_color AS course_color
        FROM announcements a
        LEFT JOIN users u ON a.instructor_id = u.id
        LEFT JOIN courses c ON a.course_id = c.id
        WHERE a.course_id = ?
        ORDER BY a.pinned DESC, a.created_at DESC
      `).all(course_id);
    } else if (req.user.role === 'student') {
      // Get announcements for all enrolled courses
      announcements = db.prepare(`
        SELECT a.*,
          u.first_name || ' ' || u.last_name AS instructor_name,
          u.avatar_initials AS instructor_initials,
          c.title AS course_title,
          c.cover_color AS course_color
        FROM announcements a
        LEFT JOIN users u ON a.instructor_id = u.id
        LEFT JOIN courses c ON a.course_id = c.id
        WHERE a.course_id IN (
          SELECT course_id FROM enrollments WHERE student_id = ?
        )
        ORDER BY a.pinned DESC, a.created_at DESC
      `).all(req.user.id);
    } else {
      // Instructor/admin sees all announcements they created
      announcements = db.prepare(`
        SELECT a.*,
          u.first_name || ' ' || u.last_name AS instructor_name,
          u.avatar_initials AS instructor_initials,
          c.title AS course_title,
          c.cover_color AS course_color
        FROM announcements a
        LEFT JOIN users u ON a.instructor_id = u.id
        LEFT JOIN courses c ON a.course_id = c.id
        WHERE a.instructor_id = ?
        ORDER BY a.pinned DESC, a.created_at DESC
      `).all(req.user.id);
    }

    res.json({ announcements });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/announcements/:id
router.get('/:id', (req, res) => {
  try {
    const ann = db.prepare(`
      SELECT a.*,
        u.first_name || ' ' || u.last_name AS instructor_name,
        u.avatar_initials AS instructor_initials,
        c.title AS course_title
      FROM announcements a
      LEFT JOIN users u ON a.instructor_id = u.id
      LEFT JOIN courses c ON a.course_id = c.id
      WHERE a.id = ?
    `).get(req.params.id);
    if (!ann) return res.status(404).json({ error: 'Announcement not found' });
    res.json({ announcement: ann });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/announcements  (instructor)
router.post('/', (req, res) => {
  try {
    if (!['instructor', 'admin'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Instructor access required' });
    }

    const { title, body, course_id, pinned, send_email } = req.body;
    if (!title || !body) return res.status(400).json({ error: 'title and body are required' });

    const result = db.prepare(`
      INSERT INTO announcements (instructor_id, title, body, course_id, pinned, send_email)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(req.user.id, title, body, course_id || null, pinned ? 1 : 0, send_email ? 1 : 0);

    // If send_email is true, log emails to enrolled students
    if (send_email && course_id) {
      const students = db.prepare(`
        SELECT u.email, u.first_name || ' ' || u.last_name AS name
        FROM enrollments e
        JOIN users u ON e.student_id = u.id
        WHERE e.course_id = ?
      `).all(course_id);

      const insertLog = db.prepare(`
        INSERT INTO email_logs (to_email, subject, template_name, status)
        VALUES (?, ?, 'announcement', 'sent')
      `);
      const sendMany = db.transaction((students) => {
        for (const s of students) {
          insertLog.run(s.email, `[Announcement] ${title}`);
        }
      });
      try { sendMany(students); } catch (e) { /* log table may not exist yet */ }
    }

    const ann = db.prepare(`
      SELECT a.*, u.first_name || ' ' || u.last_name AS instructor_name, c.title AS course_title
      FROM announcements a
      LEFT JOIN users u ON a.instructor_id = u.id
      LEFT JOIN courses c ON a.course_id = c.id
      WHERE a.id = ?
    `).get(result.lastInsertRowid);

    res.status(201).json({ announcement: ann });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/announcements/:id
router.put('/:id', (req, res) => {
  try {
    const ann = db.prepare('SELECT * FROM announcements WHERE id = ?').get(req.params.id);
    if (!ann) return res.status(404).json({ error: 'Announcement not found' });
    if (ann.instructor_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not your announcement' });
    }

    const { title, body, course_id, pinned } = req.body;
    db.prepare(`
      UPDATE announcements SET
        title = COALESCE(?, title),
        body = COALESCE(?, body),
        course_id = COALESCE(?, course_id),
        pinned = COALESCE(?, pinned),
        updated_at = datetime('now')
      WHERE id = ?
    `).run(title, body, course_id, pinned !== undefined ? (pinned ? 1 : 0) : null, req.params.id);

    const updated = db.prepare(`
      SELECT a.*, u.first_name || ' ' || u.last_name AS instructor_name, c.title AS course_title
      FROM announcements a
      LEFT JOIN users u ON a.instructor_id = u.id
      LEFT JOIN courses c ON a.course_id = c.id
      WHERE a.id = ?
    `).get(req.params.id);

    res.json({ announcement: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/announcements/:id
router.delete('/:id', (req, res) => {
  try {
    const ann = db.prepare('SELECT * FROM announcements WHERE id = ?').get(req.params.id);
    if (!ann) return res.status(404).json({ error: 'Announcement not found' });
    if (ann.instructor_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not your announcement' });
    }

    db.prepare('DELETE FROM announcements WHERE id = ?').run(req.params.id);
    res.json({ message: 'Announcement deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/announcements/:id/pin  (instructor)
router.post('/:id/pin', (req, res) => {
  try {
    if (!['instructor', 'admin'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Instructor access required' });
    }

    const ann = db.prepare('SELECT * FROM announcements WHERE id = ?').get(req.params.id);
    if (!ann) return res.status(404).json({ error: 'Announcement not found' });
    if (ann.instructor_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not your announcement' });
    }

    const newPinned = ann.pinned ? 0 : 1;
    db.prepare(`UPDATE announcements SET pinned = ?, updated_at = datetime('now') WHERE id = ?`).run(newPinned, req.params.id);
    res.json({ pinned: newPinned === 1, message: newPinned ? 'Pinned' : 'Unpinned' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
