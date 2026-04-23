const express = require('express');
const router = express.Router();
const db = require('../db');

// GET /api/search?q=:query&type=all|courses|students|sheet_music|resources
router.get('/', (req, res) => {
  try {
    const { q, type = 'all' } = req.query;
    if (!q || q.trim().length < 1) {
      return res.json({ results: [], counts: { courses: 0, students: 0, sheet_music: 0, masterclasses: 0, resources: 0 } });
    }

    const query = q.trim();
    const likeQ = `%${query}%`;
    const exactQ = query.toLowerCase();

    const results = [];
    const counts = { courses: 0, students: 0, sheet_music: 0, masterclasses: 0, resources: 0 };

    function scoreResult(item, fields) {
      // Exact match gets higher score
      for (const f of fields) {
        if (item[f] && item[f].toLowerCase() === exactQ) return 2;
        if (item[f] && item[f].toLowerCase().startsWith(exactQ)) return 1;
      }
      return 0;
    }

    // Courses
    if (type === 'all' || type === 'courses') {
      const courses = db.prepare(`
        SELECT c.id, c.title, c.subtitle, c.level, c.cover_color, c.instrument,
          u.first_name || ' ' || u.last_name AS instructor_name
        FROM courses c
        LEFT JOIN users u ON c.instructor_id = u.id
        WHERE (c.title LIKE ? OR c.subtitle LIKE ? OR c.description LIKE ?)
          AND c.status = 'active'
        LIMIT 20
      `).all(likeQ, likeQ, likeQ);

      courses.forEach(c => {
        results.push({ type: 'course', id: c.id, title: c.title, level: c.level, cover_color: c.cover_color, instructor_name: c.instructor_name, _score: scoreResult(c, ['title', 'subtitle']) });
      });
      counts.courses = courses.length;
    }

    // Students (instructor only)
    if ((type === 'all' || type === 'students') && ['instructor', 'admin'].includes(req.user.role)) {
      const students = db.prepare(`
        SELECT id, first_name, last_name, email, instrument, role
        FROM users
        WHERE (first_name LIKE ? OR last_name LIKE ? OR email LIKE ?)
        LIMIT 20
      `).all(likeQ, likeQ, likeQ);

      students.forEach(s => {
        results.push({
          type: 'user',
          id: s.id,
          name: s.first_name + ' ' + s.last_name,
          instrument: s.instrument,
          role: s.role,
          email: s.email,
          _score: scoreResult({ name: s.first_name + ' ' + s.last_name, email: s.email }, ['name', 'email'])
        });
      });
      counts.students = students.length;
    }

    // Sheet Music
    if (type === 'all' || type === 'sheet_music') {
      let sheetMusics = [];
      try {
        sheetMusics = db.prepare(`
          SELECT id, title, composer, period, difficulty
          FROM sheet_music
          WHERE title LIKE ? OR composer LIKE ?
          LIMIT 20
        `).all(likeQ, likeQ);
      } catch (e) { /* table may not exist yet */ }

      sheetMusics.forEach(sm => {
        results.push({ type: 'sheet_music', id: sm.id, title: sm.title, composer: sm.composer, period: sm.period, _score: scoreResult(sm, ['title', 'composer']) });
      });
      counts.sheet_music = sheetMusics.length;
    }

    // Masterclasses
    if (type === 'all' || type === 'masterclasses') {
      let masterclasses = [];
      try {
        masterclasses = db.prepare(`
          SELECT m.id, m.title, m.scheduled_at,
            u.first_name || ' ' || u.last_name AS instructor_name
          FROM masterclasses m
          LEFT JOIN users u ON m.instructor_id = u.id
          WHERE m.title LIKE ?
          LIMIT 20
        `).all(likeQ);
      } catch (e) { /* table may not exist yet */ }

      masterclasses.forEach(mc => {
        results.push({ type: 'masterclass', id: mc.id, title: mc.title, scheduled_at: mc.scheduled_at, instructor_name: mc.instructor_name, _score: scoreResult(mc, ['title']) });
      });
      counts.masterclasses = masterclasses.length;
    }

    // Resources
    if (type === 'all' || type === 'resources') {
      let resources = [];
      try {
        resources = db.prepare(`
          SELECT r.id, r.title, r.file_type, r.course_id, c.title AS course_title
          FROM resources r
          LEFT JOIN courses c ON r.course_id = c.id
          WHERE (r.title LIKE ? OR r.description LIKE ?)
            AND (r.is_public = 1 OR r.uploaded_by = ?)
          LIMIT 20
        `).all(likeQ, likeQ, req.user.id);
      } catch (e) { /* table may not exist yet */ }

      resources.forEach(r => {
        results.push({ type: 'resource', id: r.id, title: r.title, file_type: r.file_type, course_id: r.course_id, course_title: r.course_title, _score: scoreResult(r, ['title']) });
      });
      counts.resources = resources.length;
    }

    // Sort: exact match first (score 2), then starts-with (score 1), then rest
    results.sort((a, b) => (b._score || 0) - (a._score || 0));
    results.forEach(r => delete r._score);

    res.json({ results, counts, query });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
