const express = require('express');
const router = express.Router();
const multer = require('multer');
const db = require('../db');
const requireRole = require('../middleware/role');
const { persistUpload } = require('../lib/storage');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

function slugify(str) {
  return (str || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}
function uniqueSlug(base, excludeId) {
  let slug = base, n = 2;
  while (db.prepare('SELECT id FROM courses WHERE slug = ? AND (? IS NULL OR id != ?)').get(slug, excludeId || null, excludeId || null)) {
    slug = `${base}-${n++}`;
  }
  return slug;
}

// GET /api/courses
// Role-aware listing:
//   - instructor  → only courses they own (regardless of query params)
//   - admin       → all courses
//   - student/etc → active courses (filterable via query params)
router.get('/', (req, res) => {
  try {
    const { level, category, instrument, search, status } = req.query;
    let query = `
      SELECT c.*, u.first_name || ' ' || u.last_name AS instructor_name
      FROM courses c
      LEFT JOIN users u ON c.instructor_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (req.user && req.user.role === 'instructor') {
      query += ' AND c.instructor_id = ?';
      params.push(req.user.id);
      // Instructors see all their courses regardless of status (drafts, active, archived)
    } else {
      if (status && status !== 'all') { query += ' AND c.status = ?'; params.push(status); }
      else if (!status) { query += " AND c.status = 'active'"; }
    }
    if (level) { query += ' AND c.level = ?'; params.push(level); }
    if (category) { query += ' AND c.category = ?'; params.push(category); }
    if (instrument) { query += ' AND c.instrument = ?'; params.push(instrument); }
    if (search) { query += ' AND c.title LIKE ?'; params.push(`%${search}%`); }

    query += ' ORDER BY c.created_at DESC';
    const courses = db.prepare(query).all(...params);
    res.json({ courses });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/courses/:id
router.get('/:id', (req, res) => {
  try {
    const course = db.prepare(`
      SELECT c.*, u.first_name || ' ' || u.last_name AS instructor_name, u.bio AS instructor_bio, u.avatar_initials AS instructor_initials
      FROM courses c
      LEFT JOIN users u ON c.instructor_id = u.id
      WHERE c.id = ?
    `).get(req.params.id);
    if (!course) return res.status(404).json({ error: 'Course not found' });
    res.json({ course });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/courses/:id/chapters
router.get('/:id/chapters', (req, res) => {
  try {
    const chapters = db.prepare('SELECT * FROM chapters WHERE course_id = ? ORDER BY order_index').all(req.params.id);
    const lessonsAll = db.prepare('SELECT * FROM lessons WHERE course_id = ? ORDER BY order_index').all(req.params.id);

    // If student, also get their progress
    const progressMap = {};
    if (req.user.role === 'student') {
      const progress = db.prepare('SELECT lesson_id, completed FROM lesson_progress WHERE student_id = ?').all(req.user.id);
      progress.forEach(p => { progressMap[p.lesson_id] = p.completed; });
    }

    const result = chapters.map(ch => ({
      ...ch,
      lessons: lessonsAll
        .filter(l => l.chapter_id === ch.id)
        .map(l => ({ ...l, completed: progressMap[l.id] ? true : false }))
    }));

    res.json({ chapters: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/courses — instructor or admin
router.post('/', requireRole(['instructor', 'admin']), upload.single('cover_image'), async (req, res) => {
  try {
    const { title, subtitle, description, instrument, level, category, cover_color, cover_accent, cover_image_url, duration_weeks, instructor_id } = req.body;
    if (!title) return res.status(400).json({ error: 'Title is required' });

    // Admin may create on behalf of another instructor; instructor is always the author
    const ownerId = (req.user.role === 'admin' && instructor_id) ? instructor_id : req.user.id;

    let finalCoverUrl = cover_image_url || (db.defaultCoverForLevel ? db.defaultCoverForLevel(level) : null);
    if (req.file) {
      finalCoverUrl = await persistUpload(req.file, 'courses/covers');
    }

    const result = db.prepare(`
      INSERT INTO courses (title, subtitle, description, instructor_id, instrument, level, category, cover_color, cover_accent, cover_image_url, duration_weeks)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      title, subtitle || null, description || null, ownerId,
      instrument || null, level || null, category || null,
      cover_color || '#2D4F1E', cover_accent || '#D1A14E',
      finalCoverUrl,
      duration_weeks || null
    );
    const newId = result.lastInsertRowid;

    // Auto-generate a unique slug so Preview links are pretty + future-proof
    const slug = uniqueSlug(slugify(title) || `course-${newId}`, newId);
    db.prepare('UPDATE courses SET slug = ? WHERE id = ?').run(slug, newId);

    // Seed 5 default Foundations (A-E) so the course-landing tabs render
    // a meaningful structure out of the box; instructor can rename/add/delete.
    const insertChapter = db.prepare(
      'INSERT INTO chapters (course_id, title, order_index, description) VALUES (?, ?, ?, ?)'
    );
    ['A', 'B', 'C', 'D', 'E'].forEach((letter, i) => {
      insertChapter.run(newId, `Foundation '${letter}'`, i, '');
    });

    const course = db.prepare('SELECT * FROM courses WHERE id = ?').get(newId);
    res.status(201).json({ course });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/courses/:id — instructor (own course) or admin (any course)
router.put('/:id', requireRole(['instructor', 'admin']), upload.single('cover_image'), async (req, res) => {
  try {
    const { title, subtitle, description, instrument, level, category, cover_color, cover_accent, cover_image_url, duration_weeks, status } = req.body;
    let course;
    if (req.user.role === 'admin') {
      course = db.prepare('SELECT * FROM courses WHERE id = ?').get(req.params.id);
    } else {
      course = db.prepare('SELECT * FROM courses WHERE id = ? AND instructor_id = ?').get(req.params.id, req.user.id);
    }
    if (!course) return res.status(404).json({ error: 'Course not found or not authorized' });

    let finalCoverUrl = cover_image_url !== undefined ? cover_image_url : course.cover_image_url;
    if (req.file) {
      finalCoverUrl = await persistUpload(req.file, 'courses/covers');
    }

    db.prepare(`
      UPDATE courses SET title = ?, subtitle = ?, description = ?, instrument = ?, level = ?, category = ?, cover_color = ?, cover_accent = ?, cover_image_url = ?, duration_weeks = ?, status = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(
      title || course.title, subtitle || course.subtitle, description || course.description,
      instrument || course.instrument, level || course.level, category || course.category,
      cover_color || course.cover_color, cover_accent || course.cover_accent,
      finalCoverUrl,
      duration_weeks || course.duration_weeks, status || course.status, req.params.id
    );

    const updated = db.prepare('SELECT * FROM courses WHERE id = ?').get(req.params.id);
    res.json({ course: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/courses/:id — instructor (own) or admin (any)
router.delete('/:id', requireRole(['instructor', 'admin']), (req, res) => {
  try {
    let course;
    if (req.user.role === 'admin') {
      course = db.prepare('SELECT * FROM courses WHERE id = ?').get(req.params.id);
    } else {
      course = db.prepare('SELECT * FROM courses WHERE id = ? AND instructor_id = ?').get(req.params.id, req.user.id);
    }
    if (!course) return res.status(404).json({ error: 'Course not found or not authorized' });

    db.prepare('DELETE FROM courses WHERE id = ?').run(req.params.id);
    res.json({ message: 'Course deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
