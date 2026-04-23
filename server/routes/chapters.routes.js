const router = require('express').Router();
const db = require('../db');
const requireRole = require('../middleware/role');

// Only the owning instructor or any admin can write to chapters of a course.
function canEditCourse(req, courseId) {
  if (req.user.role === 'admin') return true;
  if (req.user.role !== 'instructor') return false;
  const row = db.prepare('SELECT instructor_id FROM courses WHERE id = ?').get(courseId);
  return row && row.instructor_id === req.user.id;
}
function canEditChapter(req, chapterId) {
  const row = db.prepare(`
    SELECT c.instructor_id, c.id AS course_id
    FROM chapters ch JOIN courses c ON ch.course_id = c.id
    WHERE ch.id = ?
  `).get(chapterId);
  if (!row) return { ok: false, code: 404 };
  if (req.user.role === 'admin') return { ok: true, course_id: row.course_id };
  if (req.user.role === 'instructor' && row.instructor_id === req.user.id) return { ok: true, course_id: row.course_id };
  return { ok: false, code: 403 };
}

// GET /api/chapters?course_id=X  (instructor authoring view — owner-gated)
router.get('/', (req, res) => {
  try {
    const { course_id } = req.query;
    if (!course_id) return res.status(400).json({ error: 'course_id is required' });
    // Instructors may only read chapters for courses they own. Admins see all.
    // (Students read chapters via GET /api/courses/:id/chapters with progress merge.)
    if (req.user && req.user.role === 'instructor' && !canEditCourse(req, course_id)) {
      return res.status(403).json({ error: 'Not authorized to view this course' });
    }
    const chapters = db.prepare('SELECT * FROM chapters WHERE course_id = ? ORDER BY order_index').all(course_id);
    const lessons = db.prepare('SELECT * FROM lessons WHERE course_id = ? ORDER BY order_index').all(course_id);
    const result = chapters.map(ch => ({
      ...ch,
      lessons: lessons.filter(l => l.chapter_id === ch.id)
    }));
    res.json({ chapters: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/chapters — instructor (own course) or admin
router.post('/', requireRole(['instructor', 'admin']), (req, res) => {
  try {
    const { course_id, title, order_index, description } = req.body;
    if (!course_id || !title) return res.status(400).json({ error: 'course_id and title are required' });
    if (!canEditCourse(req, course_id)) return res.status(403).json({ error: 'Not authorized to edit this course' });

    const nextOrder = order_index != null
      ? order_index
      : (db.prepare('SELECT COALESCE(MAX(order_index),-1)+1 AS n FROM chapters WHERE course_id = ?').get(course_id).n);

    const result = db.prepare(
      'INSERT INTO chapters (course_id, title, order_index, description) VALUES (?, ?, ?, ?)'
    ).run(course_id, title, nextOrder, description || '');
    res.status(201).json({ id: result.lastInsertRowid, course_id, title, order_index: nextOrder, description: description || '', lessons: [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/chapters/:id
router.put('/:id', requireRole(['instructor', 'admin']), (req, res) => {
  try {
    const g = canEditChapter(req, req.params.id);
    if (!g.ok) return res.status(g.code).json({ error: g.code === 404 ? 'Chapter not found' : 'Not authorized' });

    const existing = db.prepare('SELECT * FROM chapters WHERE id = ?').get(req.params.id);
    const { title, order_index, description } = req.body;
    db.prepare('UPDATE chapters SET title = ?, order_index = ?, description = ? WHERE id = ?')
      .run(
        title !== undefined ? title : existing.title,
        order_index !== undefined ? order_index : existing.order_index,
        description !== undefined ? description : existing.description,
        req.params.id
      );
    res.json({ message: 'Chapter updated', chapter: db.prepare('SELECT * FROM chapters WHERE id = ?').get(req.params.id) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/chapters/:id
router.delete('/:id', requireRole(['instructor', 'admin']), (req, res) => {
  try {
    const g = canEditChapter(req, req.params.id);
    if (!g.ok) return res.status(g.code).json({ error: g.code === 404 ? 'Chapter not found' : 'Not authorized' });

    db.prepare('DELETE FROM lessons WHERE chapter_id = ?').run(req.params.id);
    db.prepare('DELETE FROM chapters WHERE id = ?').run(req.params.id);
    db.prepare('UPDATE courses SET lesson_count = (SELECT COUNT(*) FROM lessons WHERE course_id = ?) WHERE id = ?').run(g.course_id, g.course_id);
    res.json({ message: 'Chapter deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
