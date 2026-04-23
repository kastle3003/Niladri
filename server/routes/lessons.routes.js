const express = require('express');
const router = express.Router();
const multer = require('multer');
const db = require('../db');
const access = require('../lib/access');
const requireRole = require('../middleware/role');
const { persistUpload } = require('../lib/storage');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 * 1024 } }); // 2GB for video

function canEditCourse(req, courseId) {
  if (req.user.role === 'admin') return true;
  if (req.user.role !== 'instructor') return false;
  const row = db.prepare('SELECT instructor_id FROM courses WHERE id = ?').get(courseId);
  return row && row.instructor_id === req.user.id;
}
function canEditLesson(req, lessonId) {
  const row = db.prepare(`
    SELECT c.instructor_id, l.course_id
    FROM lessons l JOIN courses c ON l.course_id = c.id
    WHERE l.id = ?
  `).get(lessonId);
  if (!row) return { ok: false, code: 404 };
  if (req.user.role === 'admin') return { ok: true, course_id: row.course_id };
  if (req.user.role === 'instructor' && row.instructor_id === req.user.id) return { ok: true, course_id: row.course_id };
  return { ok: false, code: 403 };
}

// GET /api/lessons?course_id=X
router.get('/', (req, res) => {
  try {
    const { course_id } = req.query;
    let query = 'SELECT * FROM lessons WHERE 1=1';
    const params = [];
    if (course_id) { query += ' AND course_id = ?'; params.push(course_id); }
    query += ' ORDER BY course_id, order_index';
    const lessons = db.prepare(query).all(...params);
    res.json({ lessons });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/lessons/:id — includes materials + timestamps for the lesson viewer
router.get('/:id', (req, res) => {
  try {
    const lesson = db.prepare('SELECT * FROM lessons WHERE id = ?').get(req.params.id);
    if (!lesson) return res.status(404).json({ error: 'Lesson not found' });

    const acc = access.canAccessLecture(req.user, lesson.id);
    if (!acc.allowed) {
      return res.status(403).json({
        error: 'Access denied',
        reason: acc.reason,
        blocked_by: acc.blocked_by,
        lesson: {
          id: lesson.id,
          chapter_id: lesson.chapter_id,
          course_id: lesson.course_id,
          title: lesson.title,
          is_preview: !!lesson.is_preview,
          duration_minutes: lesson.duration_minutes,
          duration_seconds: lesson.duration_seconds,
        },
      });
    }

    const materials = db.prepare(
      'SELECT * FROM lesson_materials WHERE lesson_id = ? ORDER BY order_index, id'
    ).all(lesson.id);
    const timestamps = db.prepare(`
      SELECT t.* FROM video_timestamps t
      JOIN lesson_materials m ON t.material_id = m.id
      WHERE m.lesson_id = ?
      ORDER BY t.material_id, t.time_seconds
    `).all(lesson.id);
    const byMaterial = {};
    timestamps.forEach(t => { (byMaterial[t.material_id] = byMaterial[t.material_id] || []).push(t); });
    lesson.materials = materials.map(m => ({ ...m, timestamps: byMaterial[m.id] || [] }));

    const p = access.getLessonProgress(req.user.id, lesson.id);
    lesson.progress = {
      watched_seconds: p ? (p.watched_seconds || 0) : 0,
      last_position: p ? (p.last_position || 0) : 0,
      completion_percentage: p ? (p.completion_percentage || 0) : 0,
      is_completed: !!(p && p.completed === 1),
    };

    res.json({ lesson });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/lessons — create new lesson. Accepts either:
//   - JSON body with content_url set, OR
//   - multipart with a `video` file (streamed to Wasabi).
router.post('/', requireRole(['instructor', 'admin']), upload.single('video'), async (req, res) => {
  try {
    const { chapter_id, course_id, title, type, duration_minutes, order_index, content_url, is_preview } = req.body;
    if (!chapter_id || !course_id || !title) {
      return res.status(400).json({ error: 'chapter_id, course_id and title are required' });
    }
    if (!canEditCourse(req, course_id)) return res.status(403).json({ error: 'Not authorized to edit this course' });

    let finalContentUrl = content_url || null;
    if (req.file) {
      finalContentUrl = await persistUpload(req.file, `courses/${course_id}/lessons`);
    }

    const nextOrder = order_index != null
      ? order_index
      : (db.prepare('SELECT COALESCE(MAX(order_index),-1)+1 AS n FROM lessons WHERE chapter_id = ?').get(chapter_id).n);

    const result = db.prepare(
      'INSERT INTO lessons (chapter_id, course_id, title, order_index, type, content_url, duration_minutes, is_preview) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(
      chapter_id, course_id, title, nextOrder,
      type || 'video', finalContentUrl, duration_minutes || null,
      is_preview === '1' || is_preview === 1 || is_preview === true || is_preview === 'true' ? 1 : 0
    );
    db.prepare('UPDATE courses SET lesson_count = (SELECT COUNT(*) FROM lessons WHERE course_id = ?) WHERE id = ?').run(course_id, course_id);
    const lesson = db.prepare('SELECT * FROM lessons WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json({ lesson });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/lessons/:id — update lesson (optionally replace video file)
router.put('/:id', requireRole(['instructor', 'admin']), upload.single('video'), async (req, res) => {
  try {
    const g = canEditLesson(req, req.params.id);
    if (!g.ok) return res.status(g.code).json({ error: g.code === 404 ? 'Lesson not found' : 'Not authorized' });

    const existing = db.prepare('SELECT * FROM lessons WHERE id = ?').get(req.params.id);
    const { title, type, duration_minutes, order_index, content_url, is_preview } = req.body;

    let finalContentUrl = content_url !== undefined ? content_url : existing.content_url;
    if (req.file) {
      finalContentUrl = await persistUpload(req.file, `courses/${existing.course_id}/lessons`);
    }

    db.prepare(
      'UPDATE lessons SET title = ?, type = ?, duration_minutes = ?, order_index = ?, content_url = ?, is_preview = ? WHERE id = ?'
    ).run(
      title !== undefined ? title : existing.title,
      type || existing.type || 'video',
      duration_minutes !== undefined ? duration_minutes : existing.duration_minutes,
      order_index !== undefined ? order_index : existing.order_index,
      finalContentUrl,
      is_preview !== undefined
        ? (is_preview === '1' || is_preview === 1 || is_preview === true || is_preview === 'true' ? 1 : 0)
        : existing.is_preview,
      req.params.id
    );
    res.json({ lesson: db.prepare('SELECT * FROM lessons WHERE id = ?').get(req.params.id) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/lessons/:id
router.delete('/:id', requireRole(['instructor', 'admin']), (req, res) => {
  try {
    const g = canEditLesson(req, req.params.id);
    if (!g.ok) return res.status(g.code).json({ error: g.code === 404 ? 'Lesson not found' : 'Not authorized' });

    db.prepare('DELETE FROM lessons WHERE id = ?').run(req.params.id);
    db.prepare('UPDATE courses SET lesson_count = (SELECT COUNT(*) FROM lessons WHERE course_id = ?) WHERE id = ?').run(g.course_id, g.course_id);
    res.json({ message: 'Lesson deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/lessons/:id/complete
router.post('/:id/complete', (req, res) => {
  try {
    const lesson = db.prepare('SELECT * FROM lessons WHERE id = ?').get(req.params.id);
    if (!lesson) return res.status(404).json({ error: 'Lesson not found' });

    db.prepare(`
      INSERT INTO lesson_progress (student_id, lesson_id, completed, completed_at)
      VALUES (?, ?, 1, datetime('now'))
      ON CONFLICT(student_id, lesson_id) DO UPDATE SET completed = 1, completed_at = datetime('now')
    `).run(req.user.id, lesson.id);

    const enrollment = db.prepare('SELECT * FROM enrollments WHERE student_id = ? AND course_id = ?').get(req.user.id, lesson.course_id);
    if (enrollment) {
      const totalLessons = db.prepare('SELECT COUNT(*) as count FROM lessons WHERE course_id = ?').get(lesson.course_id);
      const completedLessons = db.prepare(`
        SELECT COUNT(*) as count FROM lesson_progress lp
        JOIN lessons l ON lp.lesson_id = l.id
        WHERE lp.student_id = ? AND l.course_id = ? AND lp.completed = 1
      `).get(req.user.id, lesson.course_id);

      const progress_pct = totalLessons.count > 0
        ? Math.round((completedLessons.count / totalLessons.count) * 100)
        : 0;

      db.prepare(`UPDATE enrollments SET progress_pct = ?, last_accessed_at = datetime('now') WHERE student_id = ? AND course_id = ?`)
        .run(progress_pct, req.user.id, lesson.course_id);

      res.json({ message: 'Lesson marked as complete', progress_pct });
    } else {
      res.json({ message: 'Lesson marked as complete' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
