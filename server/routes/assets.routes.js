const express = require('express');
const router = express.Router();
const db = require('../db');
const access = require('../lib/access');

// GET /api/assets/:lesson_id
// Lists the assets (materials) for a lesson. Mirrors /api/materials?lesson_id=…
// but always gates videos/download URLs behind completion when the lesson isn't a preview.
router.get('/:lesson_id', (req, res) => {
  try {
    const lesson = access.getLesson(req.params.lesson_id);
    if (!lesson) return res.status(404).json({ error: 'Lesson not found' });

    const acc = access.canAccessLecture(req.user, lesson.id);
    if (!acc.allowed) {
      return res.status(403).json({ error: 'Access denied', reason: acc.reason, blocked_by: acc.blocked_by });
    }

    const completed = access.isLessonCompleted(req.user.id, lesson.id);
    const materials = db.prepare(
      'SELECT * FROM lesson_materials WHERE lesson_id = ? ORDER BY order_index, id'
    ).all(lesson.id);

    const shaped = materials.map(m => ({
      id: m.id,
      lesson_id: m.lesson_id,
      type: m.type,
      title: m.title,
      order_index: m.order_index,
      preview_url: m.url, // always returned so the UI can show a thumbnail / header
      downloadable: (access.isStaff(req.user) || !!lesson.is_preview || completed),
      download_url: (access.isStaff(req.user) || !!lesson.is_preview || completed)
        ? `/api/assets/download/${m.id}`
        : null,
    }));

    res.json({
      lesson_id: lesson.id,
      is_preview: !!lesson.is_preview,
      lesson_completed: completed,
      assets: shaped,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/assets/download/:material_id
// Streaming/redirect endpoint. Blocks when the owning lesson isn't completed
// (unless the lesson is a preview or the caller is staff). Returns 302 to the
// resource URL today — swap to a signed S3/R2 URL in production.
router.get('/download/:material_id', (req, res) => {
  try {
    const m = db.prepare('SELECT * FROM lesson_materials WHERE id = ?').get(req.params.material_id);
    if (!m) return res.status(404).json({ error: 'Asset not found' });
    const lesson = access.getLesson(m.lesson_id);
    if (!lesson) return res.status(404).json({ error: 'Parent lesson not found' });

    // 1. Must be able to even view the lecture.
    const acc = access.canAccessLecture(req.user, lesson.id);
    if (!acc.allowed) {
      return res.status(403).json({ error: 'Access denied', reason: acc.reason, blocked_by: acc.blocked_by });
    }

    // 2. Must have completed the lecture (preview lectures and staff bypass).
    if (!lesson.is_preview && !access.isStaff(req.user) && !access.isLessonCompleted(req.user.id, lesson.id)) {
      return res.status(403).json({
        error: 'Complete the lecture before downloading its assets',
        reason: 'lecture_not_completed',
      });
    }

    if (m.url) {
      // In production: generate a signed S3/R2 URL here with a short TTL.
      return res.redirect(302, m.url);
    }
    if (m.file_path) {
      return res.download(m.file_path);
    }
    return res.status(404).json({ error: 'No downloadable content on this asset' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
