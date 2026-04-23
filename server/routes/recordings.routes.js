const express = require('express');
const router = express.Router();
const multer = require('multer');
const db = require('../db');
const { persistUpload } = require('../lib/storage');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200 * 1024 * 1024 } });

// GET /api/recordings/me
router.get('/me', (req, res) => {
  try {
    const recordings = db.prepare(`
      SELECT r.*, c.title AS course_title, l.title AS lesson_title
      FROM recordings r
      LEFT JOIN courses c ON r.course_id = c.id
      LEFT JOIN lessons l ON r.lesson_id = l.id
      WHERE r.student_id = ?
      ORDER BY r.created_at DESC
    `).all(req.user.id);
    res.json({ recordings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/recordings/:id
router.get('/:id', (req, res) => {
  try {
    const recording = db.prepare(`
      SELECT r.*, c.title AS course_title, l.title AS lesson_title
      FROM recordings r
      LEFT JOIN courses c ON r.course_id = c.id
      LEFT JOIN lessons l ON r.lesson_id = l.id
      WHERE r.id = ? AND r.student_id = ?
    `).get(req.params.id, req.user.id);
    if (!recording) return res.status(404).json({ error: 'Recording not found' });
    res.json({ recording });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/recordings
router.post('/', upload.single('audio'), async (req, res) => {
  try {
    const { course_id, lesson_id, title, duration_seconds, waveform_data, notes } = req.body;
    const file_path = await persistUpload(req.file, 'recordings');

    const result = db.prepare(`
      INSERT INTO recordings (student_id, course_id, lesson_id, title, file_path, duration_seconds, waveform_data, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id, course_id || null, lesson_id || null,
      title || 'Untitled Recording', file_path,
      duration_seconds || null, waveform_data || null, notes || null
    );

    const recording = db.prepare('SELECT * FROM recordings WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json({ recording });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/recordings/:id
router.put('/:id', (req, res) => {
  try {
    const recording = db.prepare('SELECT * FROM recordings WHERE id = ? AND student_id = ?').get(req.params.id, req.user.id);
    if (!recording) return res.status(404).json({ error: 'Recording not found or not authorized' });

    const { title, notes } = req.body;
    db.prepare('UPDATE recordings SET title = ?, notes = ? WHERE id = ?').run(title || recording.title, notes !== undefined ? notes : recording.notes, req.params.id);

    const updated = db.prepare('SELECT * FROM recordings WHERE id = ?').get(req.params.id);
    res.json({ recording: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/recordings/:id
router.delete('/:id', (req, res) => {
  try {
    const result = db.prepare('DELETE FROM recordings WHERE id = ? AND student_id = ?').run(req.params.id, req.user.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Recording not found or not authorized' });
    res.json({ message: 'Recording deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
