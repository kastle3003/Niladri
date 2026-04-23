const express = require('express');
const router = express.Router();
const multer = require('multer');
const db = require('../db');
const { persistUpload } = require('../lib/storage');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 * 1024 } });

// Returns true if the current user is allowed to edit materials on this lesson.
// Admin: always. Instructor: only if they own the parent course.
function canEditLesson(req, lessonId) {
  if (req.user.role === 'admin') return true;
  if (req.user.role !== 'instructor') return false;
  const row = db.prepare(`
    SELECT c.instructor_id
    FROM lessons l JOIN courses c ON l.course_id = c.id
    WHERE l.id = ?
  `).get(lessonId);
  return row && row.instructor_id === req.user.id;
}
function canEditMaterial(req, materialId) {
  if (req.user.role === 'admin') return true;
  if (req.user.role !== 'instructor') return false;
  const row = db.prepare(`
    SELECT c.instructor_id
    FROM lesson_materials m
      JOIN lessons l ON m.lesson_id = l.id
      JOIN courses c ON l.course_id = c.id
    WHERE m.id = ?
  `).get(materialId);
  return row && row.instructor_id === req.user.id;
}

// GET /api/materials?lesson_id=N  — list materials (+timestamps) for a lesson
router.get('/', (req, res) => {
  try {
    const { lesson_id } = req.query;
    if (!lesson_id) return res.status(400).json({ error: 'lesson_id is required' });
    const materials = db.prepare(
      'SELECT * FROM lesson_materials WHERE lesson_id = ? ORDER BY order_index, id'
    ).all(lesson_id);
    const timestamps = db.prepare(`
      SELECT t.* FROM video_timestamps t
      JOIN lesson_materials m ON t.material_id = m.id
      WHERE m.lesson_id = ?
      ORDER BY t.material_id, t.time_seconds
    `).all(lesson_id);
    const byMaterial = {};
    timestamps.forEach(t => { (byMaterial[t.material_id] = byMaterial[t.material_id] || []).push(t); });
    res.json({ materials: materials.map(m => ({ ...m, timestamps: byMaterial[m.id] || [] })) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/materials  — add a material to a lesson.
// Accepts either JSON { lesson_id, type, title, url, ... } OR multipart with a `file` field
// (auto-uploaded to Wasabi; type is inferred from mime if not provided).
router.post('/', upload.single('file'), async (req, res) => {
  try {
    const { lesson_id, title, duration_seconds, order_index } = req.body;
    let { type, url } = req.body;
    if (!lesson_id) return res.status(400).json({ error: 'lesson_id is required' });
    if (!canEditLesson(req, lesson_id)) return res.status(403).json({ error: 'Not authorized to edit this lesson' });

    if (req.file) {
      url = await persistUpload(req.file, `lessons/${lesson_id}/materials`);
      if (!type) {
        const mt = (req.file.mimetype || '').toLowerCase();
        if (mt.startsWith('video/')) type = 'video';
        else if (mt.startsWith('image/')) type = 'image';
        else if (mt === 'application/pdf') type = 'pdf';
        else type = 'url';
      }
    }

    if (!type) return res.status(400).json({ error: 'type is required when no file is uploaded' });
    const VALID = ['video', 'url', 'image', 'pdf'];
    if (!VALID.includes(type)) return res.status(400).json({ error: `type must be one of ${VALID.join(', ')}` });

    const nextOrder = order_index != null
      ? order_index
      : (db.prepare('SELECT COALESCE(MAX(order_index),-1)+1 AS n FROM lesson_materials WHERE lesson_id = ?').get(lesson_id).n);

    const result = db.prepare(
      'INSERT INTO lesson_materials (lesson_id, type, title, url, duration_seconds, order_index) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(lesson_id, type, title || null, url || null, duration_seconds || null, nextOrder);

    const material = db.prepare('SELECT * FROM lesson_materials WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json({ material: { ...material, timestamps: [] } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/materials/:id  — update a material
router.put('/:id', (req, res) => {
  try {
    if (!canEditMaterial(req, req.params.id)) return res.status(403).json({ error: 'Not authorized' });
    const existing = db.prepare('SELECT * FROM lesson_materials WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Material not found' });
    const { type, title, url, duration_seconds, order_index } = req.body;
    db.prepare(
      'UPDATE lesson_materials SET type=?, title=?, url=?, duration_seconds=?, order_index=? WHERE id=?'
    ).run(
      type || existing.type,
      title !== undefined ? title : existing.title,
      url !== undefined ? url : existing.url,
      duration_seconds !== undefined ? duration_seconds : existing.duration_seconds,
      order_index !== undefined ? order_index : existing.order_index,
      req.params.id
    );
    res.json({ material: db.prepare('SELECT * FROM lesson_materials WHERE id = ?').get(req.params.id) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/materials/:id
router.delete('/:id', (req, res) => {
  try {
    if (!canEditMaterial(req, req.params.id)) return res.status(403).json({ error: 'Not authorized' });
    db.prepare('DELETE FROM lesson_materials WHERE id = ?').run(req.params.id);
    res.json({ message: 'Material deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Timestamps ──────────────────────────────────────────────────────────────

// GET /api/materials/:id/timestamps
router.get('/:id/timestamps', (req, res) => {
  try {
    const timestamps = db.prepare(
      'SELECT * FROM video_timestamps WHERE material_id = ? ORDER BY time_seconds'
    ).all(req.params.id);
    res.json({ timestamps });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/materials/:id/timestamps  — add a timestamp manually
// body: { time_seconds, label }
router.post('/:id/timestamps', (req, res) => {
  try {
    if (!canEditMaterial(req, req.params.id)) return res.status(403).json({ error: 'Not authorized' });
    const material = db.prepare('SELECT * FROM lesson_materials WHERE id = ?').get(req.params.id);
    if (!material) return res.status(404).json({ error: 'Material not found' });
    if (material.type !== 'video') return res.status(400).json({ error: 'Timestamps are only allowed on video materials' });

    const { time_seconds, label } = req.body;
    if (time_seconds == null || Number(time_seconds) < 0) return res.status(400).json({ error: 'time_seconds must be >= 0' });

    const nextOrder = db.prepare('SELECT COALESCE(MAX(order_index),-1)+1 AS n FROM video_timestamps WHERE material_id = ?').get(req.params.id).n;
    const result = db.prepare(
      'INSERT INTO video_timestamps (material_id, time_seconds, label, order_index) VALUES (?, ?, ?, ?)'
    ).run(req.params.id, Math.round(Number(time_seconds)), label || null, nextOrder);

    const ts = db.prepare('SELECT * FROM video_timestamps WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json({ timestamp: ts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/materials/:id/timestamps/auto  — auto-generate 1-min markers
// body (optional): { interval_seconds (default 60), duration_seconds (overrides material field) }
router.post('/:id/timestamps/auto', (req, res) => {
  try {
    if (!canEditMaterial(req, req.params.id)) return res.status(403).json({ error: 'Not authorized' });
    const material = db.prepare('SELECT * FROM lesson_materials WHERE id = ?').get(req.params.id);
    if (!material) return res.status(404).json({ error: 'Material not found' });
    if (material.type !== 'video') return res.status(400).json({ error: 'Timestamps are only allowed on video materials' });

    const interval = Math.max(10, parseInt(req.body.interval_seconds) || 60);
    const duration = parseInt(req.body.duration_seconds) || material.duration_seconds;
    if (!duration) return res.status(400).json({ error: 'duration_seconds is required (or set on the material)' });

    // Replace any existing timestamps for this material
    db.prepare('DELETE FROM video_timestamps WHERE material_id = ?').run(req.params.id);

    const insert = db.prepare('INSERT INTO video_timestamps (material_id, time_seconds, label, order_index) VALUES (?, ?, ?, ?)');
    let idx = 0;
    for (let t = interval; t < duration; t += interval) {
      const minute = Math.floor(t / 60);
      const seconds = t % 60;
      const label = seconds === 0 ? `Minute ${minute}` : `${minute}m ${seconds}s`;
      insert.run(req.params.id, t, label, idx++);
    }

    // Persist duration on the material if the caller provided it
    if (req.body.duration_seconds && !material.duration_seconds) {
      db.prepare('UPDATE lesson_materials SET duration_seconds = ? WHERE id = ?').run(duration, req.params.id);
    }

    const timestamps = db.prepare('SELECT * FROM video_timestamps WHERE material_id = ? ORDER BY time_seconds').all(req.params.id);
    res.json({ timestamps, count: timestamps.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/materials/:mid/timestamps/:tsid
router.put('/:mid/timestamps/:tsid', (req, res) => {
  try {
    if (!canEditMaterial(req, req.params.mid)) return res.status(403).json({ error: 'Not authorized' });
    const existing = db.prepare('SELECT * FROM video_timestamps WHERE id = ? AND material_id = ?').get(req.params.tsid, req.params.mid);
    if (!existing) return res.status(404).json({ error: 'Timestamp not found' });
    const { time_seconds, label } = req.body;
    db.prepare('UPDATE video_timestamps SET time_seconds=?, label=? WHERE id=?')
      .run(time_seconds != null ? Math.round(Number(time_seconds)) : existing.time_seconds, label !== undefined ? label : existing.label, req.params.tsid);
    res.json({ timestamp: db.prepare('SELECT * FROM video_timestamps WHERE id = ?').get(req.params.tsid) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/materials/:mid/timestamps/:tsid
router.delete('/:mid/timestamps/:tsid', (req, res) => {
  try {
    if (!canEditMaterial(req, req.params.mid)) return res.status(403).json({ error: 'Not authorized' });
    db.prepare('DELETE FROM video_timestamps WHERE id = ? AND material_id = ?').run(req.params.tsid, req.params.mid);
    res.json({ message: 'Timestamp deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
