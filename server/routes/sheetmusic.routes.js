const express = require('express');
const router = express.Router();
const multer = require('multer');
const db = require('../db');
const requireRole = require('../middleware/role');
const { persistUpload } = require('../lib/storage');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// GET /api/sheet-music
router.get('/', (req, res) => {
  try {
    const { instrument, period, difficulty, search } = req.query;
    let query = `
      SELECT sm.*, u.first_name || ' ' || u.last_name AS uploader_name
      FROM sheet_music sm
      LEFT JOIN users u ON sm.uploaded_by = u.id
      WHERE 1=1
    `;
    const params = [];
    if (instrument) { query += ' AND sm.instrument = ?'; params.push(instrument); }
    if (period) { query += ' AND sm.period = ?'; params.push(period); }
    if (difficulty) { query += ' AND sm.difficulty = ?'; params.push(difficulty); }
    if (search) { query += ' AND (sm.title LIKE ? OR sm.composer LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
    query += ' ORDER BY sm.created_at DESC';

    const items = db.prepare(query).all(...params);
    res.json({ items });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/sheet-music/:id
router.get('/:id', (req, res) => {
  try {
    const item = db.prepare(`
      SELECT sm.*, u.first_name || ' ' || u.last_name AS uploader_name
      FROM sheet_music sm
      LEFT JOIN users u ON sm.uploaded_by = u.id
      WHERE sm.id = ?
    `).get(req.params.id);
    if (!item) return res.status(404).json({ error: 'Sheet music not found' });
    res.json({ item });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/sheet-music — instructor only
router.post('/', requireRole('instructor'), upload.fields([{ name: 'file', maxCount: 1 }, { name: 'preview', maxCount: 1 }]), async (req, res) => {
  try {
    const { title, composer, period, instrument, difficulty, page_count, course_id } = req.body;
    if (!title) return res.status(400).json({ error: 'Title is required' });

    const file_path = await persistUpload(req.files?.file?.[0], 'sheetmusic');
    const preview_path = await persistUpload(req.files?.preview?.[0], 'sheetmusic/preview');

    const result = db.prepare(`
      INSERT INTO sheet_music (title, composer, period, instrument, difficulty, file_path, preview_path, page_count, uploaded_by, course_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(title, composer || null, period || null, instrument || null, difficulty || null, file_path, preview_path, page_count || null, req.user.id, course_id || null);

    const item = db.prepare('SELECT * FROM sheet_music WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json({ item });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/sheet-music/:id — instructor only
router.delete('/:id', requireRole('instructor'), (req, res) => {
  try {
    const item = db.prepare('SELECT * FROM sheet_music WHERE id = ? AND uploaded_by = ?').get(req.params.id, req.user.id);
    if (!item) return res.status(404).json({ error: 'Sheet music not found or not authorized' });
    db.prepare('DELETE FROM sheet_music WHERE id = ?').run(req.params.id);
    res.json({ message: 'Sheet music deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
