const express = require('express');
const router = express.Router();
const db = require('../db');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { persistUpload, presignedUrl, deleteObject, wasabiEnabled } = require('../lib/storage');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200 * 1024 * 1024 } });

// GET /api/resources?course_id=:id&lesson_id=:id&category=:cat
router.get('/', (req, res) => {
  try {
    const { course_id, lesson_id, category } = req.query;
    let query = `
      SELECT r.*,
        u.first_name || ' ' || u.last_name AS uploader_name,
        c.title AS course_title
      FROM resources r
      LEFT JOIN users u ON r.uploaded_by = u.id
      LEFT JOIN courses c ON r.course_id = c.id
      WHERE (r.is_public = 1 OR r.uploaded_by = ?
    `;
    const params = [req.user.id];

    // Students can access resources for their enrolled courses
    if (req.user.role === 'student') {
      query += ` OR r.course_id IN (SELECT course_id FROM enrollments WHERE student_id = ?)`;
      params.push(req.user.id);
    }

    query += ')';

    if (course_id) { query += ' AND r.course_id = ?'; params.push(course_id); }
    if (lesson_id) { query += ' AND r.lesson_id = ?'; params.push(lesson_id); }
    if (category) { query += ' AND r.category = ?'; params.push(category); }

    query += ' ORDER BY r.created_at DESC';
    const resources = db.prepare(query).all(...params);
    res.json({ resources });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/resources/:id/download
router.get('/:id/download', async (req, res) => {
  try {
    const resource = db.prepare('SELECT * FROM resources WHERE id = ?').get(req.params.id);
    if (!resource) return res.status(404).json({ error: 'Resource not found' });

    // Check access
    const hasAccess = resource.is_public ||
      resource.uploaded_by === req.user.id ||
      ['instructor', 'admin'].includes(req.user.role) ||
      (resource.course_id && db.prepare('SELECT 1 FROM enrollments WHERE student_id = ? AND course_id = ?').get(req.user.id, resource.course_id));

    if (!hasAccess) return res.status(403).json({ error: 'Access denied' });

    db.prepare('UPDATE resources SET download_count = download_count + 1 WHERE id = ?').run(req.params.id);

    const stored = resource.file_path || '';

    // Wasabi-stored: redirect to presigned URL
    if (stored.startsWith('/api/files/')) {
      const key = stored.replace(/^\/api\/files\//, '');
      const url = await presignedUrl(key, 900);
      return res.redirect(302, url);
    }

    // Local fallback — handle both "/uploads/<file>" (new local) and absolute disk paths (legacy rows)
    const abs = stored.startsWith('/uploads/')
      ? path.join(__dirname, '../../data/uploads', stored.replace('/uploads/', ''))
      : stored;

    if (!abs || !fs.existsSync(abs)) {
      return res.status(404).json({ error: 'File not found on disk' });
    }

    const filename = path.basename(abs);
    res.setHeader('Content-Disposition', `attachment; filename="${resource.title || filename}"`);
    res.sendFile(abs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/resources  (instructor upload)
router.post('/', upload.single('file'), async (req, res) => {
  try {
    if (!['instructor', 'admin', 'teaching_assistant'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Instructor access required' });
    }

    const { title, description, course_id, lesson_id, category, is_public } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required' });

    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const fileType = path.extname(req.file.originalname).replace('.', '').toLowerCase();
    const fileSizeBytes = req.file.size;
    const filePath = await persistUpload(req.file, 'resources');

    const result = db.prepare(`
      INSERT INTO resources (uploaded_by, title, description, course_id, lesson_id, file_path, file_type, file_size_bytes, category, is_public)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id, title, description || null, course_id || null, lesson_id || null,
      filePath, fileType, fileSizeBytes, category || 'general', is_public === 'true' || is_public === '1' ? 1 : 0
    );

    const resource = db.prepare('SELECT * FROM resources WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json({ resource });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/resources/:id
router.put('/:id', (req, res) => {
  try {
    const resource = db.prepare('SELECT * FROM resources WHERE id = ?').get(req.params.id);
    if (!resource) return res.status(404).json({ error: 'Resource not found' });
    if (resource.uploaded_by !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not your resource' });
    }

    const { title, description, course_id, lesson_id, category, is_public } = req.body;
    db.prepare(`
      UPDATE resources SET
        title = COALESCE(?, title),
        description = COALESCE(?, description),
        course_id = COALESCE(?, course_id),
        lesson_id = COALESCE(?, lesson_id),
        category = COALESCE(?, category),
        is_public = COALESCE(?, is_public)
      WHERE id = ?
    `).run(title, description, course_id, lesson_id, category,
      is_public !== undefined ? (is_public ? 1 : 0) : null,
      req.params.id);

    const updated = db.prepare('SELECT * FROM resources WHERE id = ?').get(req.params.id);
    res.json({ resource: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/resources/:id
router.delete('/:id', async (req, res) => {
  try {
    const resource = db.prepare('SELECT * FROM resources WHERE id = ?').get(req.params.id);
    if (!resource) return res.status(404).json({ error: 'Resource not found' });
    if (resource.uploaded_by !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not your resource' });
    }

    const stored = resource.file_path || '';
    if (stored.startsWith('/api/files/')) {
      if (wasabiEnabled()) await deleteObject(stored);
    } else if (stored.startsWith('/uploads/')) {
      const abs = path.join(__dirname, '../../data/uploads', stored.replace('/uploads/', ''));
      if (fs.existsSync(abs)) { try { fs.unlinkSync(abs); } catch (e) { /* ignore */ } }
    } else if (stored && fs.existsSync(stored)) {
      try { fs.unlinkSync(stored); } catch (e) { /* ignore */ }
    }

    db.prepare('DELETE FROM resources WHERE id = ?').run(req.params.id);
    res.json({ message: 'Resource deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
