const express = require('express');
const router = express.Router();
const db = require('../db');

// ── Blog: public read ─────────────────────────────────────────────────────────

// GET /api/public/blog — list published posts
router.get('/blog', (req, res) => {
  try {
    const { category, limit = 10, offset = 0 } = req.query;
    let sql = `
      SELECT b.id, b.title, b.slug, b.excerpt, b.cover_image, b.category, b.tags,
             u.first_name || ' ' || u.last_name AS author_name,
             b.published_at, b.views
      FROM blogs b
      LEFT JOIN users u ON b.author_id = u.id
      WHERE b.status = 'published'
    `;
    const params = [];
    if (category) {
      sql += ` AND b.category = ?`;
      params.push(category);
    }
    sql += ` ORDER BY b.published_at DESC LIMIT ? OFFSET ?`;
    params.push(Number(limit), Number(offset));

    const posts = db.prepare(sql).all(...params);
    res.json({ posts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/public/blog/:slug — single published post
router.get('/blog/:slug', (req, res) => {
  try {
    const post = db.prepare(`
      SELECT b.*,
             u.first_name || ' ' || u.last_name AS author_name,
             u.bio AS author_bio,
             u.avatar_initials AS author_initials
      FROM blogs b
      LEFT JOIN users u ON b.author_id = u.id
      WHERE b.slug = ? AND b.status = 'published'
    `).get(req.params.slug);

    if (!post) return res.status(404).json({ error: 'Post not found' });

    db.prepare(`UPDATE blogs SET views = views + 1 WHERE id = ?`).run(post.id);
    post.views = post.views + 1;

    res.json({ post });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/public/courses  — all active courses (no auth)
router.get('/courses', (req, res) => {
  try {
    const courses = db.prepare(`
      SELECT c.*, u.first_name || ' ' || u.last_name AS instructor_name,
             u.avatar_initials AS instructor_initials, u.instrument AS instructor_instrument
      FROM courses c
      LEFT JOIN users u ON c.instructor_id = u.id
      WHERE c.status = 'active'
      ORDER BY c.id ASC
    `).all();
    res.json({ courses });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/public/courses/:slugOrId  — single course by slug (preferred) or numeric id
router.get('/courses/:slugOrId', (req, res) => {
  try {
    const { slugOrId } = req.params;
    // Try slug first, fall back to numeric id for backward compat
    const isNumeric = /^\d+$/.test(slugOrId);
    const course = db.prepare(`
      SELECT c.*,
             u.first_name || ' ' || u.last_name AS instructor_name,
             u.bio AS instructor_bio,
             u.avatar_initials AS instructor_initials,
             u.instrument AS instructor_instrument
      FROM courses c
      LEFT JOIN users u ON c.instructor_id = u.id
      WHERE ${isNumeric ? 'c.id = ?' : 'c.slug = ?'} AND c.status = 'active'
    `).get(slugOrId);

    if (!course) return res.status(404).json({ error: 'Course not found' });

    const chapters = db.prepare(
      'SELECT * FROM chapters WHERE course_id = ? ORDER BY order_index'
    ).all(course.id);

    const lessons = db.prepare(
      'SELECT id, chapter_id, title, order_index, type, duration_minutes, duration_seconds, is_preview FROM lessons WHERE course_id = ? ORDER BY order_index'
    ).all(course.id);

    // Attach materials + timestamps only for preview lessons so anonymous
    // visitors can play the Free Preview video without signing in.
    const previewIds = lessons.filter(l => l.is_preview).map(l => l.id);
    let previewMatById = {};
    if (previewIds.length) {
      const placeholders = previewIds.map(() => '?').join(',');
      const mats = db.prepare(
        `SELECT * FROM lesson_materials WHERE lesson_id IN (${placeholders}) ORDER BY order_index, id`
      ).all(...previewIds);
      const ts = db.prepare(`
        SELECT t.* FROM video_timestamps t
        JOIN lesson_materials m ON t.material_id = m.id
        WHERE m.lesson_id IN (${placeholders})
        ORDER BY t.material_id, t.time_seconds
      `).all(...previewIds);
      const tsByMat = {};
      ts.forEach(x => { (tsByMat[x.material_id] = tsByMat[x.material_id] || []).push(x); });
      mats.forEach(m => {
        (previewMatById[m.lesson_id] = previewMatById[m.lesson_id] || [])
          .push({ ...m, timestamps: tsByMat[m.id] || [] });
      });
    }
    lessons.forEach(l => { l.materials = l.is_preview ? (previewMatById[l.id] || []) : []; });

    const chaptersWithLessons = chapters.map(ch => ({
      ...ch,
      lessons: lessons.filter(l => l.chapter_id === ch.id)
    }));

    res.json({ course, chapters: chaptersWithLessons });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
