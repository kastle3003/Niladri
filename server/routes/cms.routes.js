const express = require('express');
const router = express.Router();
const db = require('../db');
const bcrypt = require('bcryptjs');

function slugify(title) {
  return title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// Apply admin check to all CMS routes
router.use(adminOnly);

// ── Dashboard Stats ───────────────────────────────────────────────────────────

router.get('/stats', (req, res) => {
  try {
    const totalCourses = db.prepare(`SELECT COUNT(*) AS n FROM courses`).get().n;
    const totalStudents = db.prepare(`SELECT COUNT(*) AS n FROM users WHERE role = 'student'`).get().n;
    const totalInstructors = db.prepare(`SELECT COUNT(*) AS n FROM users WHERE role = 'instructor'`).get().n;
    const totalPosts = db.prepare(`SELECT COUNT(*) AS n FROM blogs`).get().n;
    const activeEnrollments = db.prepare(`SELECT COUNT(*) AS n FROM enrollments WHERE completed_at IS NULL`).get().n;

    res.json({
      totalCourses,
      totalStudents,
      totalInstructors,
      totalPosts,
      activeEnrollments,
      revenue: 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Courses ───────────────────────────────────────────────────────────────────

router.get('/courses', (req, res) => {
  try {
    const courses = db.prepare(`
      SELECT c.*,
             u.first_name || ' ' || u.last_name AS instructor_name,
             COUNT(e.id) AS enrollment_count
      FROM courses c
      LEFT JOIN users u ON c.instructor_id = u.id
      LEFT JOIN enrollments e ON e.course_id = c.id
      GROUP BY c.id
      ORDER BY c.created_at DESC
    `).all();
    res.json({ courses });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/courses', (req, res) => {
  try {
    const {
      title, subtitle, description, instructor_id, instrument,
      level, category, tags, cover_color, duration_weeks, status
    } = req.body;

    if (!title) return res.status(400).json({ error: 'title is required' });

    // Auto-generate unique slug from title
    let baseSlug = slugify(title);
    let slug = baseSlug;
    let n = 2;
    while (db.prepare('SELECT id FROM courses WHERE slug = ?').get(slug)) {
      slug = `${baseSlug}-${n++}`;
    }

    // Default the instructor to the creating admin if none provided, so the
    // course isn't orphaned in the public catalog with "(no instructor)".
    const ownerId = instructor_id || req.user.id;

    const result = db.prepare(`
      INSERT INTO courses (title, slug, subtitle, description, instructor_id, instrument, level, category, tags, cover_color, duration_weeks, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      title, slug, subtitle || null, description || null,
      ownerId, instrument || null,
      level || null, category || null,
      tags ? JSON.stringify(Array.isArray(tags) ? tags : tags.split(',').map(t => t.trim())) : '[]',
      cover_color || null, duration_weeks || null, status || 'active'
    );

    const course = db.prepare('SELECT * FROM courses WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json({ course });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.put('/courses/:id', (req, res) => {
  try {
    const existing = db.prepare('SELECT * FROM courses WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Course not found' });

    const fields = ['title', 'subtitle', 'description', 'instructor_id', 'instrument',
                    'level', 'category', 'cover_color', 'duration_weeks', 'status'];
    const updates = [];
    const params = [];

    for (const f of fields) {
      if (req.body[f] !== undefined) {
        updates.push(`${f} = ?`);
        params.push(req.body[f]);
      }
    }

    // Regenerate slug if title changed
    if (req.body.title && req.body.title !== existing.title) {
      let baseSlug = slugify(req.body.title);
      let slug = baseSlug;
      let n = 2;
      while (db.prepare('SELECT id FROM courses WHERE slug = ? AND id != ?').get(slug, req.params.id)) {
        slug = `${baseSlug}-${n++}`;
      }
      updates.push('slug = ?');
      params.push(slug);
    }

    // Handle tags field
    if (req.body.tags !== undefined) {
      const tagsArr = Array.isArray(req.body.tags) ? req.body.tags : String(req.body.tags).split(',').map(t => t.trim()).filter(Boolean);
      updates.push('tags = ?');
      params.push(JSON.stringify(tagsArr));
    }

    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

    updates.push(`updated_at = datetime('now')`);
    params.push(req.params.id);

    db.prepare(`UPDATE courses SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    const course = db.prepare('SELECT * FROM courses WHERE id = ?').get(req.params.id);
    res.json({ course });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/courses/:id', (req, res) => {
  try {
    const existing = db.prepare('SELECT id FROM courses WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Course not found' });

    const enrollCount = db.prepare('SELECT COUNT(*) AS n FROM enrollments WHERE course_id = ?').get(req.params.id).n;
    if (enrollCount > 0) {
      return res.status(409).json({ error: 'Cannot delete course with active enrollments' });
    }

    db.prepare('DELETE FROM courses WHERE id = ?').run(req.params.id);
    res.json({ message: 'Course deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.patch('/courses/:id/status', (req, res) => {
  try {
    const existing = db.prepare('SELECT * FROM courses WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Course not found' });

    const newStatus = existing.status === 'active' ? 'inactive' : 'active';
    db.prepare(`UPDATE courses SET status = ?, updated_at = datetime('now') WHERE id = ?`).run(newStatus, req.params.id);
    res.json({ id: existing.id, status: newStatus });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Instructors ───────────────────────────────────────────────────────────────

router.get('/instructors', (req, res) => {
  try {
    const instructors = db.prepare(`
      SELECT u.id, u.email, u.first_name, u.last_name, u.instrument, u.bio,
             u.avatar_initials, u.created_at,
             COUNT(c.id) AS course_count
      FROM users u
      LEFT JOIN courses c ON c.instructor_id = u.id
      WHERE u.role = 'instructor'
      GROUP BY u.id
      ORDER BY u.first_name ASC
    `).all();
    res.json({ instructors });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/instructors', (req, res) => {
  try {
    const { email, password, first_name, last_name, instrument, bio } = req.body;
    if (!email || !password || !first_name || !last_name) {
      return res.status(400).json({ error: 'email, password, first_name, last_name are required' });
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) return res.status(409).json({ error: 'Email already in use' });

    const password_hash = bcrypt.hashSync(password, 10);
    const avatar_initials = `${first_name[0]}${last_name[0]}`.toUpperCase();

    const result = db.prepare(`
      INSERT INTO users (email, password_hash, first_name, last_name, role, instrument, avatar_initials, bio, verified)
      VALUES (?, ?, ?, ?, 'instructor', ?, ?, ?, 1)
    `).run(email, password_hash, first_name, last_name, instrument || null, avatar_initials, bio || null);

    const instructor = db.prepare(
      'SELECT id, email, first_name, last_name, role, instrument, avatar_initials, bio, created_at FROM users WHERE id = ?'
    ).get(result.lastInsertRowid);

    res.status(201).json({ instructor });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.put('/instructors/:id', (req, res) => {
  try {
    const existing = db.prepare(`SELECT * FROM users WHERE id = ? AND role = 'instructor'`).get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Instructor not found' });

    const fields = ['email', 'first_name', 'last_name', 'instrument', 'bio', 'avatar_initials'];
    const updates = [];
    const params = [];

    for (const f of fields) {
      if (req.body[f] !== undefined) {
        updates.push(`${f} = ?`);
        params.push(req.body[f]);
      }
    }

    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

    params.push(req.params.id);
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);

    const instructor = db.prepare(
      'SELECT id, email, first_name, last_name, role, instrument, avatar_initials, bio, created_at FROM users WHERE id = ?'
    ).get(req.params.id);
    res.json({ instructor });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/instructors/:id', (req, res) => {
  try {
    const existing = db.prepare(`SELECT id FROM users WHERE id = ? AND role = 'instructor'`).get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Instructor not found' });

    const courseCount = db.prepare('SELECT COUNT(*) AS n FROM courses WHERE instructor_id = ?').get(req.params.id).n;
    if (courseCount > 0) {
      return res.status(409).json({ error: 'Cannot delete instructor with assigned courses' });
    }

    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    res.json({ message: 'Instructor deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Blog (admin CMS) ──────────────────────────────────────────────────────────

router.get('/blog', (req, res) => {
  try {
    const { limit = 20, offset = 0 } = req.query;
    const posts = db.prepare(`
      SELECT b.*,
             u.first_name || ' ' || u.last_name AS author_name
      FROM blogs b
      LEFT JOIN users u ON b.author_id = u.id
      ORDER BY b.created_at DESC
      LIMIT ? OFFSET ?
    `).all(Number(limit), Number(offset));
    res.json({ posts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/blog', (req, res) => {
  try {
    const { title, body, excerpt, cover_image, category, tags, status, published_at } = req.body;
    if (!title || !body) return res.status(400).json({ error: 'title and body are required' });

    const slug = slugify(title);
    const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const resolvedPublishedAt = status === 'published' ? (published_at || now) : (published_at || null);

    const result = db.prepare(`
      INSERT INTO blogs (title, slug, excerpt, body, cover_image, author_id, category, tags, status, published_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      title, slug, excerpt || null, body, cover_image || null,
      req.user.id, category || 'general', tags || '[]',
      status || 'draft', resolvedPublishedAt
    );

    const post = db.prepare('SELECT * FROM blogs WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json({ post });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'A post with this slug already exists' });
    res.status(500).json({ error: err.message });
  }
});

router.put('/blog/:id', (req, res) => {
  try {
    const existing = db.prepare('SELECT * FROM blogs WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Post not found' });

    const { title, body, excerpt, cover_image, category, tags, status, published_at } = req.body;

    const newTitle = title !== undefined ? title : existing.title;
    const newSlug = title ? slugify(title) : existing.slug;
    const newStatus = status !== undefined ? status : existing.status;

    let newPublishedAt = published_at !== undefined ? published_at : existing.published_at;
    if (newStatus === 'published' && !newPublishedAt) {
      newPublishedAt = new Date().toISOString().replace('T', ' ').substring(0, 19);
    }

    const now = new Date().toISOString().replace('T', ' ').substring(0, 19);

    db.prepare(`
      UPDATE blogs SET
        title = ?, slug = ?, excerpt = ?, body = ?, cover_image = ?,
        category = ?, tags = ?, status = ?, published_at = ?, updated_at = ?
      WHERE id = ?
    `).run(
      newTitle,
      newSlug,
      excerpt !== undefined ? excerpt : existing.excerpt,
      body !== undefined ? body : existing.body,
      cover_image !== undefined ? cover_image : existing.cover_image,
      category !== undefined ? category : existing.category,
      tags !== undefined ? tags : existing.tags,
      newStatus,
      newPublishedAt,
      now,
      req.params.id
    );

    const post = db.prepare('SELECT * FROM blogs WHERE id = ?').get(req.params.id);
    res.json({ post });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'A post with this slug already exists' });
    res.status(500).json({ error: err.message });
  }
});

router.delete('/blog/:id', (req, res) => {
  try {
    const existing = db.prepare('SELECT id FROM blogs WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Post not found' });

    db.prepare('DELETE FROM blogs WHERE id = ?').run(req.params.id);
    res.json({ message: 'Post deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.patch('/blog/:id/status', (req, res) => {
  try {
    const existing = db.prepare('SELECT * FROM blogs WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Post not found' });

    const newStatus = existing.status === 'published' ? 'draft' : 'published';
    const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const newPublishedAt = newStatus === 'published' && !existing.published_at ? now : existing.published_at;

    db.prepare(`UPDATE blogs SET status = ?, published_at = ?, updated_at = ? WHERE id = ?`)
      .run(newStatus, newPublishedAt, now, req.params.id);

    res.json({ id: existing.id, status: newStatus, published_at: newPublishedAt });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Students ──────────────────────────────────────────────────────────────────

router.get('/students', (req, res) => {
  try {
    const students = db.prepare(`
      SELECT u.id, u.email, u.first_name, u.last_name, u.instrument, u.avatar_initials,
             u.created_at AS joined_date,
             COUNT(e.id) AS enrollment_count
      FROM users u
      LEFT JOIN enrollments e ON e.student_id = u.id
      WHERE u.role = 'student'
      GROUP BY u.id
      ORDER BY u.created_at DESC
    `).all();
    res.json({ students });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/students/:id', (req, res) => {
  try {
    const existing = db.prepare(`SELECT id FROM users WHERE id = ? AND role = 'student'`).get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Student not found' });

    db.prepare(`UPDATE users SET role = 'disabled' WHERE id = ?`).run(req.params.id);
    res.json({ message: 'Student disabled' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
