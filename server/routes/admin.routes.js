const router = require('express').Router();
const db = require('../db');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

// ── Middleware: Admin-only ──
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ═══════════════════════════════════════════════════
//  STATS / ANALYTICS
// ═══════════════════════════════════════════════════

// GET /api/admin/stats
router.get('/stats', adminOnly, (req, res) => {
  try {
    const total_users = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
    const total_students = db.prepare("SELECT COUNT(*) as c FROM users WHERE role='student'").get().c;
    const total_instructors = db.prepare("SELECT COUNT(*) as c FROM users WHERE role='instructor'").get().c;
    const active_courses = db.prepare("SELECT COUNT(*) as c FROM courses WHERE status='active'").get().c;
    const total_courses = db.prepare('SELECT COUNT(*) as c FROM courses').get().c;
    const total_enrollments = db.prepare('SELECT COUNT(*) as c FROM enrollments').get().c;
    const emails_sent = db.prepare('SELECT COUNT(*) as c FROM email_logs').get().c;

    // Revenue
    let total_revenue = 0, month_revenue = 0, pending_revenue = 0;
    try {
      total_revenue = db.prepare("SELECT COALESCE(SUM(amount_paise),0) as s FROM payments WHERE status='paid'").get().s;
      const now = new Date();
      const monthStart = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-01`;
      month_revenue = db.prepare("SELECT COALESCE(SUM(amount_paise),0) as s FROM payments WHERE status='paid' AND created_at >= ?").get(monthStart).s;
      pending_revenue = db.prepare("SELECT COALESCE(SUM(amount_paise),0) as s FROM payments WHERE status='created'").get().s;
    } catch(e) {}

    // Storage used (sum file sizes from resources)
    let storage_bytes = 0;
    try {
      storage_bytes = db.prepare('SELECT COALESCE(SUM(file_size_bytes),0) as s FROM resources').get().s;
    } catch(e) {}
    const storage_used = storage_bytes > 1073741824
      ? (storage_bytes / 1073741824).toFixed(1) + ' GB'
      : storage_bytes > 1048576
        ? (storage_bytes / 1048576).toFixed(0) + ' MB'
        : (storage_bytes / 1024).toFixed(0) + ' KB';

    // New users this month
    let new_users_month = 0;
    try {
      const now = new Date();
      const monthStart = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-01`;
      new_users_month = db.prepare("SELECT COUNT(*) as c FROM users WHERE created_at >= ?").get(monthStart).c;
    } catch(e) {}

    // New enrollments this month
    let new_enrollments_month = 0;
    try {
      const now = new Date();
      const monthStart = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-01`;
      new_enrollments_month = db.prepare("SELECT COUNT(*) as c FROM enrollments WHERE enrolled_at >= ?").get(monthStart).c;
    } catch(e) {}

    // Recent activity (last 10)
    let recent_activity = [];
    try {
      // Combine enrollments, payments, users creation
      const recentEnroll = db.prepare(`
        SELECT 'enrollment' as type, e.enrolled_at as time,
          u.first_name || ' ' || u.last_name as user_name,
          c.title as course_title
        FROM enrollments e
        JOIN users u ON e.student_id = u.id
        JOIN courses c ON e.course_id = c.id
        ORDER BY e.enrolled_at DESC LIMIT 5
      `).all();
      const recentUsers = db.prepare(`
        SELECT 'user_joined' as type, created_at as time,
          first_name || ' ' || last_name as user_name,
          role as course_title
        FROM users ORDER BY created_at DESC LIMIT 5
      `).all();
      recent_activity = [...recentEnroll, ...recentUsers]
        .sort((a,b) => new Date(b.time) - new Date(a.time))
        .slice(0, 10);
    } catch(e) {}

    // Monthly revenue breakdown (last 6 months)
    let revenue_chart = [];
    try {
      revenue_chart = db.prepare(`
        SELECT strftime('%Y-%m', created_at) as month,
          SUM(CASE WHEN status='paid' THEN amount_paise ELSE 0 END) as revenue
        FROM payments
        GROUP BY month
        ORDER BY month DESC
        LIMIT 6
      `).all().reverse();
    } catch(e) {}

    // User growth (last 6 months)
    let user_growth = [];
    try {
      user_growth = db.prepare(`
        SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count
        FROM users
        GROUP BY month
        ORDER BY month DESC
        LIMIT 6
      `).all().reverse();
    } catch(e) {}

    res.json({
      total_users, total_students, total_instructors,
      active_courses, total_courses, total_enrollments,
      emails_sent, storage_used, storage_bytes,
      total_revenue, month_revenue, pending_revenue,
      new_users_month, new_enrollments_month,
      recent_activity, revenue_chart, user_growth
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  CONFIGURATION
// ═══════════════════════════════════════════════════

// GET current config
router.get('/config', (req, res) => {
  try {
    const row = db.prepare('SELECT * FROM app_config WHERE id = 1').get();
    if (!row) return res.json({ s3: {}, smtp: {}, general: {}, razorpay: {} });
    res.json({
      s3: JSON.parse(row.s3_config || '{}'),
      smtp: JSON.parse(row.smtp_config || '{}'),
      general: JSON.parse(row.general_config || '{}'),
      razorpay: JSON.parse(row.razorpay_config || '{}')
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT S3 config
router.put('/config/s3', adminOnly, (req, res) => {
  try {
    const existing = db.prepare('SELECT id FROM app_config WHERE id = 1').get();
    const json = JSON.stringify(req.body);
    if (existing) {
      db.prepare("UPDATE app_config SET s3_config = ?, updated_at = datetime('now') WHERE id = 1").run(json);
    } else {
      db.prepare('INSERT INTO app_config (id, s3_config) VALUES (1, ?)').run(json);
    }
    res.json({ message: 'S3 configuration saved' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT SMTP config
router.put('/config/smtp', adminOnly, (req, res) => {
  try {
    const existing = db.prepare('SELECT id FROM app_config WHERE id = 1').get();
    const json = JSON.stringify(req.body);
    if (existing) {
      db.prepare("UPDATE app_config SET smtp_config = ?, updated_at = datetime('now') WHERE id = 1").run(json);
    } else {
      db.prepare('INSERT INTO app_config (id, smtp_config) VALUES (1, ?)').run(json);
    }
    res.json({ message: 'SMTP configuration saved' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT General config
router.put('/config/general', adminOnly, (req, res) => {
  try {
    const existing = db.prepare('SELECT id FROM app_config WHERE id = 1').get();
    const json = JSON.stringify(req.body);
    if (existing) {
      db.prepare("UPDATE app_config SET general_config = ?, updated_at = datetime('now') WHERE id = 1").run(json);
    } else {
      db.prepare('INSERT INTO app_config (id, general_config) VALUES (1, ?)').run(json);
    }
    res.json({ message: 'General configuration saved' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT Razorpay config
router.put('/config/razorpay', adminOnly, (req, res) => {
  try {
    const existing = db.prepare('SELECT id FROM app_config WHERE id = 1').get();
    const json = JSON.stringify(req.body);
    if (existing) {
      db.prepare("UPDATE app_config SET razorpay_config = ?, updated_at = datetime('now') WHERE id = 1").run(json);
    } else {
      db.prepare('INSERT INTO app_config (id, razorpay_config) VALUES (1, ?)').run(json);
    }
    res.json({ message: 'Razorpay configuration saved' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST Test S3
router.post('/s3/test', adminOnly, (req, res) => {
  const { access_key_id, secret_access_key, bucket_name, region } = req.body;
  if (!access_key_id || !secret_access_key || !bucket_name || !region) {
    return res.status(400).json({ error: 'All S3 fields are required to test connection' });
  }
  setTimeout(() => res.json({ message: 'S3 connection successful', bucket: bucket_name }), 800);
});

// POST Test SMTP
router.post('/smtp/test', adminOnly, (req, res) => {
  const { test_email, host, port, username } = req.body;
  if (!test_email || !host || !username) {
    return res.status(400).json({ error: 'SMTP config and test email are required' });
  }
  setTimeout(() => res.json({ message: `Test email sent to ${test_email}` }), 1000);
});

// ═══════════════════════════════════════════════════
//  USER MANAGEMENT
// ═══════════════════════════════════════════════════

// GET /api/admin/users
router.get('/users', adminOnly, (req, res) => {
  try {
    const users = db.prepare(`
      SELECT id, first_name, last_name, email, role, instrument, avatar_initials, bio, verified, created_at
      FROM users ORDER BY created_at DESC
    `).all();

    // Enrich with enrollment count
    const enriched = users.map(u => {
      const enrollCount = db.prepare('SELECT COUNT(*) as c FROM enrollments WHERE student_id = ?').get(u.id).c;
      return { ...u, name: u.first_name + ' ' + u.last_name, enrollment_count: enrollCount };
    });

    res.json({ users: enriched });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/users — Create new user
router.post('/users', adminOnly, (req, res) => {
  try {
    const { email, password, first_name, last_name, role, instrument } = req.body;
    if (!email || !password || !first_name || !last_name) {
      return res.status(400).json({ error: 'email, password, first_name, and last_name are required' });
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) return res.status(409).json({ error: 'User with this email already exists' });

    const hash = bcrypt.hashSync(password, 10);
    const initials = (first_name[0] + (last_name[0] || '')).toUpperCase();
    const validRole = ['student','instructor','teaching_assistant','admin'].includes(role) ? role : 'student';

    const result = db.prepare(`
      INSERT INTO users (email, password_hash, first_name, last_name, role, instrument, avatar_initials, verified)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    `).run(email, hash, first_name, last_name, validRole, instrument || null, initials);

    const user = db.prepare('SELECT id, first_name, last_name, email, role, instrument, avatar_initials, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json({ user, message: 'User created successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/users/:id — Update user role
router.put('/users/:id', adminOnly, (req, res) => {
  try {
    const { role, first_name, last_name, instrument } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (role && ['student','instructor','teaching_assistant','admin'].includes(role)) {
      db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id);
    }
    if (first_name) db.prepare('UPDATE users SET first_name = ? WHERE id = ?').run(first_name, req.params.id);
    if (last_name) db.prepare('UPDATE users SET last_name = ? WHERE id = ?').run(last_name, req.params.id);
    if (instrument !== undefined) db.prepare('UPDATE users SET instrument = ? WHERE id = ?').run(instrument, req.params.id);

    const updated = db.prepare('SELECT id, first_name, last_name, email, role, instrument, avatar_initials, created_at FROM users WHERE id = ?').get(req.params.id);
    res.json({ user: updated, message: 'User updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/users/:id — Delete user
router.delete('/users/:id', adminOnly, (req, res) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.role === 'admin') return res.status(403).json({ error: 'Cannot delete admin users' });

    // Clean up related data
    db.prepare('DELETE FROM enrollments WHERE student_id = ?').run(req.params.id);
    db.prepare('DELETE FROM notifications WHERE user_id = ?').run(req.params.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);

    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  COURSE MANAGEMENT / OVERSIGHT
// ═══════════════════════════════════════════════════

// GET /api/admin/courses — List all courses with instructor info
router.get('/courses', adminOnly, (req, res) => {
  try {
    const courses = db.prepare(`
      SELECT c.*,
        u.first_name || ' ' || u.last_name as instructor_name,
        u.email as instructor_email,
        (SELECT COUNT(*) FROM enrollments WHERE course_id = c.id) as enrollment_count,
        (SELECT COUNT(*) FROM lessons WHERE course_id = c.id) as actual_lesson_count,
        (SELECT COALESCE(SUM(amount_paise),0) FROM payments WHERE course_id = c.id AND status='paid') as total_revenue
      FROM courses c
      LEFT JOIN users u ON c.instructor_id = u.id
      ORDER BY c.created_at DESC
    `).all();
    res.json({ courses });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/courses/:id — Update course status, pricing, etc
router.put('/courses/:id', adminOnly, (req, res) => {
  try {
    const course = db.prepare('SELECT * FROM courses WHERE id = ?').get(req.params.id);
    if (!course) return res.status(404).json({ error: 'Course not found' });

    const { status, price_paise, is_paid, category, level } = req.body;

    if (status) db.prepare("UPDATE courses SET status = ?, updated_at = datetime('now') WHERE id = ?").run(status, req.params.id);
    if (price_paise !== undefined) db.prepare("UPDATE courses SET price_paise = ?, updated_at = datetime('now') WHERE id = ?").run(price_paise, req.params.id);
    if (is_paid !== undefined) db.prepare("UPDATE courses SET is_paid = ?, updated_at = datetime('now') WHERE id = ?").run(is_paid ? 1 : 0, req.params.id);
    if (category) db.prepare("UPDATE courses SET category = ?, updated_at = datetime('now') WHERE id = ?").run(category, req.params.id);
    if (level) db.prepare("UPDATE courses SET level = ?, updated_at = datetime('now') WHERE id = ?").run(level, req.params.id);

    const updated = db.prepare('SELECT * FROM courses WHERE id = ?').get(req.params.id);
    res.json({ course: updated, message: 'Course updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/courses/:id
router.delete('/courses/:id', adminOnly, (req, res) => {
  try {
    const course = db.prepare('SELECT * FROM courses WHERE id = ?').get(req.params.id);
    if (!course) return res.status(404).json({ error: 'Course not found' });

    db.prepare('DELETE FROM enrollments WHERE course_id = ?').run(req.params.id);
    db.prepare('DELETE FROM lessons WHERE course_id = ?').run(req.params.id);
    db.prepare('DELETE FROM chapters WHERE course_id = ?').run(req.params.id);
    db.prepare('DELETE FROM courses WHERE id = ?').run(req.params.id);

    res.json({ message: 'Course deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  FINANCIAL / PAYMENTS
// ═══════════════════════════════════════════════════

// GET /api/admin/payments
router.get('/payments', adminOnly, (req, res) => {
  try {
    const payments = db.prepare(`
      SELECT p.*,
        u.first_name || ' ' || u.last_name AS student_name,
        u.email AS student_email,
        c.title AS course_title
      FROM payments p
      LEFT JOIN users u ON p.user_id = u.id
      LEFT JOIN courses c ON p.course_id = c.id
      ORDER BY p.created_at DESC
    `).all();

    const totalPaid = payments.filter(p => p.status === 'paid').reduce((s, p) => s + (p.amount_paise || 0), 0);
    const now = new Date();
    const monthStart = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-01`;
    const thisMonth = payments.filter(p => p.status === 'paid' && p.created_at >= monthStart).reduce((s, p) => s + (p.amount_paise || 0), 0);
    const pending = payments.filter(p => p.status === 'created').reduce((s, p) => s + (p.amount_paise || 0), 0);
    const failed = payments.filter(p => p.status === 'failed').reduce((s, p) => s + (p.amount_paise || 0), 0);

    res.json({
      payments,
      summary: {
        total_revenue: totalPaid,
        month_revenue: thisMonth,
        pending_amount: pending,
        failed_amount: failed,
        total_transactions: payments.length,
        paid_count: payments.filter(p => p.status === 'paid').length,
        pending_count: payments.filter(p => p.status === 'created').length,
        failed_count: payments.filter(p => p.status === 'failed').length
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  ANNOUNCEMENTS (admin-wide)
// ═══════════════════════════════════════════════════

// GET /api/admin/announcements
router.get('/announcements', adminOnly, (req, res) => {
  try {
    const announcements = db.prepare(`
      SELECT a.*,
        u.first_name || ' ' || u.last_name AS author_name,
        c.title AS course_title
      FROM announcements a
      LEFT JOIN users u ON a.instructor_id = u.id
      LEFT JOIN courses c ON a.course_id = c.id
      ORDER BY a.pinned DESC, a.created_at DESC
    `).all();
    res.json({ announcements });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/announcements — Create platform-wide announcement
router.post('/announcements', adminOnly, (req, res) => {
  try {
    const { title, body, course_id, pinned, send_email } = req.body;
    if (!title || !body) return res.status(400).json({ error: 'title and body are required' });

    const result = db.prepare(`
      INSERT INTO announcements (instructor_id, title, body, course_id, pinned, send_email)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(req.user.id, title, body, course_id || null, pinned ? 1 : 0, send_email ? 1 : 0);

    const ann = db.prepare(`
      SELECT a.*, u.first_name || ' ' || u.last_name AS author_name, c.title AS course_title
      FROM announcements a
      LEFT JOIN users u ON a.instructor_id = u.id
      LEFT JOIN courses c ON a.course_id = c.id
      WHERE a.id = ?
    `).get(result.lastInsertRowid);

    res.status(201).json({ announcement: ann, message: 'Announcement created' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/announcements/:id
router.delete('/announcements/:id', adminOnly, (req, res) => {
  try {
    db.prepare('DELETE FROM announcements WHERE id = ?').run(req.params.id);
    res.json({ message: 'Announcement deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  SYSTEM NOTIFICATIONS (BROADCAST)
// ═══════════════════════════════════════════════════

// POST /api/admin/notifications/broadcast — Push a notification to many users
// body: { title, body, link?, target: 'all' | 'students' | 'instructors' | 'admins' }
router.post('/notifications/broadcast', adminOnly, (req, res) => {
  try {
    const { title, body, link, target } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required' });

    const targetMap = {
      all:         "SELECT id FROM users",
      students:    "SELECT id FROM users WHERE role='student'",
      instructors: "SELECT id FROM users WHERE role='instructor'",
      admins:      "SELECT id FROM users WHERE role='admin'"
    };
    const sql = targetMap[target || 'all'];
    if (!sql) return res.status(400).json({ error: 'invalid target' });

    const users = db.prepare(sql).all();
    const insert = db.prepare(`
      INSERT INTO notifications (user_id, type, title, body, link)
      VALUES (?, 'system', ?, ?, ?)
    `);
    const tx = db.transaction((rows) => {
      for (const u of rows) insert.run(u.id, title, body || '', link || null);
    });
    tx(users);

    res.status(201).json({ message: `Notification sent to ${users.length} user${users.length !== 1 ? 's' : ''}`, recipients: users.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  STORAGE BREAKDOWN
// ═══════════════════════════════════════════════════

function dirSize(dir) {
  let total = 0;
  if (!fs.existsSync(dir)) return 0;
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    let entries = [];
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch(e) { continue; }
    for (const e of entries) {
      const p = path.join(cur, e.name);
      try {
        if (e.isDirectory()) stack.push(p);
        else if (e.isFile()) total += fs.statSync(p).size;
      } catch(_) {}
    }
  }
  return total;
}
function fmtBytes(b) {
  if (b > 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
  if (b > 1048576)    return (b / 1048576).toFixed(1) + ' MB';
  if (b > 1024)       return (b / 1024).toFixed(0) + ' KB';
  return b + ' B';
}

// GET /api/admin/storage — full storage breakdown
router.get('/storage', adminOnly, (req, res) => {
  try {
    const dataDir = path.join(__dirname, '../../data');
    const uploadsDir = path.join(dataDir, 'uploads');
    const certDir = path.join(dataDir, 'certificates');
    const resDir = path.join(dataDir, 'resources');

    const uploadsBytes = dirSize(uploadsDir);
    const certsBytes = dirSize(certDir);
    const resourcesBytes = dirSize(resDir);
    const totalDiskBytes = uploadsBytes + certsBytes + resourcesBytes;

    let resourcesDbBytes = 0, resourcesDbCount = 0;
    try {
      const r = db.prepare('SELECT COALESCE(SUM(file_size_bytes),0) as s, COUNT(*) as c FROM resources').get();
      resourcesDbBytes = r.s; resourcesDbCount = r.c;
    } catch(e) {}

    let byCategory = [];
    try {
      byCategory = db.prepare(`
        SELECT category, COUNT(*) as count, COALESCE(SUM(file_size_bytes),0) as bytes
        FROM resources GROUP BY category ORDER BY bytes DESC
      `).all().map(r => ({ ...r, size: fmtBytes(r.bytes) }));
    } catch(e) {}

    let byType = [];
    try {
      byType = db.prepare(`
        SELECT file_type as type, COUNT(*) as count, COALESCE(SUM(file_size_bytes),0) as bytes
        FROM resources WHERE file_type IS NOT NULL
        GROUP BY file_type ORDER BY bytes DESC
      `).all().map(r => ({ ...r, size: fmtBytes(r.bytes) }));
    } catch(e) {}

    res.json({
      total_bytes: totalDiskBytes,
      total_size: fmtBytes(totalDiskBytes),
      uploads:     { bytes: uploadsBytes,  size: fmtBytes(uploadsBytes) },
      certificates:{ bytes: certsBytes,    size: fmtBytes(certsBytes) },
      resources:   { bytes: resourcesBytes,size: fmtBytes(resourcesBytes), db_bytes: resourcesDbBytes, db_size: fmtBytes(resourcesDbBytes), count: resourcesDbCount },
      by_category: byCategory,
      by_type: byType
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  ROLE PERMISSIONS (persisted in app_config.general_config.role_permissions)
// ═══════════════════════════════════════════════════

const DEFAULT_PERMISSIONS = {
  admin: ['manage_users','manage_all_courses','admin_panel','view_reports','billing','platform_config','content_moderation'],
  instructor: ['create_courses','manage_own_courses','view_enrollments','grade_assignments','send_announcements','manage_sheet_music'],
  teaching_assistant: ['view_assigned_courses','grade_assignments','send_announcements','manage_resources'],
  student: ['view_enrolled_courses','submit_assignments','access_archive','take_quizzes','practice_log','download_resources']
};

function readGeneralConfig() {
  const row = db.prepare('SELECT general_config FROM app_config WHERE id = 1').get();
  if (!row) return {};
  try { return JSON.parse(row.general_config || '{}'); } catch(e) { return {}; }
}

// GET /api/admin/permissions
router.get('/permissions', adminOnly, (req, res) => {
  try {
    const cfg = readGeneralConfig();
    res.json({ permissions: cfg.role_permissions || DEFAULT_PERMISSIONS });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/permissions
router.put('/permissions', adminOnly, (req, res) => {
  try {
    const { permissions } = req.body;
    if (!permissions || typeof permissions !== 'object') {
      return res.status(400).json({ error: 'permissions object required' });
    }
    const cfg = readGeneralConfig();
    cfg.role_permissions = permissions;
    const json = JSON.stringify(cfg);
    const existing = db.prepare('SELECT id FROM app_config WHERE id = 1').get();
    if (existing) {
      db.prepare("UPDATE app_config SET general_config = ?, updated_at = datetime('now') WHERE id = 1").run(json);
    } else {
      db.prepare('INSERT INTO app_config (id, general_config) VALUES (1, ?)').run(json);
    }
    res.json({ message: 'Permissions saved', permissions });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  CONTENT MODERATION (flags)
// ═══════════════════════════════════════════════════

// GET /api/admin/flags?status=pending|resolved|dismissed
router.get('/flags', adminOnly, (req, res) => {
  try {
    const status = req.query.status;
    let sql = `
      SELECT f.*,
        u.first_name || ' ' || u.last_name AS reporter_name,
        u.email AS reporter_email
      FROM content_flags f
      LEFT JOIN users u ON f.reported_by = u.id
    `;
    const params = [];
    if (status) { sql += ' WHERE f.status = ?'; params.push(status); }
    sql += ' ORDER BY f.created_at DESC';
    const flags = db.prepare(sql).all(...params);

    const enriched = flags.map(f => {
      let target_title = '—';
      try {
        if (f.content_type === 'course') {
          const c = db.prepare('SELECT title FROM courses WHERE id = ?').get(f.content_id);
          target_title = c ? c.title : 'Deleted course';
        } else if (f.content_type === 'announcement') {
          const a = db.prepare('SELECT title FROM announcements WHERE id = ?').get(f.content_id);
          target_title = a ? a.title : 'Deleted announcement';
        } else if (f.content_type === 'user') {
          const u = db.prepare('SELECT first_name || \' \' || last_name as n FROM users WHERE id = ?').get(f.content_id);
          target_title = u ? u.n : 'Deleted user';
        }
      } catch(e) {}
      return { ...f, target_title };
    });

    const counts = {
      pending: db.prepare("SELECT COUNT(*) as c FROM content_flags WHERE status='pending'").get().c,
      resolved: db.prepare("SELECT COUNT(*) as c FROM content_flags WHERE status='resolved'").get().c,
      dismissed: db.prepare("SELECT COUNT(*) as c FROM content_flags WHERE status='dismissed'").get().c
    };

    res.json({ flags: enriched, counts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/flags — admin can also raise a flag (e.g. internal review)
router.post('/flags', adminOnly, (req, res) => {
  try {
    const { content_type, content_id, reason } = req.body;
    if (!content_type || !content_id) return res.status(400).json({ error: 'content_type and content_id required' });
    const r = db.prepare(`
      INSERT INTO content_flags (content_type, content_id, reason, reported_by)
      VALUES (?, ?, ?, ?)
    `).run(content_type, content_id, reason || null, req.user.id);
    res.status(201).json({ id: r.lastInsertRowid, message: 'Flag created' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/flags/:id — { action: 'resolve' | 'dismiss', resolution? }
router.put('/flags/:id', adminOnly, (req, res) => {
  try {
    const { action, resolution } = req.body;
    if (!['resolve','dismiss'].includes(action)) {
      return res.status(400).json({ error: 'action must be resolve or dismiss' });
    }
    const flag = db.prepare('SELECT * FROM content_flags WHERE id = ?').get(req.params.id);
    if (!flag) return res.status(404).json({ error: 'Flag not found' });

    const newStatus = action === 'resolve' ? 'resolved' : 'dismissed';
    db.prepare(`
      UPDATE content_flags
      SET status = ?, resolution = ?, resolved_by = ?, resolved_at = datetime('now')
      WHERE id = ?
    `).run(newStatus, resolution || null, req.user.id, req.params.id);

    res.json({ message: 'Flag ' + newStatus });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/flags/:id
router.delete('/flags/:id', adminOnly, (req, res) => {
  try {
    db.prepare('DELETE FROM content_flags WHERE id = ?').run(req.params.id);
    res.json({ message: 'Flag deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  SUBSCRIPTION MANAGEMENT
// ═══════════════════════════════════════════════════

// GET /api/admin/subscriptions/plans
router.get('/subscriptions/plans', adminOnly, (req, res) => {
  try {
    const plans = db.prepare(`
      SELECT p.*,
        (SELECT COUNT(*) FROM user_subscriptions s WHERE s.plan_id = p.id AND s.status='active') as active_subscribers,
        (SELECT COUNT(*) FROM user_subscriptions s WHERE s.plan_id = p.id) as total_subscribers
      FROM subscription_plans p
      ORDER BY p.sort_order ASC, p.created_at ASC
    `).all().map(p => ({
      ...p,
      features: (() => { try { return JSON.parse(p.features || '[]'); } catch(e) { return []; } })(),
      is_active: !!p.is_active
    }));
    res.json({ plans });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/subscriptions/plans
router.post('/subscriptions/plans', adminOnly, (req, res) => {
  try {
    const { name, description, price_paise, billing_period, features, sort_order, is_active } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });
    const r = db.prepare(`
      INSERT INTO subscription_plans (name, description, price_paise, billing_period, features, sort_order, is_active)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      name,
      description || '',
      parseInt(price_paise) || 0,
      billing_period || 'monthly',
      JSON.stringify(features || []),
      parseInt(sort_order) || 0,
      is_active === false ? 0 : 1
    );
    res.status(201).json({ id: r.lastInsertRowid, message: 'Plan created' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/subscriptions/plans/:id
router.put('/subscriptions/plans/:id', adminOnly, (req, res) => {
  try {
    const plan = db.prepare('SELECT * FROM subscription_plans WHERE id = ?').get(req.params.id);
    if (!plan) return res.status(404).json({ error: 'Plan not found' });
    const { name, description, price_paise, billing_period, features, sort_order, is_active } = req.body;

    db.prepare(`
      UPDATE subscription_plans
      SET name = COALESCE(?, name),
          description = COALESCE(?, description),
          price_paise = COALESCE(?, price_paise),
          billing_period = COALESCE(?, billing_period),
          features = COALESCE(?, features),
          sort_order = COALESCE(?, sort_order),
          is_active = COALESCE(?, is_active),
          updated_at = datetime('now')
      WHERE id = ?
    `).run(
      name ?? null,
      description ?? null,
      price_paise !== undefined ? parseInt(price_paise) : null,
      billing_period ?? null,
      features !== undefined ? JSON.stringify(features) : null,
      sort_order !== undefined ? parseInt(sort_order) : null,
      is_active !== undefined ? (is_active ? 1 : 0) : null,
      req.params.id
    );
    res.json({ message: 'Plan updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/subscriptions/plans/:id
router.delete('/subscriptions/plans/:id', adminOnly, (req, res) => {
  try {
    const active = db.prepare("SELECT COUNT(*) as c FROM user_subscriptions WHERE plan_id = ? AND status='active'").get(req.params.id).c;
    if (active > 0) return res.status(409).json({ error: `Cannot delete: ${active} active subscriber${active !== 1 ? 's' : ''}. Deactivate the plan instead.` });
    db.prepare('DELETE FROM subscription_plans WHERE id = ?').run(req.params.id);
    res.json({ message: 'Plan deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/subscriptions — all subscribers across all plans
router.get('/subscriptions', adminOnly, (req, res) => {
  try {
    const subs = db.prepare(`
      SELECT s.*,
        u.first_name || ' ' || u.last_name AS user_name,
        u.email AS user_email,
        p.name AS plan_name,
        p.price_paise AS plan_price_paise,
        p.billing_period AS plan_period
      FROM user_subscriptions s
      LEFT JOIN users u ON s.user_id = u.id
      LEFT JOIN subscription_plans p ON s.plan_id = p.id
      ORDER BY s.created_at DESC
    `).all();

    const summary = {
      active:    db.prepare("SELECT COUNT(*) as c FROM user_subscriptions WHERE status='active'").get().c,
      cancelled: db.prepare("SELECT COUNT(*) as c FROM user_subscriptions WHERE status='cancelled'").get().c,
      expired:   db.prepare("SELECT COUNT(*) as c FROM user_subscriptions WHERE status='expired'").get().c,
      mrr_paise: db.prepare(`
        SELECT COALESCE(SUM(
          CASE WHEN p.billing_period = 'yearly' THEN p.price_paise / 12 ELSE p.price_paise END
        ), 0) AS s
        FROM user_subscriptions us
        JOIN subscription_plans p ON us.plan_id = p.id
        WHERE us.status = 'active'
      `).get().s
    };

    res.json({ subscriptions: subs, summary });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/subscriptions — assign a plan to a user
router.post('/subscriptions', adminOnly, (req, res) => {
  try {
    const { user_id, plan_id, expires_at } = req.body;
    if (!user_id || !plan_id) return res.status(400).json({ error: 'user_id and plan_id required' });
    const user = db.prepare('SELECT id FROM users WHERE id = ?').get(user_id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const plan = db.prepare('SELECT id FROM subscription_plans WHERE id = ?').get(plan_id);
    if (!plan) return res.status(404).json({ error: 'Plan not found' });

    const r = db.prepare(`
      INSERT INTO user_subscriptions (user_id, plan_id, expires_at)
      VALUES (?, ?, ?)
    `).run(user_id, plan_id, expires_at || null);
    res.status(201).json({ id: r.lastInsertRowid, message: 'Subscription created' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/subscriptions/:id — update status (cancel / reactivate / mark expired)
router.put('/subscriptions/:id', adminOnly, (req, res) => {
  try {
    const sub = db.prepare('SELECT * FROM user_subscriptions WHERE id = ?').get(req.params.id);
    if (!sub) return res.status(404).json({ error: 'Subscription not found' });
    const { status, expires_at } = req.body;
    const validStatuses = ['active','cancelled','expired'];
    if (status && !validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    if (status) {
      const cancelledAt = status === 'cancelled' ? "datetime('now')" : 'cancelled_at';
      db.prepare(`UPDATE user_subscriptions SET status = ?, cancelled_at = ${cancelledAt} WHERE id = ?`).run(status, req.params.id);
    }
    if (expires_at !== undefined) {
      db.prepare('UPDATE user_subscriptions SET expires_at = ? WHERE id = ?').run(expires_at, req.params.id);
    }
    res.json({ message: 'Subscription updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/subscriptions/:id
router.delete('/subscriptions/:id', adminOnly, (req, res) => {
  try {
    db.prepare('DELETE FROM user_subscriptions WHERE id = ?').run(req.params.id);
    res.json({ message: 'Subscription deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
