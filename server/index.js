require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();

// Ensure data dirs exist
const uploadDir = process.env.UPLOAD_DIR || './data/uploads';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const certDir = path.join(__dirname, '../data/certificates');
if (!fs.existsSync(certDir)) fs.mkdirSync(certDir, { recursive: true });

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Root & named routes (declared BEFORE express.static) ──
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/home.html'));
});
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ── SEO-friendly course URLs: /courses/:slug ──
// /courses → courses.html (static file, served by express.static)
// /courses/sitar-the-complete-foundation → course-landing.html (JS reads slug from pathname)
app.get('/courses/:slug', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/course-landing.html'));
});

// ── Public (no-auth) API for landing pages ──
app.use('/api/public', require('./routes/public.routes'));

// Static files — never cache HTML, so admin-page changes propagate immediately
app.use(express.static(path.join(__dirname, '../public'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));
app.use('/uploads', express.static(path.join(__dirname, '../data/uploads')));

// Mount routes
app.use('/api/auth', require('./routes/auth.routes'));
app.use('/api/courses', require('./middleware/auth'), require('./routes/courses.routes'));
app.use('/api/enrollments', require('./middleware/auth'), require('./routes/enrollments.routes'));
app.use('/api/lessons', require('./middleware/auth'), require('./routes/lessons.routes'));
app.use('/api/sheet-music', require('./middleware/auth'), require('./routes/sheetmusic.routes'));
app.use('/api/recordings', require('./middleware/auth'), require('./routes/recordings.routes'));
app.use('/api/masterclasses', require('./middleware/auth'), require('./routes/masterclasses.routes'));
app.use('/api/submissions', require('./middleware/auth'), require('./routes/submissions.routes'));
app.use('/api/quotes', require('./middleware/auth'), require('./routes/quotes.routes'));
app.use('/api/admin', require('./middleware/auth'), require('./routes/admin.routes'));
app.use('/api/chapters', require('./middleware/auth'), require('./routes/chapters.routes'));
app.use('/api/assignments', require('./middleware/auth'), require('./routes/assignments.routes'));

// Sprint 1+2: Learning core & communication
app.use('/api/quizzes', require('./middleware/auth'), require('./routes/quiz.routes'));
app.use('/api/notifications', require('./middleware/auth'), require('./routes/notifications.routes'));
app.use('/api/messages', require('./middleware/auth'), require('./routes/messages.routes'));
app.use('/api/profile', require('./middleware/auth'), require('./routes/profile.routes'));

// Sprint 3: Analytics & engagement
app.use('/api/analytics', require('./middleware/auth'), require('./routes/analytics.routes'));
app.use('/api/practice-log', require('./middleware/auth'), require('./routes/practice-log.routes'));
app.use('/api/calendar', require('./middleware/auth'), require('./routes/calendar.routes'));

// Sprint 4+5+6: Monetisation, growth, scale
app.use('/api/payments', require('./middleware/auth'), require('./routes/payments.routes'));
app.use('/api/certificates', require('./middleware/auth'), require('./routes/certificates.routes'));
app.use('/api/live-sessions', require('./middleware/auth'), require('./routes/live-classes.routes'));
app.use('/api/search', require('./middleware/auth'), require('./routes/search.routes'));
app.use('/api/announcements', require('./middleware/auth'), require('./routes/announcements.routes'));
app.use('/api/resources', require('./middleware/auth'), require('./routes/resources.routes'));
app.use('/api/email', require('./middleware/auth'), require('./routes/email.routes'));
app.use('/api/roles', require('./middleware/auth'), require('./routes/roles.routes'));

// CMS & Blog
app.use('/api/cms', require('./middleware/auth'), require('./routes/cms.routes'));
app.use('/api/blog', require('./routes/blog.routes'));

// SPA fallback — serve home for non-API, non-file routes
app.get('*', (req, res) => {
  const file = path.join(__dirname, '../public', req.path);
  if (require('fs').existsSync(file)) {
    res.sendFile(file);
  } else {
    res.sendFile(path.join(__dirname, '../public/home.html'));
  }
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`The Archive LMS running on http://localhost:${PORT}`));
