const express = require('express');
const router = express.Router();
const db = require('../db');
const access = require('../lib/access');

// Max forward jump (seconds) tolerated between two successive progress pings.
// Anything bigger is treated as a scrub/skip and rejected.
const MAX_FORWARD_JUMP_SECONDS = 10;

// POST /api/progress/update
// Body: { lesson_id, position_seconds, duration_seconds? }
// - position_seconds: current playhead in the video
// - duration_seconds: optional, used to compute completion percentage if lesson.duration_seconds is missing
//
// Anti-skip rule:
//   Reject when position_seconds > stored_last_position + MAX_FORWARD_JUMP_SECONDS.
//   Seeking backwards is always allowed (learners re-watch).
//   Tiny forward jumps (≤ 10s) are allowed for network-lag tolerance.
//
// Completion rule:
//   watched_seconds / duration_seconds >= COMPLETION_THRESHOLD%  →  is_completed = 1.
//   watched_seconds only ever grows (we keep the max).
router.post('/update', (req, res) => {
  try {
    const userId = req.user.id;
    const { lesson_id, position_seconds, duration_seconds } = req.body || {};

    if (!lesson_id) return res.status(400).json({ error: 'lesson_id is required' });
    if (position_seconds == null || isNaN(Number(position_seconds))) {
      return res.status(400).json({ error: 'position_seconds is required' });
    }

    const lesson = access.getLesson(lesson_id);
    if (!lesson) return res.status(404).json({ error: 'Lesson not found' });

    // Access check — staff & preview skip ownership.
    const acc = access.canAccessLecture(req.user, lesson.id);
    if (!acc.allowed) {
      return res.status(403).json({ error: 'Access denied', reason: acc.reason, blocked_by: acc.blocked_by });
    }

    // Resolve duration: prefer persisted value, fall back to client-supplied, fall back to 0
    const effectiveDuration = Math.max(
      parseInt(lesson.duration_seconds) || 0,
      parseInt(duration_seconds) || 0
    );
    // Opportunistically persist duration on the lesson so the next call doesn't need it.
    if (effectiveDuration > 0 && !lesson.duration_seconds) {
      db.prepare('UPDATE lessons SET duration_seconds = ? WHERE id = ?').run(effectiveDuration, lesson.id);
    }

    const pos = Math.max(0, Math.round(Number(position_seconds)));

    // Read existing progress (may not exist yet)
    const prev = access.getLessonProgress(userId, lesson.id);
    const prevLast = prev ? (prev.last_position || 0) : 0;
    const prevWatched = prev ? (prev.watched_seconds || 0) : 0;

    // ── Anti-skip: reject if client jumped forward more than the buffer ──
    if (pos > prevLast + MAX_FORWARD_JUMP_SECONDS) {
      return res.status(400).json({
        error: 'Forward skipping is not allowed',
        reason: 'skip_detected',
        last_position: prevLast,
        attempted_position: pos,
        max_jump: MAX_FORWARD_JUMP_SECONDS,
      });
    }

    // watched_seconds is monotonic: only the max ever seen.
    const newWatched = Math.max(prevWatched, pos);

    const completionPct = effectiveDuration > 0
      ? Math.min(100, Math.round((newWatched / effectiveDuration) * 100))
      : 0;

    const justCompleted = completionPct >= access.COMPLETION_THRESHOLD;

    // Upsert lesson_progress
    db.prepare(`
      INSERT INTO lesson_progress
        (student_id, lesson_id, completed, completed_at, watched_seconds, last_position, completion_percentage, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(student_id, lesson_id) DO UPDATE SET
        watched_seconds = excluded.watched_seconds,
        last_position = excluded.last_position,
        completion_percentage = excluded.completion_percentage,
        completed = CASE WHEN lesson_progress.completed = 1 THEN 1 ELSE excluded.completed END,
        completed_at = CASE WHEN lesson_progress.completed = 1 THEN lesson_progress.completed_at
                            WHEN excluded.completed = 1 THEN datetime('now')
                            ELSE lesson_progress.completed_at END,
        updated_at = datetime('now')
    `).run(
      userId, lesson.id,
      justCompleted ? 1 : 0,
      justCompleted ? new Date().toISOString() : null,
      newWatched, pos, completionPct
    );

    // If this update *just flipped* the lesson to completed, recompute enrollment progress
    // and look for a foundation-unlock event for emailing purposes.
    let foundationUnlocked = false;
    let courseUnlocked = false;
    if (justCompleted && !(prev && prev.completed === 1)) {
      // Recalculate enrollment progress_pct (same approach as /api/lessons/:id/complete)
      const enrollment = db.prepare('SELECT * FROM enrollments WHERE student_id = ? AND course_id = ?').get(userId, lesson.course_id);
      if (enrollment) {
        const totalLessons = db.prepare('SELECT COUNT(*) c FROM lessons WHERE course_id = ?').get(lesson.course_id).c;
        const done = db.prepare(`
          SELECT COUNT(*) c FROM lesson_progress lp
          JOIN lessons l ON lp.lesson_id = l.id
          WHERE lp.student_id = ? AND l.course_id = ? AND lp.completed = 1
        `).get(userId, lesson.course_id).c;
        const pct = totalLessons ? Math.round((done / totalLessons) * 100) : 0;
        db.prepare('UPDATE enrollments SET progress_pct = ?, last_accessed_at = datetime(\'now\') WHERE student_id = ? AND course_id = ?')
          .run(pct, userId, lesson.course_id);
      }

      // Foundation unlock event: current foundation 100% → if the user owns it,
      // the NEXT foundation is now purchase-eligible.
      if (access.isFoundationCompleted(userId, lesson.chapter_id)) {
        foundationUnlocked = true;
        const sibs = access.courseFoundations(lesson.course_id);
        const idx = sibs.findIndex(f => f.id === lesson.chapter_id);
        const nextF = sibs[idx + 1];
        if (nextF) emitEmail(userId, 'foundation_unlocked', { foundation: nextF.title });
      }

      // Course unlock (whole course complete)
      const allCompleteRow = db.prepare(`
        SELECT
          (SELECT COUNT(*) FROM lessons WHERE course_id = ?) AS total,
          (SELECT COUNT(*) FROM lesson_progress lp JOIN lessons l ON lp.lesson_id = l.id
              WHERE lp.student_id = ? AND l.course_id = ? AND lp.completed = 1) AS done
      `).get(lesson.course_id, userId, lesson.course_id);
      if (allCompleteRow.total > 0 && allCompleteRow.total === allCompleteRow.done) {
        courseUnlocked = true;
        emitEmail(userId, 'course_unlocked', { course_id: lesson.course_id });
      } else {
        emitEmail(userId, 'lecture_completed', { lesson_id: lesson.id, title: lesson.title });
      }
    }

    res.json({
      lesson_id: lesson.id,
      watched_seconds: newWatched,
      last_position: pos,
      completion_percentage: completionPct,
      is_completed: justCompleted,
      duration_seconds: effectiveDuration,
      foundation_unlocked: foundationUnlocked,
      course_unlocked: courseUnlocked,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/progress/:lesson_id
router.get('/:lesson_id', (req, res) => {
  try {
    const lesson = access.getLesson(req.params.lesson_id);
    if (!lesson) return res.status(404).json({ error: 'Lesson not found' });
    const p = access.getLessonProgress(req.user.id, lesson.id);
    res.json({
      lesson_id: lesson.id,
      watched_seconds: p ? (p.watched_seconds || 0) : 0,
      last_position: p ? (p.last_position || 0) : 0,
      completion_percentage: p ? (p.completion_percentage || 0) : 0,
      is_completed: !!(p && p.completed === 1),
      duration_seconds: lesson.duration_seconds || 0,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Convenience summary for a foundation: per-lecture status + aggregate %.
router.get('/foundation/:foundation_id', (req, res) => {
  try {
    const f = access.getFoundation(req.params.foundation_id);
    if (!f) return res.status(404).json({ error: 'Foundation not found' });
    const lessons = access.foundationLessons(f.id);
    const out = lessons.map(l => {
      const p = access.getLessonProgress(req.user.id, l.id);
      const acc = access.canAccessLecture(req.user, l.id);
      return {
        lesson_id: l.id,
        title: l.title,
        order_index: l.order_index,
        is_preview: !!l.is_preview,
        duration_seconds: l.duration_seconds || 0,
        watched_seconds: p ? (p.watched_seconds || 0) : 0,
        last_position: p ? (p.last_position || 0) : 0,
        completion_percentage: p ? (p.completion_percentage || 0) : 0,
        is_completed: !!(p && p.completed === 1),
        accessible: acc.allowed,
        locked_reason: acc.allowed ? null : acc.reason,
      };
    });
    res.json({
      foundation_id: f.id,
      title: f.title,
      progress_pct: access.foundationProgressPct(req.user.id, f.id),
      is_completed: access.isFoundationCompleted(req.user.id, f.id),
      lessons: out,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Internal: simulated email sender — writes to email_logs so the existing
// admin Email-Logs page shows these events. Real SMTP integration lives in admin config.
function emitEmail(userId, template, data) {
  try {
    const user = db.prepare('SELECT email FROM users WHERE id = ?').get(userId);
    if (!user) return;
    const subjects = {
      payment_success:      'Payment received',
      foundation_unlocked:  'New foundation unlocked',
      course_unlocked:      'Course complete — well done',
      lecture_completed:    'Lecture completed',
    };
    db.prepare(`
      INSERT INTO email_logs (to_email, subject, template_name, status)
      VALUES (?, ?, ?, 'sent')
    `).run(user.email, subjects[template] || template, template);
  } catch (e) { /* best-effort */ }
}

module.exports = router;
module.exports.emitEmail = emitEmail;
