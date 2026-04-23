// Access-control helpers for the Course → Foundation → Lecture hierarchy.
//
// Term mapping (existing schema → spec):
//   Course     = courses
//   Foundation = chapters            (ordered by order_index: A, B, C, D, E …)
//   Lecture    = lessons             (ordered by order_index within a foundation)
//   Asset      = lesson_materials    (pdf / image / url / video)
//
// Rules enforced:
//   - A preview lecture is accessible to anyone authed.
//   - Otherwise, the user must either own the course bundle OR own the parent foundation.
//   - Foundations must be purchased in sequence (A → E).
//     A foundation can be bought only if the previous foundation is 100% complete AND owned.
//   - A non-preview lecture in a purchased foundation unlocks only after the previous lecture
//     in the same foundation is "completed" (completion_percentage >= 90).
//   - Instructors & admins bypass all of this.
//
// All functions return plain data — no throwing. Callers decide status codes.

const db = require('../db');

const COMPLETION_THRESHOLD = 90;   // % — "≥ 90% video watched"

function isStaff(user) {
  return user && (user.role === 'admin' || user.role === 'instructor');
}

// ── Lookups ────────────────────────────────────────────────────────────────
function getLesson(lessonId) {
  return db.prepare('SELECT * FROM lessons WHERE id = ?').get(lessonId);
}
function getFoundation(chapterId) {
  return db.prepare('SELECT * FROM chapters WHERE id = ?').get(chapterId);
}
function getCourse(courseId) {
  return db.prepare('SELECT * FROM courses WHERE id = ?').get(courseId);
}
function getLessonProgress(userId, lessonId) {
  return db.prepare(
    'SELECT * FROM lesson_progress WHERE student_id = ? AND lesson_id = ?'
  ).get(userId, lessonId);
}

// Returns the lessons inside a foundation, ordered.
function foundationLessons(chapterId) {
  return db.prepare(
    'SELECT * FROM lessons WHERE chapter_id = ? ORDER BY order_index, id'
  ).all(chapterId);
}
// Returns the foundations inside a course, ordered.
function courseFoundations(courseId) {
  return db.prepare(
    'SELECT * FROM chapters WHERE course_id = ? ORDER BY order_index, id'
  ).all(courseId);
}

// ── Ownership ──────────────────────────────────────────────────────────────
function ownsBundle(userId, courseId) {
  if (!userId || !courseId) return false;
  const row = db.prepare(
    `SELECT 1 FROM purchases
     WHERE user_id = ? AND course_id = ? AND type = 'bundle' AND status = 'completed' LIMIT 1`
  ).get(userId, courseId);
  return !!row;
}
function ownsFoundation(userId, foundationId) {
  if (!userId || !foundationId) return false;
  const row = db.prepare(
    `SELECT 1 FROM purchases
     WHERE user_id = ? AND foundation_id = ? AND type = 'individual' AND status = 'completed' LIMIT 1`
  ).get(userId, foundationId);
  return !!row;
}
// True if the user owns the parent course bundle OR the specific foundation.
function hasFoundationAccess(userId, foundationId) {
  const f = getFoundation(foundationId);
  if (!f) return false;
  if (ownsBundle(userId, f.course_id)) return true;
  if (ownsFoundation(userId, foundationId)) return true;
  return false;
}
function hasCourseAccess(userId, courseId) {
  if (!userId || !courseId) return false;
  if (ownsBundle(userId, courseId)) return true;
  // If the user owns every foundation individually, treat as full access.
  const fs = courseFoundations(courseId);
  if (!fs.length) return false;
  return fs.every(f => ownsFoundation(userId, f.id));
}

// ── Completion ─────────────────────────────────────────────────────────────
function isLessonCompleted(userId, lessonId) {
  const p = getLessonProgress(userId, lessonId);
  if (!p) return false;
  if (p.completed === 1) return true;
  return (p.completion_percentage || 0) >= COMPLETION_THRESHOLD;
}
function isFoundationCompleted(userId, foundationId) {
  const lessons = foundationLessons(foundationId);
  if (!lessons.length) return false;
  return lessons.every(l => isLessonCompleted(userId, l.id));
}

// ── Lecture access ─────────────────────────────────────────────────────────
// Returns { allowed, reason? } so the route can send a helpful 403 body.
function canAccessLecture(user, lessonId) {
  const lesson = getLesson(lessonId);
  if (!lesson) return { allowed: false, reason: 'lesson_not_found' };
  if (!user)   return { allowed: false, reason: 'not_authenticated' };

  // Staff always get in.
  if (isStaff(user)) return { allowed: true, reason: 'staff' };

  // Preview lectures are open for any authed user.
  if (lesson.is_preview) return { allowed: true, reason: 'preview' };

  // Must own the foundation OR the course bundle.
  if (!hasFoundationAccess(user.id, lesson.chapter_id)) {
    return { allowed: false, reason: 'not_purchased' };
  }

  // Strict sequential unlock inside the foundation:
  // first non-preview lecture is always accessible if owned;
  // subsequent non-preview lectures require the previous one to be completed.
  const siblings = foundationLessons(lesson.chapter_id);
  const idx = siblings.findIndex(l => l.id === lesson.id);
  for (let i = 0; i < idx; i++) {
    const prev = siblings[i];
    if (prev.is_preview) continue; // previews don't gate anything
    if (!isLessonCompleted(user.id, prev.id)) {
      return { allowed: false, reason: 'previous_lecture_incomplete', blocked_by: prev.id };
    }
  }
  return { allowed: true, reason: 'owned' };
}

// ── Foundation purchase eligibility (A → E sequence) ───────────────────────
// Returns { allowed, reason? }.
function canPurchaseFoundation(userId, foundationId) {
  const f = getFoundation(foundationId);
  if (!f) return { allowed: false, reason: 'foundation_not_found' };

  // If already owned (bundle or individual), reject with a friendly reason
  if (ownsBundle(userId, f.course_id)) return { allowed: false, reason: 'already_owned_via_bundle' };
  if (ownsFoundation(userId, foundationId)) return { allowed: false, reason: 'already_owned' };

  const siblings = courseFoundations(f.course_id);
  const idx = siblings.findIndex(x => x.id === foundationId);
  if (idx < 0) return { allowed: false, reason: 'sequence_lookup_failed' };

  // The very first foundation is always purchasable.
  if (idx === 0) return { allowed: true, reason: 'first_foundation' };

  const prev = siblings[idx - 1];
  if (!ownsFoundation(userId, prev.id) && !ownsBundle(userId, f.course_id)) {
    return { allowed: false, reason: 'previous_foundation_not_purchased', blocked_by: prev.id };
  }
  if (!isFoundationCompleted(userId, prev.id)) {
    return { allowed: false, reason: 'previous_foundation_incomplete', blocked_by: prev.id };
  }
  return { allowed: true, reason: 'sequence_ok' };
}

// ── Misc helpers used by the summary endpoints ─────────────────────────────
function lessonCompletionPct(userId, lessonId) {
  const p = getLessonProgress(userId, lessonId);
  return p ? (p.completion_percentage || 0) : 0;
}
function foundationProgressPct(userId, foundationId) {
  const lessons = foundationLessons(foundationId);
  if (!lessons.length) return 0;
  const total = lessons.reduce((a, l) => a + (l.duration_seconds || 0), 0);
  // If durations are zero, fall back to lesson-count ratio.
  if (total === 0) {
    const done = lessons.filter(l => isLessonCompleted(userId, l.id)).length;
    return Math.round((done / lessons.length) * 100);
  }
  const watched = lessons.reduce((a, l) => {
    const p = getLessonProgress(userId, l.id);
    return a + Math.min(p?.watched_seconds || 0, l.duration_seconds || 0);
  }, 0);
  return Math.round((watched / total) * 100);
}

module.exports = {
  COMPLETION_THRESHOLD,
  isStaff,
  getLesson, getFoundation, getCourse,
  getLessonProgress,
  foundationLessons, courseFoundations,
  ownsBundle, ownsFoundation,
  hasFoundationAccess, hasCourseAccess,
  isLessonCompleted, isFoundationCompleted,
  canAccessLecture, canPurchaseFoundation,
  lessonCompletionPct, foundationProgressPct,
};
