/**
 * One-shot cleanup: keep exactly 3 instructors (Niladri, Taufiq, Sveta) each
 * with exactly 1 course (their first by id). All other instructors are demoted
 * to 'student' (preserving their accounts/logins). All other courses and their
 * dependent rows (chapters, lessons, materials, timestamps, enrollments, etc.)
 * are deleted.
 *
 * Dry-run by default. Pass --yes to execute.
 *
 *   node scripts/prune-to-3.js           # preview
 *   node scripts/prune-to-3.js --yes     # commit
 */
require('dotenv').config();
const db = require('../server/db');

const KEEP_EMAILS = [
  'niladri@thefoundationroom.in',
  'taufiq@thefoundationroom.in',
  'sveta@thefoundationroom.in',
];
const EXECUTE = process.argv.includes('--yes');

function log(...args) { console.log(...args); }

function plan() {
  const kept = db.prepare(`
    SELECT id, email, first_name, last_name FROM users
    WHERE email IN (${KEEP_EMAILS.map(() => '?').join(',')}) AND role = 'instructor'
  `).all(...KEEP_EMAILS);
  if (kept.length !== KEEP_EMAILS.length) {
    throw new Error(`Expected ${KEEP_EMAILS.length} kept instructors, found ${kept.length}. Seed may not have run.`);
  }
  const keptInstructorIds = kept.map(k => k.id);

  // Pick the earliest course (lowest id) for each kept instructor
  const keptCourses = keptInstructorIds.map(instId => {
    const c = db.prepare('SELECT id, title, slug FROM courses WHERE instructor_id = ? ORDER BY id ASC LIMIT 1').get(instId);
    if (!c) throw new Error(`Kept instructor id=${instId} has no courses to keep`);
    return { ...c, instructor_id: instId };
  });
  const keptCourseIds = keptCourses.map(c => c.id);

  const demoteInstructors = db.prepare(`
    SELECT id, email, first_name, last_name FROM users
    WHERE role = 'instructor' AND id NOT IN (${keptInstructorIds.map(() => '?').join(',')})
  `).all(...keptInstructorIds);

  const deleteCourses = db.prepare(`
    SELECT id, title, slug, instructor_id FROM courses
    WHERE id NOT IN (${keptCourseIds.map(() => '?').join(',')})
  `).all(...keptCourseIds);

  return { kept, keptInstructorIds, keptCourses, keptCourseIds, demoteInstructors, deleteCourses };
}

function run() {
  const p = plan();

  log('\n=== KEEP these 3 instructors ===');
  p.kept.forEach(i => log(`  id=${i.id}  ${i.email}  (${i.first_name} ${i.last_name})`));

  log('\n=== KEEP these 3 courses ===');
  p.keptCourses.forEach(c => log(`  id=${c.id}  inst=${c.instructor_id}  "${c.title}"  slug=${c.slug}`));

  log(`\n=== DEMOTE to 'student' (${p.demoteInstructors.length} user${p.demoteInstructors.length === 1 ? '' : 's'}) ===`);
  p.demoteInstructors.forEach(u => log(`  id=${u.id}  ${u.email}  (${u.first_name} ${u.last_name})`));

  log(`\n=== DELETE these courses (${p.deleteCourses.length}) ===`);
  p.deleteCourses.forEach(c => log(`  id=${c.id}  "${c.title}"  (inst=${c.instructor_id})  slug=${c.slug}`));

  // Dependent-row counts for the courses about to be deleted (for visibility)
  if (p.deleteCourses.length) {
    const delIds = p.deleteCourses.map(c => c.id);
    const ph = delIds.map(() => '?').join(',');
    const countOf = (sql) => db.prepare(sql).get(...delIds).n;
    const lessonIdsRows = db.prepare(`SELECT id FROM lessons WHERE course_id IN (${ph})`).all(...delIds);
    const lessonIds = lessonIdsRows.map(r => r.id);

    log('\n--- dependent rows that will be removed ---');
    log(`  chapters:          ${countOf(`SELECT COUNT(*) n FROM chapters WHERE course_id IN (${ph})`)}`);
    log(`  lessons:           ${lessonIds.length}`);
    if (lessonIds.length) {
      const lph = lessonIds.map(() => '?').join(',');
      const lcount = (sql) => db.prepare(sql).all(...lessonIds)[0].n;
      log(`  lesson_materials:  ${db.prepare(`SELECT COUNT(*) n FROM lesson_materials WHERE lesson_id IN (${lph})`).get(...lessonIds).n}`);
      log(`  lesson_progress:   ${db.prepare(`SELECT COUNT(*) n FROM lesson_progress WHERE lesson_id IN (${lph})`).get(...lessonIds).n}`);
    }
    log(`  enrollments:       ${countOf(`SELECT COUNT(*) n FROM enrollments WHERE course_id IN (${ph})`)}`);
    log(`  sheet_music:       ${countOf(`SELECT COUNT(*) n FROM sheet_music WHERE course_id IN (${ph})`)}`);
    log(`  assignments:       ${countOf(`SELECT COUNT(*) n FROM assignments WHERE course_id IN (${ph})`)}`);
  }

  if (!EXECUTE) {
    log('\n[DRY-RUN] Nothing changed. Re-run with --yes to apply.');
    return;
  }

  log('\n=== EXECUTING ===');
  const tx = db.transaction(() => {
    const delIds = p.deleteCourses.map(c => c.id);
    if (delIds.length) {
      const ph = delIds.map(() => '?').join(',');
      const lessonIds = db.prepare(`SELECT id FROM lessons WHERE course_id IN (${ph})`).all(...delIds).map(r => r.id);

      if (lessonIds.length) {
        const lph = lessonIds.map(() => '?').join(',');
        const materialIds = db.prepare(`SELECT id FROM lesson_materials WHERE lesson_id IN (${lph})`).all(...lessonIds).map(r => r.id);
        if (materialIds.length) {
          const mph = materialIds.map(() => '?').join(',');
          db.prepare(`DELETE FROM video_timestamps WHERE material_id IN (${mph})`).run(...materialIds);
        }
        db.prepare(`DELETE FROM lesson_materials WHERE lesson_id IN (${lph})`).run(...lessonIds);
        db.prepare(`DELETE FROM lesson_progress WHERE lesson_id IN (${lph})`).run(...lessonIds);
      }

      db.prepare(`DELETE FROM lessons WHERE course_id IN (${ph})`).run(...delIds);
      db.prepare(`DELETE FROM chapters WHERE course_id IN (${ph})`).run(...delIds);
      db.prepare(`DELETE FROM enrollments WHERE course_id IN (${ph})`).run(...delIds);
      db.prepare(`DELETE FROM sheet_music WHERE course_id IN (${ph})`).run(...delIds);
      db.prepare(`DELETE FROM assignments WHERE course_id IN (${ph})`).run(...delIds);
      // Soft-clear foreign refs on audit tables instead of deleting them
      try { db.prepare(`UPDATE payments SET course_id = NULL WHERE course_id IN (${ph})`).run(...delIds); } catch (_) {}
      try { db.prepare(`UPDATE announcements SET course_id = NULL WHERE course_id IN (${ph})`).run(...delIds); } catch (_) {}
      try { db.prepare(`UPDATE live_sessions SET course_id = NULL WHERE course_id IN (${ph})`).run(...delIds); } catch (_) {}

      db.prepare(`DELETE FROM courses WHERE id IN (${ph})`).run(...delIds);
    }

    if (p.demoteInstructors.length) {
      const dIds = p.demoteInstructors.map(u => u.id);
      const dph = dIds.map(() => '?').join(',');
      db.prepare(`UPDATE users SET role = 'student' WHERE id IN (${dph})`).run(...dIds);
    }
  });

  tx();
  log('\n✅ Done.');
  log('Courses remaining:     ' + db.prepare('SELECT COUNT(*) n FROM courses').get().n);
  log('Instructors remaining: ' + db.prepare("SELECT COUNT(*) n FROM users WHERE role='instructor'").get().n);
}

try {
  run();
} catch (e) {
  console.error('\nFAILED:', e.message);
  process.exit(1);
}
