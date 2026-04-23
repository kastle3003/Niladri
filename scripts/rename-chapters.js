/**
 * Rename every course's chapters in order to the 5-foundation naming convention
 * (Foundation 'A' through 'E'). If a course has fewer than 5 chapters, missing
 * ones are created (empty). If it has more, extras are left with their existing
 * titles so nothing is lost.
 *
 * Idempotent: running twice does nothing extra.
 *
 *   node scripts/rename-chapters.js           # preview
 *   node scripts/rename-chapters.js --yes     # apply
 */
require('dotenv').config();
const db = require('../server/db');

const LABELS = ['A', 'B', 'C', 'D', 'E'];
const EXECUTE = process.argv.includes('--yes');

const courses = db.prepare('SELECT id, title FROM courses ORDER BY id').all();
if (!courses.length) { console.log('No courses.'); process.exit(0); }

const actions = [];

for (const course of courses) {
  const chapters = db.prepare(
    'SELECT id, title, order_index FROM chapters WHERE course_id = ? ORDER BY order_index, id'
  ).all(course.id);

  LABELS.forEach((letter, i) => {
    const desired = `Foundation '${letter}'`;
    const existing = chapters[i];
    if (!existing) {
      actions.push({ kind: 'insert', course_id: course.id, course_title: course.title, order_index: i, title: desired });
    } else if (existing.title !== desired) {
      actions.push({ kind: 'rename', chapter_id: existing.id, course_id: course.id, course_title: course.title, from: existing.title, to: desired, order_index: i });
    }
  });
}

if (!actions.length) {
  console.log('Nothing to do — all courses already conform.');
  process.exit(0);
}

console.log(`\nPlanned changes (${actions.length}):`);
for (const a of actions) {
  if (a.kind === 'rename') {
    console.log(`  [rename] course #${a.course_id} "${a.course_title}"  "${a.from}" → "${a.to}"`);
  } else {
    console.log(`  [insert] course #${a.course_id} "${a.course_title}"  + "${a.title}" (order ${a.order_index})`);
  }
}

if (!EXECUTE) {
  console.log('\n[DRY-RUN] Re-run with --yes to apply.');
  process.exit(0);
}

const tx = db.transaction(() => {
  for (const a of actions) {
    if (a.kind === 'rename') {
      db.prepare('UPDATE chapters SET title = ?, order_index = ? WHERE id = ?').run(a.to, a.order_index, a.chapter_id);
    } else {
      db.prepare('INSERT INTO chapters (course_id, title, order_index, description) VALUES (?, ?, ?, ?)')
        .run(a.course_id, a.title, a.order_index, '');
    }
  }
});
tx();
console.log('\n✅ Done.');
