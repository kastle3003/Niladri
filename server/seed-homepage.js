/**
 * Idempotent seed for the 5 courses shown on the public homepage.
 * Runs on every startup; inserts a course only if its slug is missing.
 *
 * Courses match the <article class="tier-card"> blocks in public/home.html.
 * Three distinct instructors: Taufiq Qureshi, Sveta Kilpady, Niladri Kumar.
 *
 * NOTE: `db` is passed in explicitly to avoid a circular import with db.js.
 */

function instructorIdByEmail(db, email, fallbackRole = 'instructor') {
  const u = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (u) return u.id;
  const any = db.prepare("SELECT id FROM users WHERE role = ? ORDER BY id LIMIT 1").get(fallbackRole);
  return any ? any.id : null;
}

const TIERS = [
  {
    title: 'Basic Foundation Course',
    slug: 'basic-foundation-course',
    subtitle: 'Enter the Training — Level A to Level E',
    description: 'New to rhythm? Start here. Learn the Djembe and navigate through Indian Percussion with Taufiq Qureshi. Train on any instrument — Djembe, Cajon, Darbuka, Duff — or start without one using specified household items. A 5-Level foundation course from Level A to Level E.',
    instructor_email: 'taufiq@thefoundationroom.in',
    instrument: 'Djembe', level: 'Foundation', category: 'Percussion',
    tags: ['Rhythm', 'Djembe', 'Indian Percussion', 'Beginner Friendly'],
    cover_color: '#2D4F1E', cover_accent: '#D1A14E',
    cover_image_url: 'https://images.unsplash.com/photo-1519892300165-cb5542fb47c7?w=1200&q=75&auto=format&fit=crop',
    duration_weeks: 20,
    level_labels: ['Level A', 'Level B', 'Level C', 'Level D', 'Level E'],
  },
  {
    title: 'Beginner Course',
    slug: 'beginner-course',
    subtitle: 'Already learning — Level A to Level D',
    description: 'For those already familiar with the basics who wish to pursue further learning and explore grooves. Increase fluency, familiarity and musical sense towards rhythm. Covers slightly complex grooves, applications to popular songs, and Indian rhythm concepts — Sam, Khaali, Chakradhar, Rela, Challan, Jati.',
    instructor_email: 'taufiq@thefoundationroom.in',
    instrument: 'Djembe', level: 'Beginner', category: 'Percussion',
    tags: ['Rhythm', 'Djembe', 'World Grooves', 'Indian Rhythm'],
    cover_color: '#1E3A5F', cover_accent: '#D1A14E',
    cover_image_url: 'https://images.unsplash.com/photo-1514320291840-2e0a9bf2a9ae?w=1200&q=75&auto=format&fit=crop',
    duration_weeks: 16,
    level_labels: ['Level A', 'Level B', 'Level C', 'Level D'],
  },
  {
    title: 'Intermediate Course',
    slug: 'intermediate-course',
    subtitle: 'Already playing — Level A to Level D',
    description: 'Pick up further concepts and details of Indian rhythm and the tabla repertoire on the Djembe. Develop more control, musicality, application and performance confidence. Study the Tabla repertoire — Punjab, Delhi, Ajrada Gharana, making Tihai\'s, intro to Peshkar.',
    instructor_email: 'sveta@thefoundationroom.in',
    instrument: 'Vocals', level: 'Intermediate', category: 'Vocals',
    tags: ['Hindustani Classical', 'Kirana Gharana', 'Raga', 'Sargam'],
    cover_color: '#4E1E2D', cover_accent: '#D1A14E',
    cover_image_url: 'https://images.unsplash.com/photo-1493225457124-a3eb161ffa5f?w=1200&q=75&auto=format&fit=crop',
    duration_weeks: 18,
    level_labels: ['Level A', 'Level B', 'Level C', 'Level D'],
  },
  {
    title: 'Advanced Course',
    slug: 'advanced-course',
    subtitle: 'Deeper study into Indian rhythms',
    description: 'Explore deeper concepts and intricate performer practices along with the art of accompaniment, stage training and further study of the tabla repertoire. Complex grooves, sound quality development, speed training, recitations, deeper study of Indian Rhythm.',
    instructor_email: 'niladri@thefoundationroom.in',
    instrument: 'Sitar', level: 'Advanced', category: 'Sitar',
    tags: ['Hindustani Classical', 'Imdadkhani Gharana', 'Raga', 'Improvisation'],
    cover_color: '#1A0D00', cover_accent: '#C8A84B',
    cover_image_url: 'https://images.unsplash.com/photo-1510915361894-db8b60106cb1?w=1200&q=75&auto=format&fit=crop',
    duration_weeks: 24,
    level_labels: ['Level A', 'Level B', 'Level C', 'Level D'],
  },
  {
    title: 'The Practise Room',
    slug: 'the-practise-room',
    subtitle: 'Practises designed for every kind of student',
    description: 'An unbounded practice hub — designed for absolute newcomers, beginners, intermediate, advanced and professional players alike. Daily riyaz tracks, groove loops, metronome challenges and guided practice plans with Taufiq Qureshi. Practise. Pursue. Perform.',
    instructor_email: 'taufiq@thefoundationroom.in',
    instrument: 'Djembe', level: 'Masterclass', category: 'Practice',
    tags: ['Practice', 'Riyaz', 'Daily Discipline'],
    cover_color: '#2D1E4F', cover_accent: '#D1A14E',
    cover_image_url: 'https://images.unsplash.com/photo-1558098329-a11cff621064?w=1200&q=75&auto=format&fit=crop',
    duration_weeks: null,
    level_labels: ['All Sessions'],
  },
];

function lessonsForLevel(levelLabel, courseTitle) {
  return [
    {
      title: `${levelLabel} — Orientation`,
      type: 'video',
      duration_minutes: 8,
      is_preview: 1,
      materials: [
        { type: 'video', title: `${levelLabel} overview`, url: 'https://www.youtube.com/embed/jfKfPfyJRdk', duration_seconds: 480 },
        { type: 'pdf',   title: `${levelLabel} syllabus`, url: 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf' },
      ],
    },
    {
      title: `${levelLabel} — Core Technique`,
      type: 'video',
      duration_minutes: 22,
      is_preview: 0,
      materials: [
        { type: 'video', title: 'Technique demonstration', url: 'https://www.youtube.com/embed/dQw4w9WgXcQ', duration_seconds: 1320 },
        { type: 'image', title: 'Technique reference', url: 'https://images.unsplash.com/photo-1519892300165-cb5542fb47c7?w=1200&q=75&auto=format&fit=crop' },
      ],
    },
    {
      title: `${levelLabel} — Practice Exercise`,
      type: 'exercise',
      duration_minutes: 18,
      is_preview: 0,
      materials: [
        { type: 'video', title: 'Play-along track', url: 'https://www.youtube.com/embed/5qap5aO4i9A', duration_seconds: 1080 },
        { type: 'pdf',   title: 'Practice sheet', url: 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf' },
      ],
    },
  ];
}

function ensureHomepageCourses(db) {
  const insertCourse = db.prepare(`
    INSERT INTO courses
      (title, slug, subtitle, description, instructor_id, instrument, level, category, tags,
       cover_color, cover_accent, cover_image_url, duration_weeks, lesson_count, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
  `);
  const insertChapter = db.prepare('INSERT INTO chapters (course_id, title, order_index, description) VALUES (?, ?, ?, ?)');
  const insertLesson = db.prepare('INSERT INTO lessons (chapter_id, course_id, title, order_index, type, content_url, duration_minutes, is_preview) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
  const insertMaterial = db.prepare('INSERT INTO lesson_materials (lesson_id, type, title, url, duration_seconds, order_index) VALUES (?, ?, ?, ?, ?, ?)');
  const bumpLessonCount = db.prepare('UPDATE courses SET lesson_count = ? WHERE id = ?');

  let added = 0;
  for (const tier of TIERS) {
    const existing = db.prepare('SELECT id FROM courses WHERE slug = ?').get(tier.slug);
    if (existing) continue;

    const instructorId = instructorIdByEmail(db, tier.instructor_email);
    if (!instructorId) {
      console.warn(`[seed-homepage] No instructor for ${tier.instructor_email} — skipping "${tier.title}"`);
      continue;
    }

    const courseId = insertCourse.run(
      tier.title, tier.slug, tier.subtitle, tier.description,
      instructorId, tier.instrument, tier.level, tier.category,
      JSON.stringify(tier.tags || []),
      tier.cover_color, tier.cover_accent, tier.cover_image_url,
      tier.duration_weeks, 0
    ).lastInsertRowid;

    let lessonCount = 0;
    tier.level_labels.forEach((label, chIdx) => {
      const chapterId = insertChapter.run(courseId, label, chIdx, `${tier.title} — ${label}`).lastInsertRowid;
      lessonsForLevel(label, tier.title).forEach((lesson, lIdx) => {
        const lessonId = insertLesson.run(
          chapterId, courseId, lesson.title, lIdx,
          lesson.type, null, lesson.duration_minutes || null,
          lesson.is_preview ? 1 : 0
        ).lastInsertRowid;
        lessonCount++;
        lesson.materials.forEach((m, mIdx) => {
          insertMaterial.run(lessonId, m.type, m.title, m.url, m.duration_seconds || null, mIdx);
        });
      });
    });
    bumpLessonCount.run(lessonCount, courseId);
    added++;
    console.log(`[seed-homepage] + ${tier.title} (${tier.level_labels.length} foundations, ${lessonCount} lessons)`);
  }

  if (added === 0) console.log('[seed-homepage] all 5 homepage courses already present.');
  else console.log(`[seed-homepage] inserted ${added} course(s).`);
}

module.exports = { ensureHomepageCourses };
