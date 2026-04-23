// End-to-end smoke test for: public home, auth, course CRUD at instructor level,
// file upload through Wasabi, and student access to a preview lesson.
const http = require('http');

const BASE = 'http://localhost:3001';

function req(method, path, { token, json, body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const opts = { method, headers: { ...headers } };
    let payload = body;
    if (json !== undefined) {
      payload = JSON.stringify(json);
      opts.headers['content-type'] = 'application/json';
      opts.headers['content-length'] = Buffer.byteLength(payload);
    }
    if (token) opts.headers['authorization'] = 'Bearer ' + token;
    const r = http.request(BASE + path, opts, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = data; }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed });
      });
    });
    r.on('error', reject);
    if (payload) r.write(payload);
    r.end();
  });
}

function assert(cond, msg) {
  if (!cond) throw new Error('ASSERT FAIL: ' + msg);
  console.log('  ✓ ' + msg);
}

(async () => {
  console.log('1. GET / (homepage)');
  const home = await req('GET', '/');
  assert(home.status === 200, 'homepage returns 200');

  console.log('2. Login as Taufiq (instructor)');
  const login = await req('POST', '/api/auth/login', { json: { email: 'taufiq@thefoundationroom.in', password: 'password123' } });
  assert(login.status === 200 && login.body.token, 'instructor login ok');
  const instructorToken = login.body.token;
  const instructorId = login.body.user.id;
  console.log('   instructor id:', instructorId);

  console.log('3. List courses — expect at least 5 homepage courses');
  const list = await req('GET', '/api/courses', { token: instructorToken });
  assert(list.status === 200, 'courses list 200');
  const slugs = (list.body.courses || []).map(c => c.slug);
  for (const s of ['basic-foundation-course', 'beginner-course', 'intermediate-course', 'advanced-course', 'the-practise-room']) {
    assert(slugs.includes(s), `homepage course present: ${s}`);
  }

  console.log('4. Instructor creates a new course');
  const create = await req('POST', '/api/courses', {
    token: instructorToken,
    json: { title: 'E2E Test Course', subtitle: 'sub', description: 'd', level: 'Foundation', instrument: 'Djembe', category: 'Percussion' }
  });
  assert(create.status === 201 && create.body.course.id, 'course created');
  const newCourseId = create.body.course.id;
  console.log('   new course id:', newCourseId);

  console.log('5. Instructor creates a chapter');
  const chap = await req('POST', '/api/chapters', { token: instructorToken, json: { course_id: newCourseId, title: 'Level A' } });
  assert(chap.status === 201 && chap.body.id, 'chapter created');
  const chapterId = chap.body.id;

  console.log('6. Instructor creates a preview lesson');
  const les = await req('POST', '/api/lessons', {
    token: instructorToken,
    json: { course_id: newCourseId, chapter_id: chapterId, title: 'E2E Preview Lesson', type: 'video', is_preview: true }
  });
  assert(les.status === 201 && les.body.lesson.id, 'lesson created');
  assert(les.body.lesson.is_preview === 1, 'lesson is_preview = 1');
  const lessonId = les.body.lesson.id;

  console.log('7. Upload a file to Wasabi via /api/materials (multipart)');
  const boundary = '----e2e' + Date.now();
  const fileContent = Buffer.from('e2e test file content ' + Date.now());
  const parts = [];
  const push = (name, val) => parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${val}\r\n`));
  push('lesson_id', String(lessonId));
  push('title', 'E2E uploaded PDF');
  parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="test.txt"\r\nContent-Type: text/plain\r\n\r\n`));
  parts.push(fileContent);
  parts.push(Buffer.from(`\r\n--${boundary}--\r\n`));
  const multipartBody = Buffer.concat(parts);
  const upload = await req('POST', '/api/materials', {
    token: instructorToken,
    body: multipartBody,
    headers: {
      'content-type': 'multipart/form-data; boundary=' + boundary,
      'content-length': multipartBody.length,
    }
  });
  assert(upload.status === 201, 'material upload 201');
  const url = upload.body.material.url;
  console.log('   uploaded url:', url);
  assert(url.startsWith('/api/files/lessons/'), 'stored URL is Wasabi-backed');

  console.log('8. GET /api/files/<key> follows a 302 to a presigned Wasabi URL');
  const follow = await req('GET', url, { token: instructorToken });
  assert(follow.status === 302, 'server returns 302');
  assert(/wasabisys\.com/.test(follow.headers.location || ''), 'Location points at wasabisys.com');

  console.log('9. Login as student and confirm preview lesson is accessible');
  const slogin = await req('POST', '/api/auth/login', { json: { email: 'student@thefoundationroom.in', password: 'password123' } });
  assert(slogin.status === 200 && slogin.body.token, 'student login ok');
  const studentToken = slogin.body.token;

  console.log('10. Student fetches the preview lesson');
  const slesson = await req('GET', `/api/lessons/${lessonId}`, { token: studentToken });
  assert(slesson.status === 200, `preview lesson accessible to student (got ${slesson.status})`);
  assert(slesson.body.lesson.is_preview === 1, 'lesson.is_preview persists');

  console.log('11. Student cannot access a non-preview lesson from a seeded course');
  const seeded = await req('GET', '/api/courses', { token: studentToken });
  const foundation = seeded.body.courses.find(c => c.slug === 'basic-foundation-course');
  const chaptersOfFoundation = await req('GET', `/api/courses/${foundation.id}/chapters`, { token: studentToken });
  const firstChapter = chaptersOfFoundation.body.chapters[0];
  const nonPreview = firstChapter.lessons.find(l => !l.is_preview);
  const blocked = await req('GET', `/api/lessons/${nonPreview.id}`, { token: studentToken });
  assert(blocked.status === 403 && blocked.body.reason === 'not_purchased', 'non-preview lesson gated for unenrolled student');

  console.log('12. Instructor cleans up (delete chapter cascades lessons, then delete course)');
  const dch = await req('DELETE', `/api/chapters/${chapterId}`, { token: instructorToken });
  assert(dch.status === 200, 'chapter deleted');
  const dc = await req('DELETE', `/api/courses/${newCourseId}`, { token: instructorToken });
  assert(dc.status === 200, 'course deleted');

  console.log('\nPASS — all 12 checks succeeded.');
})().catch((e) => { console.error('\n' + e.message); process.exit(1); });
