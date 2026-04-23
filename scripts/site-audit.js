// One-off site-wide audit. Walks every HTML in /public, HEAD-ish checks every
// internal href/src it references, times each fetch, flags 404s and slow pages.
//
// Run:  node scripts/site-audit.js [BASE_URL]

const fs = require('fs');
const path = require('path');
const http = require('http');

const BASE = (process.argv[2] || 'http://localhost:3001').replace(/\/$/, '');
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const SLOW_STATIC_MS = 500;
const SLOW_API_MS    = 1000;

// Routes that are valid but not served from /public (SEO routes declared in server/index.js)
const ALIAS_ROUTES = [
  { pattern: /^\/$/,                       note: 'home' },
  { pattern: /^\/login$/,                  note: '→ index.html' },
  { pattern: /^\/register$/,               note: '→ index.html' },
  { pattern: /^\/courses\/[^\/]+$/,        note: '→ course-landing.html (slug route)' },
];

// Parse anchor-style hrefs / script srcs / css hrefs. Good-enough regex for flat HTML.
function extractInternalLinks(html, baseHref) {
  const out = new Set();
  const rxHref = /(?:href|src)=['"]([^'"#?]+)(?:\?[^'"]*)?(?:#[^'"]*)?['"]/gi;
  let m;
  while ((m = rxHref.exec(html)) !== null) {
    const url = m[1].trim();
    if (!url) continue;
    if (/^(https?:|mailto:|tel:|data:)/i.test(url)) continue;   // external or inline
    if (url.startsWith('#')) continue;                          // pure anchor
    // Resolve relative to the page path
    let abs = url;
    if (!abs.startsWith('/')) {
      const base = baseHref.replace(/\/[^\/]*$/, '/');
      abs = base + abs;
    }
    out.add(abs);
  }
  // Also pick up api.* calls made from inline scripts: api.get('/api/xyz'), api.post('/api/xyz')
  const rxApi = /\bapi\.(?:get|post|put|del|delete|upload)\(\s*['"`]([^'"`]+)['"`]/g;
  while ((m = rxApi.exec(html)) !== null) {
    if (m[1].startsWith('/api/')) out.add(m[1].replace(/\?.*$/, ''));
  }
  // And bare fetch('/api/…') or fetch(`/api/…`) calls
  const rxFetch = /\bfetch\(\s*[`'"]([^`'"]+)[`'"]/g;
  while ((m = rxFetch.exec(html)) !== null) {
    // Skip template literals that contain ${…} — those resolve at runtime with
    // real ids, so probing them with a synthetic "1" would be a false positive.
    if (m[1].startsWith('/api/') && !m[1].includes('${')) {
      out.add(m[1].replace(/\?.*$/, ''));
    }
  }
  return Array.from(out);
}

function request(pathPart) {
  return new Promise(resolve => {
    const start = Date.now();
    const req = http.request(BASE + pathPart, { method: 'GET', timeout: 10000 }, res => {
      let bytes = 0;
      res.on('data', chunk => { bytes += chunk.length; });
      res.on('end', () => resolve({ status: res.statusCode, ms: Date.now() - start, bytes }));
    });
    req.on('error', err => resolve({ status: 0, ms: Date.now() - start, error: err.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, ms: Date.now() - start, error: 'timeout' }); });
    req.end();
  });
}

function isApi(url) { return url.startsWith('/api/'); }

(async () => {
  // 1. Enumerate every HTML file in /public
  const htmlFiles = fs.readdirSync(PUBLIC_DIR).filter(f => f.endsWith('.html')).sort();
  console.log(`Auditing ${htmlFiles.length} HTML pages + alias routes against ${BASE}`);
  console.log('='.repeat(78));

  const pageTimings = [];
  const seenLinks = new Set();

  for (const f of htmlFiles) {
    const href = '/' + f;
    const r = await request(href);
    pageTimings.push({ url: href, ...r });

    let linksFound = 0;
    if (r.status === 200) {
      const html = fs.readFileSync(path.join(PUBLIC_DIR, f), 'utf8');
      const links = extractInternalLinks(html, href);
      links.forEach(l => seenLinks.add(l));
      linksFound = links.length;
    }
    const flag = r.status === 200 ? '✓' : '✗';
    const slow = r.ms > SLOW_STATIC_MS ? ' (SLOW)' : '';
    console.log(` ${flag} ${String(r.status).padEnd(3)} ${String(r.ms).padStart(5)}ms  ${href.padEnd(42)} links=${linksFound}${slow}`);
  }

  // 2. Check the alias/SEO routes
  console.log('\nAlias / SEO routes:');
  for (const a of ALIAS_ROUTES) {
    // Use a concrete sample for dynamic ones
    const sample = a.pattern.source === '^\\/$' ? '/' :
                   a.pattern.source === '^\\/login$' ? '/login' :
                   a.pattern.source === '^\\/register$' ? '/register' :
                   '/courses/sitar-the-complete-foundation';
    const r = await request(sample);
    pageTimings.push({ url: sample, ...r });
    const flag = r.status === 200 ? '✓' : '✗';
    console.log(` ${flag} ${String(r.status).padEnd(3)} ${String(r.ms).padStart(5)}ms  ${sample.padEnd(42)} — ${a.note}`);
  }

  // 3. Probe every unique internal link from the HTML pages
  console.log(`\nProbing ${seenLinks.size} unique internal links referenced by pages:`);
  const linkResults = [];
  for (const l of Array.from(seenLinks).sort()) {
    const r = await request(l);
    linkResults.push({ url: l, ...r });
  }

  // Classify
  const brokenPages = pageTimings.filter(r => r.status !== 200);
  const slowPages   = pageTimings.filter(r => r.status === 200 && r.ms > SLOW_STATIC_MS);

  // For links we expect /api/* to often return 401 (auth required) — that's OK, not a bug.
  const broken = linkResults.filter(r => r.status !== 200 && !(isApi(r.url) && r.status === 401));
  const slowLinks = linkResults.filter(r => r.status === 200 && ((isApi(r.url) ? r.ms > SLOW_API_MS : r.ms > SLOW_STATIC_MS)));

  console.log('\n' + '='.repeat(78));
  console.log(`Summary`);
  console.log(`  pages tested:     ${pageTimings.length}`);
  console.log(`  links tested:     ${linkResults.length}`);
  console.log(`  broken pages:     ${brokenPages.length}`);
  console.log(`  slow pages:       ${slowPages.length}`);
  console.log(`  broken links:     ${broken.length}`);
  console.log(`  slow links:       ${slowLinks.length}`);

  if (brokenPages.length) {
    console.log('\nBROKEN PAGES:');
    brokenPages.forEach(r => console.log(`  ${r.status}  ${r.url}${r.error ? '  ['+r.error+']' : ''}`));
  }
  if (broken.length) {
    console.log('\nBROKEN LINKS:');
    broken.forEach(r => console.log(`  ${r.status}  ${r.url}${r.error ? '  ['+r.error+']' : ''}`));
  }
  if (slowPages.length) {
    console.log('\nSLOW PAGES (>' + SLOW_STATIC_MS + 'ms):');
    slowPages.forEach(r => console.log(`  ${r.ms}ms  ${r.url}`));
  }
  if (slowLinks.length) {
    console.log('\nSLOW LINKS:');
    slowLinks.forEach(r => console.log(`  ${r.ms}ms  ${r.url}`));
  }
  process.exit((brokenPages.length + broken.length) ? 1 : 0);
})();
