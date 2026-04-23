// Quick sanity check — writes a tiny test object, presigns it, reads it back, deletes it.
require('dotenv').config();
const storage = require('../server/lib/storage');
const https = require('https');

async function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    }).on('error', reject);
  });
}

(async () => {
  if (!storage.wasabiEnabled()) {
    console.error('FAIL: Wasabi not enabled. Check .env WASABI_* variables.');
    process.exit(1);
  }

  const buf = Buffer.from(`wasabi connectivity test ${new Date().toISOString()}`);
  const fakeMulterFile = {
    buffer: buf,
    originalname: 'test.txt',
    mimetype: 'text/plain',
    size: buf.length,
  };

  console.log('→ Uploading test object...');
  const urlPath = await storage.persistUpload(fakeMulterFile, '_healthcheck');
  console.log('   stored path:', urlPath);

  const key = urlPath.replace(/^\/api\/files\//, '');
  console.log('→ Presigning...');
  const signed = await storage.presignedUrl(key, 120);
  console.log('   presigned URL length:', signed.length, 'chars');

  console.log('→ Fetching via presigned URL...');
  const resp = await fetchUrl(signed);
  console.log('   HTTP', resp.status, '| body:', JSON.stringify(resp.body));

  console.log('→ Deleting test object...');
  await storage.deleteObject(urlPath);
  console.log('   deleted.');

  if (resp.status === 200 && resp.body === buf.toString()) {
    console.log('\nPASS — Wasabi integration is working.');
  } else {
    console.log('\nFAIL — round-trip did not match.');
    process.exit(1);
  }
})().catch((e) => {
  console.error('\nFAIL:', e.message);
  if (e.$metadata) console.error('   HTTP status:', e.$metadata.httpStatusCode);
  if (e.Code) console.error('   code:', e.Code);
  process.exit(1);
});
