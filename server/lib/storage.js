/**
 * Unified storage layer.
 * If WASABI_ENABLED=true (and creds present) -> uploads go to Wasabi, DB stores "/api/files/<key>".
 * Otherwise -> uploads fall back to local disk, DB stores "/uploads/<filename>" (legacy scheme).
 *
 * Both URL shapes are valid <img>/<video>/<a href> sources, so frontend code does not need to change.
 */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const USE_WASABI = String(process.env.WASABI_ENABLED || '').toLowerCase() === 'true';
const LOCAL_UPLOAD_DIR = process.env.UPLOAD_DIR || './data/uploads';

let s3 = null;
let PutObjectCommand = null;
let GetObjectCommand = null;
let DeleteObjectCommand = null;
let getSignedUrl = null;
let BUCKET = null;

function initWasabi() {
  if (!USE_WASABI) return;
  const bucket = process.env.WASABI_BUCKET;
  const accessKeyId = process.env.WASABI_ACCESS_KEY;
  const secretAccessKey = process.env.WASABI_SECRET_KEY;
  if (!bucket || !accessKeyId || !secretAccessKey) {
    console.warn('[storage] WASABI_ENABLED=true but WASABI_BUCKET / WASABI_ACCESS_KEY / WASABI_SECRET_KEY missing — falling back to local disk.');
    return;
  }
  try {
    const s3mod = require('@aws-sdk/client-s3');
    const signer = require('@aws-sdk/s3-request-presigner');
    PutObjectCommand = s3mod.PutObjectCommand;
    GetObjectCommand = s3mod.GetObjectCommand;
    DeleteObjectCommand = s3mod.DeleteObjectCommand;
    getSignedUrl = signer.getSignedUrl;
    const region = process.env.WASABI_REGION || 'us-east-1';
    const endpoint = process.env.WASABI_ENDPOINT || `https://s3.${region}.wasabisys.com`;
    s3 = new s3mod.S3Client({
      region,
      endpoint,
      credentials: { accessKeyId, secretAccessKey },
      forcePathStyle: false
    });
    BUCKET = bucket;
    console.log(`[storage] Wasabi enabled: bucket=${BUCKET} region=${region} endpoint=${endpoint}`);
  } catch (e) {
    console.warn('[storage] @aws-sdk packages missing, run `npm install`. Falling back to local:', e.message);
    s3 = null;
  }
}
initWasabi();

function randomKey(originalName, prefix) {
  const ext = path.extname(originalName || '').toLowerCase() || '';
  const hash = crypto.randomBytes(8).toString('hex');
  const safePrefix = prefix ? prefix.replace(/^\/+|\/+$/g, '') + '/' : '';
  return `${safePrefix}${Date.now()}-${hash}${ext}`;
}

/**
 * Persist an uploaded file and return the URL to store in DB.
 * file: the object produced by multer.memoryStorage() (has .buffer, .originalname, .mimetype, .size)
 * prefix: optional logical folder, e.g. "recordings", "avatars"
 */
async function persistUpload(file, prefix = '') {
  if (!file) return null;
  const key = randomKey(file.originalname, prefix);

  if (s3) {
    await s3.send(new PutObjectCommand({
      Bucket: BUCKET,
      Key: key,
      Body: file.buffer,
      ContentType: file.mimetype || 'application/octet-stream',
      ContentLength: file.size
    }));
    return `/api/files/${key}`;
  }

  // local fallback — flatten into a single uploads dir, matching pre-Wasabi layout
  if (!fs.existsSync(LOCAL_UPLOAD_DIR)) fs.mkdirSync(LOCAL_UPLOAD_DIR, { recursive: true });
  const diskName = path.basename(key);
  fs.writeFileSync(path.join(LOCAL_UPLOAD_DIR, diskName), file.buffer);
  return `/uploads/${diskName}`;
}

/**
 * Return a presigned GET URL for a Wasabi key. Throws if Wasabi not configured.
 */
async function presignedUrl(key, expiresSeconds = 900) {
  if (!s3) throw new Error('Wasabi not configured');
  return getSignedUrl(s3, new GetObjectCommand({ Bucket: BUCKET, Key: key }), { expiresIn: expiresSeconds });
}

/**
 * Delete an object (best-effort). Accepts either a bare key or a "/api/files/..." URL.
 */
async function deleteObject(keyOrUrl) {
  if (!s3 || !keyOrUrl) return;
  const key = String(keyOrUrl).replace(/^\/api\/files\//, '');
  try {
    await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));
  } catch (e) {
    console.warn('[storage] deleteObject failed:', e.message);
  }
}

function wasabiEnabled() { return !!s3; }

module.exports = { persistUpload, presignedUrl, deleteObject, wasabiEnabled };
