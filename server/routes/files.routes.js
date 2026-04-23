const express = require('express');
const router = express.Router();
const storage = require('../lib/storage');

// GET /api/files/<any/key/with/slashes>
// Returns a 302 redirect to a short-lived Wasabi presigned URL so the browser
// can stream video/audio or download files directly from object storage.
router.get(/^\/(.+)$/, async (req, res) => {
  try {
    if (!storage.wasabiEnabled()) {
      return res.status(503).json({ error: 'Object storage not configured' });
    }
    const key = req.params[0];
    if (!key) return res.status(400).json({ error: 'Missing key' });
    const url = await storage.presignedUrl(key, 900);
    res.redirect(302, url);
  } catch (err) {
    console.error('[files] presign error:', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
