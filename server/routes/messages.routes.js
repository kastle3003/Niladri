const express = require('express');
const router = express.Router();
const multer = require('multer');
const db = require('../db');
const { persistUpload } = require('../lib/storage');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// GET /api/messages — alias for /threads so the bare URL returns JSON instead of falling to the SPA.
router.get('/', (req, res) => {
  req.url = '/threads';
  router.handle(req, res);
});

// GET /api/messages/unread-count
router.get('/unread-count', (req, res) => {
  try {
    const msgs = db.prepare(`
      SELECT m.read_by FROM messages m
      JOIN thread_participants tp ON tp.thread_id = m.thread_id
      WHERE tp.user_id = ? AND m.sender_id != ?
    `).all(req.user.id, req.user.id);
    const count = msgs.filter(m => {
      const readBy = JSON.parse(m.read_by || '[]');
      return !readBy.includes(req.user.id);
    }).length;
    res.json({ count });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/messages/threads
router.get('/threads', (req, res) => {
  try {
    const threads = db.prepare(`
      SELECT mt.*,
        (SELECT m.body FROM messages m WHERE m.thread_id = mt.id ORDER BY m.created_at DESC LIMIT 1) AS last_message,
        (SELECT m.created_at FROM messages m WHERE m.thread_id = mt.id ORDER BY m.created_at DESC LIMIT 1) AS last_message_at,
        (SELECT m.sender_id FROM messages m WHERE m.thread_id = mt.id ORDER BY m.created_at DESC LIMIT 1) AS last_sender_id
      FROM message_threads mt
      JOIN thread_participants tp ON tp.thread_id = mt.id
      WHERE tp.user_id = ?
      ORDER BY last_message_at DESC
    `).all(req.user.id);

    // For each thread, compute unread count and participant info
    const result = threads.map(thread => {
      const participants = db.prepare(`
        SELECT u.id, u.first_name, u.last_name, u.avatar_initials, u.role
        FROM thread_participants tp
        JOIN users u ON u.id = tp.user_id
        WHERE tp.thread_id = ?
      `).all(thread.id);

      const unreadMsgs = db.prepare(
        'SELECT read_by FROM messages WHERE thread_id = ? AND sender_id != ?'
      ).all(thread.id, req.user.id);
      const unread_count = unreadMsgs.filter(m => {
        const rb = JSON.parse(m.read_by || '[]');
        return !rb.includes(req.user.id);
      }).length;

      return { ...thread, participants, unread_count };
    });

    res.json({ threads: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/messages/threads/:id
router.get('/threads/:id', (req, res) => {
  try {
    // Verify participant
    const participation = db.prepare(
      'SELECT * FROM thread_participants WHERE thread_id = ? AND user_id = ?'
    ).get(req.params.id, req.user.id);
    if (!participation) return res.status(403).json({ error: 'Not a participant in this thread' });

    const thread = db.prepare('SELECT * FROM message_threads WHERE id = ?').get(req.params.id);
    if (!thread) return res.status(404).json({ error: 'Thread not found' });

    const messages = db.prepare(`
      SELECT m.*, u.first_name, u.last_name, u.avatar_initials
      FROM messages m
      JOIN users u ON u.id = m.sender_id
      WHERE m.thread_id = ?
      ORDER BY m.created_at ASC
    `).all(req.params.id);

    const participants = db.prepare(`
      SELECT u.id, u.first_name, u.last_name, u.avatar_initials, u.role
      FROM thread_participants tp
      JOIN users u ON u.id = tp.user_id
      WHERE tp.thread_id = ?
    `).all(req.params.id);

    res.json({ thread, messages, participants });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/messages/threads
router.post('/threads', (req, res) => {
  try {
    const { subject, participant_ids, course_id, first_message } = req.body;
    if (!subject || !first_message) return res.status(400).json({ error: 'subject and first_message are required' });
    if (!Array.isArray(participant_ids) || participant_ids.length === 0) {
      return res.status(400).json({ error: 'participant_ids must be a non-empty array' });
    }

    const threadResult = db.prepare(
      'INSERT INTO message_threads (created_by, subject, course_id) VALUES (?, ?, ?)'
    ).run(req.user.id, subject, course_id || null);
    const threadId = threadResult.lastInsertRowid;

    // Add creator + all participants
    const allParticipants = [...new Set([req.user.id, ...participant_ids.map(Number)])];
    const insertParticipant = db.prepare(
      'INSERT OR IGNORE INTO thread_participants (thread_id, user_id) VALUES (?, ?)'
    );
    for (const uid of allParticipants) {
      insertParticipant.run(threadId, uid);
    }

    // Insert first message
    const msgResult = db.prepare(
      'INSERT INTO messages (thread_id, sender_id, body, read_by) VALUES (?, ?, ?, ?)'
    ).run(threadId, req.user.id, first_message, JSON.stringify([req.user.id]));

    const thread = db.prepare('SELECT * FROM message_threads WHERE id = ?').get(threadId);
    const message = db.prepare('SELECT * FROM messages WHERE id = ?').get(msgResult.lastInsertRowid);
    res.status(201).json({ thread, message });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/messages/threads/:id/reply
router.post('/threads/:id/reply', upload.single('attachment'), async (req, res) => {
  try {
    const participation = db.prepare(
      'SELECT * FROM thread_participants WHERE thread_id = ? AND user_id = ?'
    ).get(req.params.id, req.user.id);
    if (!participation) return res.status(403).json({ error: 'Not a participant in this thread' });

    const { body } = req.body;
    if (!body) return res.status(400).json({ error: 'body is required' });
    const attachment_path = req.file
      ? await persistUpload(req.file, 'messages')
      : (req.body.attachment_path || null);

    const result = db.prepare(
      'INSERT INTO messages (thread_id, sender_id, body, attachment_path, read_by) VALUES (?, ?, ?, ?, ?)'
    ).run(req.params.id, req.user.id, body, attachment_path, JSON.stringify([req.user.id]));

    const message = db.prepare(`
      SELECT m.*, u.first_name, u.last_name, u.avatar_initials
      FROM messages m JOIN users u ON u.id = m.sender_id
      WHERE m.id = ?
    `).get(result.lastInsertRowid);

    res.status(201).json({ message });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/messages/threads/:id/read
router.post('/threads/:id/read', (req, res) => {
  try {
    const participation = db.prepare(
      'SELECT * FROM thread_participants WHERE thread_id = ? AND user_id = ?'
    ).get(req.params.id, req.user.id);
    if (!participation) return res.status(403).json({ error: 'Not a participant in this thread' });

    const messages = db.prepare('SELECT id, read_by FROM messages WHERE thread_id = ?').all(req.params.id);
    const updateMsg = db.prepare('UPDATE messages SET read_by = ? WHERE id = ?');
    for (const msg of messages) {
      const readBy = JSON.parse(msg.read_by || '[]');
      if (!readBy.includes(req.user.id)) {
        readBy.push(req.user.id);
        updateMsg.run(JSON.stringify(readBy), msg.id);
      }
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
