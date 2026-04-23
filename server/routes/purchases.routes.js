const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const db = require('../db');
const access = require('../lib/access');
const { emitEmail } = require('./progress.routes');

// Razorpay client (optional — falls back to mock orders when keys missing)
let razorpay = null;
if (process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET) {
  try {
    const Razorpay = require('razorpay');
    razorpay = new Razorpay({
      key_id: process.env.RAZORPAY_KEY_ID,
      key_secret: process.env.RAZORPAY_KEY_SECRET,
    });
  } catch (e) { /* razorpay dep missing, stay in mock mode */ }
}

function resolvePrice({ type, course, foundation }) {
  if (type === 'bundle') {
    return Number(course.bundle_price_paise) || Number(course.price_paise) || 0;
  }
  return Number(foundation.price_individual_paise) || 0;
}

// ── POST /api/purchases ────────────────────────────────────────────────────
// Body: { type: 'bundle'|'individual', course_id?, foundation_id? }
// For 'individual' purchases, enforces A→E sequence + previous-completed rule.
// Returns a Razorpay order (or a mock order when keys aren't set), plus a
// pending purchase row in the DB that the /verify step will flip to 'completed'.
router.post('/', async (req, res) => {
  try {
    const { type, course_id, foundation_id } = req.body || {};
    if (!type || !['bundle', 'individual'].includes(type)) {
      return res.status(400).json({ error: "type must be 'bundle' or 'individual'" });
    }

    let course = null;
    let foundation = null;

    if (type === 'bundle') {
      if (!course_id) return res.status(400).json({ error: 'course_id is required for a bundle purchase' });
      course = access.getCourse(course_id);
      if (!course) return res.status(404).json({ error: 'Course not found' });
      if (access.ownsBundle(req.user.id, course_id)) {
        return res.status(409).json({ error: 'You already own this bundle' });
      }
    } else {
      if (!foundation_id) return res.status(400).json({ error: 'foundation_id is required for an individual purchase' });
      foundation = access.getFoundation(foundation_id);
      if (!foundation) return res.status(404).json({ error: 'Foundation not found' });
      course = access.getCourse(foundation.course_id);

      const elig = access.canPurchaseFoundation(req.user.id, foundation_id);
      if (!elig.allowed) {
        return res.status(403).json({
          error: 'Foundation cannot be purchased yet',
          reason: elig.reason,
          blocked_by: elig.blocked_by,
        });
      }
    }

    const amount = resolvePrice({ type, course, foundation });
    if (amount < 0) return res.status(400).json({ error: 'Invalid price' });

    // Create a Razorpay order (or a mock one)
    let order;
    if (razorpay && amount > 0) {
      order = await razorpay.orders.create({
        amount,
        currency: 'INR',
        receipt: `purchase_${Date.now()}_${req.user.id}`,
        notes: { user_id: String(req.user.id), type, course_id: course?.id, foundation_id: foundation?.id },
      });
    } else {
      order = {
        id: `order_mock_${Date.now()}`,
        amount,
        currency: 'INR',
        status: 'created',
      };
    }

    const ins = db.prepare(`
      INSERT INTO purchases (user_id, course_id, foundation_id, type, status, amount_paise, currency, razorpay_order_id)
      VALUES (?, ?, ?, ?, 'pending', ?, 'INR', ?)
    `).run(
      req.user.id,
      course ? course.id : null,
      foundation ? foundation.id : null,
      type,
      amount,
      order.id
    );

    // A zero-price purchase is auto-completed (free bundle / free foundation).
    if (amount === 0) {
      finalizePurchase(ins.lastInsertRowid);
    }

    res.status(201).json({
      purchase_id: ins.lastInsertRowid,
      order_id: order.id,
      amount_paise: amount,
      currency: 'INR',
      key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_placeholder',
      auto_completed: amount === 0,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/purchases/verify
// Body: { razorpay_order_id, razorpay_payment_id, razorpay_signature }
router.post('/verify', (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body || {};
    if (!razorpay_order_id) return res.status(400).json({ error: 'razorpay_order_id is required' });

    const purchase = db.prepare('SELECT * FROM purchases WHERE razorpay_order_id = ? AND user_id = ?').get(razorpay_order_id, req.user.id);
    if (!purchase) return res.status(404).json({ error: 'Purchase not found' });
    if (purchase.status === 'completed') return res.json({ message: 'Already completed', purchase_id: purchase.id });

    // Real verification (only when secret is configured)
    if (process.env.RAZORPAY_KEY_SECRET && razorpay_payment_id && razorpay_signature) {
      const expected = crypto
        .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(`${razorpay_order_id}|${razorpay_payment_id}`)
        .digest('hex');
      if (expected !== razorpay_signature) {
        db.prepare('UPDATE purchases SET status = ? , updated_at = datetime(\'now\') WHERE id = ?').run('failed', purchase.id);
        return res.status(400).json({ error: 'Invalid signature' });
      }
    }

    db.prepare(`
      UPDATE purchases
         SET status = 'completed', razorpay_payment_id = ?, updated_at = datetime('now')
       WHERE id = ?
    `).run(razorpay_payment_id || null, purchase.id);

    finalizePurchase(purchase.id);

    res.json({ message: 'Payment verified', purchase_id: purchase.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/purchases/webhook
// Simplified Razorpay-style webhook. Verifies HMAC if RAZORPAY_WEBHOOK_SECRET is set.
router.post('/webhook', express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }), (req, res) => {
  try {
    if (process.env.RAZORPAY_WEBHOOK_SECRET) {
      const sig = req.headers['x-razorpay-signature'];
      const expected = crypto
        .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET)
        .update(req.rawBody || JSON.stringify(req.body || {}))
        .digest('hex');
      if (sig !== expected) return res.status(400).json({ error: 'Invalid webhook signature' });
    }

    const ev = req.body || {};
    const orderId = ev?.payload?.payment?.entity?.order_id || ev?.order_id;
    if (!orderId) return res.json({ ignored: true });

    const purchase = db.prepare('SELECT * FROM purchases WHERE razorpay_order_id = ?').get(orderId);
    if (!purchase) return res.json({ ignored: true });

    if (ev.event === 'payment.captured' && purchase.status !== 'completed') {
      db.prepare('UPDATE purchases SET status = ?, razorpay_payment_id = ?, updated_at = datetime(\'now\') WHERE id = ?')
        .run('completed', ev?.payload?.payment?.entity?.id || null, purchase.id);
      finalizePurchase(purchase.id);
    } else if (ev.event === 'payment.failed') {
      db.prepare('UPDATE purchases SET status = ?, updated_at = datetime(\'now\') WHERE id = ?').run('failed', purchase.id);
    }

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/purchases/me — purchases owned by the current user
router.get('/me', (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT p.*,
             c.title AS course_title,
             ch.title AS foundation_title
      FROM purchases p
      LEFT JOIN courses  c  ON p.course_id = c.id
      LEFT JOIN chapters ch ON p.foundation_id = ch.id
      WHERE p.user_id = ?
      ORDER BY p.created_at DESC
    `).all(req.user.id);
    res.json({ purchases: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/purchases/eligibility?foundation_id=X
// Handy for the checkout UI — shows *why* a purchase is blocked without attempting it.
router.get('/eligibility', (req, res) => {
  try {
    const { foundation_id } = req.query;
    if (!foundation_id) return res.status(400).json({ error: 'foundation_id is required' });
    res.json(access.canPurchaseFoundation(req.user.id, parseInt(foundation_id)));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Post-payment side effects ──────────────────────────────────────────────
// On successful bundle/individual payment:
//   1. Auto-enroll the user in the parent course (so existing enrollment-based
//      features like dashboards, analytics and certificates continue to work).
//   2. Email: "Payment received" + ("Course unlocked" OR "Foundation unlocked").
function finalizePurchase(purchaseId) {
  const p = db.prepare('SELECT * FROM purchases WHERE id = ?').get(purchaseId);
  if (!p || p.status !== 'completed') return;

  // Resolve the course id either directly or via the foundation.
  let courseId = p.course_id;
  if (!courseId && p.foundation_id) {
    const f = access.getFoundation(p.foundation_id);
    if (f) courseId = f.course_id;
  }
  if (courseId) {
    db.prepare(`INSERT OR IGNORE INTO enrollments (student_id, course_id, last_accessed_at) VALUES (?, ?, datetime('now'))`)
      .run(p.user_id, courseId);
  }

  emitEmail(p.user_id, 'payment_success', { purchase_id: p.id, amount_paise: p.amount_paise });
  if (p.type === 'bundle') {
    emitEmail(p.user_id, 'course_unlocked', { course_id: courseId });
  } else if (p.type === 'individual') {
    emitEmail(p.user_id, 'foundation_unlocked', { foundation_id: p.foundation_id });
  }
}

module.exports = router;
module.exports.finalizePurchase = finalizePurchase;
