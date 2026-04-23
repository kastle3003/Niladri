const express = require('express');
const router = express.Router();
const db = require('../db');
const crypto = require('crypto');

// Initialize Razorpay (keys from env)
let razorpay;
try {
  const Razorpay = require('razorpay');
  razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_placeholder',
    key_secret: process.env.RAZORPAY_KEY_SECRET || 'placeholder_secret'
  });
} catch (e) {
  console.warn('Razorpay not installed, payment routes in mock mode');
}

// GET /api/payments/course/:course_id/price
router.get('/course/:course_id/price', (req, res) => {
  try {
    const course = db.prepare('SELECT id, title, price_paise, is_paid FROM courses WHERE id = ?').get(req.params.course_id);
    if (!course) return res.status(404).json({ error: 'Course not found' });
    res.json({
      course_id: course.id,
      title: course.title,
      price_paise: course.price_paise || 0,
      is_paid: course.is_paid || 0,
      currency: 'INR'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/payments/create-order
router.post('/create-order', async (req, res) => {
  try {
    const { course_id } = req.body;
    if (!course_id) return res.status(400).json({ error: 'course_id required' });

    const course = db.prepare('SELECT id, title, price_paise, is_paid FROM courses WHERE id = ?').get(course_id);
    if (!course) return res.status(404).json({ error: 'Course not found' });

    const amount = course.price_paise || 0;
    const currency = 'INR';
    let orderId;

    if (razorpay && process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_ID !== 'rzp_test_placeholder') {
      const order = await razorpay.orders.create({
        amount,
        currency,
        receipt: `course_${course_id}_user_${req.user.id}_${Date.now()}`,
        notes: { course_id, user_id: req.user.id }
      });
      orderId = order.id;
    } else {
      // Mock mode
      orderId = `order_mock_${Date.now()}`;
    }

    // Insert payment record
    db.prepare(`
      INSERT INTO payments (user_id, course_id, razorpay_order_id, amount_paise, currency, status)
      VALUES (?, ?, ?, ?, ?, 'created')
    `).run(req.user.id, course_id, orderId, amount, currency);

    res.json({
      order_id: orderId,
      amount,
      currency,
      key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_placeholder',
      course_title: course.title
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/payments/verify
router.post('/verify', (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, course_id } = req.body;
    if (!razorpay_order_id || !razorpay_payment_id || !course_id) {
      return res.status(400).json({ error: 'razorpay_order_id, razorpay_payment_id, and course_id are required' });
    }

    // Verify HMAC signature
    const secret = process.env.RAZORPAY_KEY_SECRET || 'placeholder_secret';
    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSignature = crypto.createHmac('sha256', secret).update(body).digest('hex');

    const isMock = razorpay_order_id.startsWith('order_mock_');
    const signatureValid = isMock || (razorpay_signature && expectedSignature === razorpay_signature);

    if (!signatureValid) {
      db.prepare(`UPDATE payments SET status='failed', updated_at=datetime('now') WHERE razorpay_order_id=?`).run(razorpay_order_id);
      return res.status(400).json({ error: 'Invalid payment signature' });
    }

    // Update payment record
    db.prepare(`
      UPDATE payments SET
        razorpay_payment_id = ?,
        razorpay_signature = ?,
        status = 'paid',
        updated_at = datetime('now')
      WHERE razorpay_order_id = ? AND user_id = ?
    `).run(razorpay_payment_id, razorpay_signature || 'mock', razorpay_order_id, req.user.id);

    // Create enrollment if not exists
    const existing = db.prepare('SELECT id FROM enrollments WHERE student_id = ? AND course_id = ?').get(req.user.id, parseInt(course_id));
    let enrollmentId;
    if (existing) {
      enrollmentId = existing.id;
    } else {
      const result = db.prepare(`
        INSERT INTO enrollments (student_id, course_id, enrolled_at, progress_pct)
        VALUES (?, ?, datetime('now'), 0)
      `).run(req.user.id, course_id);
      enrollmentId = result.lastInsertRowid;
    }

    res.json({ success: true, enrollment_id: enrollmentId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/payments/history
router.get('/history', (req, res) => {
  try {
    const payments = db.prepare(`
      SELECT p.*, c.title AS course_title, c.cover_color
      FROM payments p
      LEFT JOIN courses c ON p.course_id = c.id
      WHERE p.user_id = ?
      ORDER BY p.created_at DESC
    `).all(req.user.id);
    res.json({ payments });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/payments/admin  (instructor/admin)
router.get('/admin', (req, res) => {
  try {
    if (!['instructor', 'admin'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const payments = db.prepare(`
      SELECT p.*,
        u.first_name || ' ' || u.last_name AS student_name,
        u.email AS student_email,
        c.title AS course_title
      FROM payments p
      LEFT JOIN users u ON p.user_id = u.id
      LEFT JOIN courses c ON p.course_id = c.id
      ORDER BY p.created_at DESC
    `).all();

    const totalPaid = payments.filter(p => p.status === 'paid').reduce((sum, p) => sum + (p.amount_paise || 0), 0);
    const thisMonth = payments.filter(p => {
      const d = new Date(p.created_at);
      const now = new Date();
      return p.status === 'paid' && d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear();
    }).reduce((sum, p) => sum + (p.amount_paise || 0), 0);
    const pending = payments.filter(p => p.status === 'created').reduce((sum, p) => sum + (p.amount_paise || 0), 0);

    res.json({ payments, summary: { total_paise: totalPaid, this_month_paise: thisMonth, pending_paise: pending } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
