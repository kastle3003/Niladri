const express = require('express');
const router = express.Router();
const db = require('../db');

// Default email templates to seed on startup
const DEFAULT_TEMPLATES = [
  {
    name: 'welcome',
    subject: 'Welcome to The Archive',
    html_body: `<!DOCTYPE html>
<html><body style="font-family:Georgia,serif;background:#F4EBD0;margin:0;padding:0;">
<div style="max-width:600px;margin:40px auto;background:#FAF7EE;border:1px solid #D1A14E;border-radius:8px;overflow:hidden;">
  <div style="background:#2D4F1E;padding:28px 32px;">
    <h1 style="font-family:Georgia,serif;font-style:italic;color:#F4EBD0;margin:0;font-size:26px;">The Archive Music School</h1>
    <p style="color:rgba(244,235,208,0.7);margin:4px 0 0;font-size:12px;letter-spacing:2px;text-transform:uppercase;">Welcome</p>
  </div>
  <div style="padding:32px;">
    <h2 style="font-family:Georgia,serif;font-style:italic;color:#8B2E26;font-size:22px;">Welcome, {{student_name}}.</h2>
    <p style="color:#4A3C28;line-height:1.7;margin:16px 0;">Your account has been created at The Archive Music School. We are delighted to have you join our community of dedicated musicians.</p>
    <p style="color:#4A3C28;line-height:1.7;margin:16px 0;">You can now browse our library of courses, access sheet music from the archive, and connect with world-class instructors.</p>
    <a href="{{login_url}}" style="display:inline-block;background:#8B2E26;color:#F4EBD0;text-decoration:none;padding:12px 28px;border-radius:6px;font-weight:600;margin:12px 0;">Begin Your Studies →</a>
    <p style="color:#7A6A52;font-size:12px;margin-top:28px;border-top:1px solid #D1A14E;padding-top:16px;">The Archive Music School · London / New York · Est. 1952</p>
  </div>
</div>
</body></html>`,
    variables: JSON.stringify(['student_name', 'login_url'])
  },
  {
    name: 'enrollment_confirmation',
    subject: 'Enrolled: {{course_name}}',
    html_body: `<!DOCTYPE html>
<html><body style="font-family:Georgia,serif;background:#F4EBD0;margin:0;padding:0;">
<div style="max-width:600px;margin:40px auto;background:#FAF7EE;border:1px solid #D1A14E;border-radius:8px;overflow:hidden;">
  <div style="background:#2D4F1E;padding:28px 32px;">
    <h1 style="font-family:Georgia,serif;font-style:italic;color:#F4EBD0;margin:0;font-size:26px;">The Archive Music School</h1>
    <p style="color:rgba(244,235,208,0.7);margin:4px 0 0;font-size:12px;letter-spacing:2px;text-transform:uppercase;">Enrollment Confirmed</p>
  </div>
  <div style="padding:32px;">
    <h2 style="font-family:Georgia,serif;font-style:italic;color:#8B2E26;font-size:22px;">You're enrolled, {{student_name}}.</h2>
    <p style="color:#4A3C28;line-height:1.7;margin:16px 0;">Your enrollment in <strong>{{course_name}}</strong> has been confirmed.</p>
    <div style="background:#F4EBD0;border-left:3px solid #D1A14E;padding:14px 18px;margin:18px 0;border-radius:0 6px 6px 0;">
      <p style="margin:0;color:#4A3C28;font-size:13px;"><strong>Course:</strong> {{course_name}}</p>
      <p style="margin:6px 0 0;color:#4A3C28;font-size:13px;"><strong>Instructor:</strong> {{instructor_name}}</p>
      <p style="margin:6px 0 0;color:#4A3C28;font-size:13px;"><strong>Enrolled on:</strong> {{enrollment_date}}</p>
    </div>
    <a href="{{course_url}}" style="display:inline-block;background:#8B2E26;color:#F4EBD0;text-decoration:none;padding:12px 28px;border-radius:6px;font-weight:600;margin:12px 0;">Go to Course →</a>
    <p style="color:#7A6A52;font-size:12px;margin-top:28px;border-top:1px solid #D1A14E;padding-top:16px;">The Archive Music School · London / New York · Est. 1952</p>
  </div>
</div>
</body></html>`,
    variables: JSON.stringify(['student_name', 'course_name', 'instructor_name', 'enrollment_date', 'course_url'])
  },
  {
    name: 'assignment_graded',
    subject: 'Your assignment has been graded',
    html_body: `<!DOCTYPE html>
<html><body style="font-family:Georgia,serif;background:#F4EBD0;margin:0;padding:0;">
<div style="max-width:600px;margin:40px auto;background:#FAF7EE;border:1px solid #D1A14E;border-radius:8px;overflow:hidden;">
  <div style="background:#2D4F1E;padding:28px 32px;">
    <h1 style="font-family:Georgia,serif;font-style:italic;color:#F4EBD0;margin:0;font-size:26px;">The Archive Music School</h1>
    <p style="color:rgba(244,235,208,0.7);margin:4px 0 0;font-size:12px;letter-spacing:2px;text-transform:uppercase;">Assignment Graded</p>
  </div>
  <div style="padding:32px;">
    <h2 style="font-family:Georgia,serif;font-style:italic;color:#8B2E26;font-size:22px;">Your work has been reviewed.</h2>
    <p style="color:#4A3C28;line-height:1.7;margin:16px 0;">Dear {{student_name}}, your submission for <strong>{{assignment_title}}</strong> has been graded.</p>
    <div style="background:#F4EBD0;border-left:3px solid #D1A14E;padding:14px 18px;margin:18px 0;border-radius:0 6px 6px 0;">
      <p style="margin:0;color:#4A3C28;font-size:13px;"><strong>Assignment:</strong> {{assignment_title}}</p>
      <p style="margin:6px 0 0;color:#4A3C28;font-size:13px;"><strong>Grade:</strong> {{grade}}</p>
      <p style="margin:6px 0 0;color:#4A3C28;font-size:13px;"><strong>Graded by:</strong> {{instructor_name}}</p>
    </div>
    <p style="color:#4A3C28;line-height:1.7;margin:16px 0;font-style:italic;"><strong>Feedback:</strong> {{feedback}}</p>
    <a href="{{submission_url}}" style="display:inline-block;background:#8B2E26;color:#F4EBD0;text-decoration:none;padding:12px 28px;border-radius:6px;font-weight:600;margin:12px 0;">View Full Feedback →</a>
    <p style="color:#7A6A52;font-size:12px;margin-top:28px;border-top:1px solid #D1A14E;padding-top:16px;">The Archive Music School · London / New York · Est. 1952</p>
  </div>
</div>
</body></html>`,
    variables: JSON.stringify(['student_name', 'assignment_title', 'grade', 'instructor_name', 'feedback', 'submission_url'])
  },
  {
    name: 'masterclass_reminder',
    subject: 'Masterclass Tomorrow: {{title}}',
    html_body: `<!DOCTYPE html>
<html><body style="font-family:Georgia,serif;background:#F4EBD0;margin:0;padding:0;">
<div style="max-width:600px;margin:40px auto;background:#FAF7EE;border:1px solid #D1A14E;border-radius:8px;overflow:hidden;">
  <div style="background:#2D4F1E;padding:28px 32px;">
    <h1 style="font-family:Georgia,serif;font-style:italic;color:#F4EBD0;margin:0;font-size:26px;">The Archive Music School</h1>
    <p style="color:rgba(244,235,208,0.7);margin:4px 0 0;font-size:12px;letter-spacing:2px;text-transform:uppercase;">Masterclass Reminder</p>
  </div>
  <div style="padding:32px;">
    <h2 style="font-family:Georgia,serif;font-style:italic;color:#8B2E26;font-size:22px;">Tomorrow: {{title}}</h2>
    <p style="color:#4A3C28;line-height:1.7;margin:16px 0;">This is a reminder that your masterclass is scheduled for tomorrow.</p>
    <div style="background:#F4EBD0;border-left:3px solid #D1A14E;padding:14px 18px;margin:18px 0;border-radius:0 6px 6px 0;">
      <p style="margin:0;color:#4A3C28;font-size:13px;"><strong>Masterclass:</strong> {{title}}</p>
      <p style="margin:6px 0 0;color:#4A3C28;font-size:13px;"><strong>Instructor:</strong> {{instructor_name}}</p>
      <p style="margin:6px 0 0;color:#4A3C28;font-size:13px;"><strong>Date &amp; Time:</strong> {{scheduled_at}}</p>
      <p style="margin:6px 0 0;color:#4A3C28;font-size:13px;"><strong>Duration:</strong> {{duration}} minutes</p>
    </div>
    <a href="{{meeting_url}}" style="display:inline-block;background:#8B2E26;color:#F4EBD0;text-decoration:none;padding:12px 28px;border-radius:6px;font-weight:600;margin:12px 0;">Join Meeting →</a>
    <p style="color:#7A6A52;font-size:12px;margin-top:28px;border-top:1px solid #D1A14E;padding-top:16px;">The Archive Music School · London / New York · Est. 1952</p>
  </div>
</div>
</body></html>`,
    variables: JSON.stringify(['title', 'instructor_name', 'scheduled_at', 'duration', 'meeting_url'])
  }
];

// Seed default templates
function seedTemplates() {
  try {
    const insert = db.prepare(`
      INSERT OR IGNORE INTO email_templates (name, subject, html_body, variables)
      VALUES (?, ?, ?, ?)
    `);
    const seedAll = db.transaction(() => {
      for (const t of DEFAULT_TEMPLATES) {
        insert.run(t.name, t.subject, t.html_body, t.variables);
      }
    });
    seedAll();
  } catch (e) {
    // Table may not exist yet at startup — will be created by db-sprint4.js
  }
}

// Try to seed on load
setImmediate(seedTemplates);

function mergeVariables(template, variables = {}) {
  let html = template;
  for (const [key, val] of Object.entries(variables)) {
    html = html.replace(new RegExp(`\\{\\{${key}\\}\\}`, 'g'), val || '');
  }
  return html;
}

// GET /api/email/templates
router.get('/templates', (req, res) => {
  try {
    if (!['instructor', 'admin'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Instructor access required' });
    }
    const templates = db.prepare('SELECT * FROM email_templates ORDER BY name').all();
    res.json({ templates });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/email/templates/:name
router.get('/templates/:name', (req, res) => {
  try {
    if (!['instructor', 'admin'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Instructor access required' });
    }
    const template = db.prepare('SELECT * FROM email_templates WHERE name = ?').get(req.params.name);
    if (!template) return res.status(404).json({ error: 'Template not found' });
    res.json({ template });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/email/templates/:name
router.put('/templates/:name', (req, res) => {
  try {
    if (!['instructor', 'admin'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Admin or instructor access required' });
    }

    const { subject, html_body, variables } = req.body;
    const existing = db.prepare('SELECT * FROM email_templates WHERE name = ?').get(req.params.name);

    if (existing) {
      db.prepare(`
        UPDATE email_templates SET
          subject = COALESCE(?, subject),
          html_body = COALESCE(?, html_body),
          variables = COALESCE(?, variables),
          updated_at = datetime('now')
        WHERE name = ?
      `).run(subject, html_body, variables ? JSON.stringify(variables) : null, req.params.name);
    } else {
      if (!subject || !html_body) return res.status(400).json({ error: 'subject and html_body required' });
      db.prepare(`
        INSERT INTO email_templates (name, subject, html_body, variables) VALUES (?, ?, ?, ?)
      `).run(req.params.name, subject, html_body, variables ? JSON.stringify(variables) : '[]');
    }

    const template = db.prepare('SELECT * FROM email_templates WHERE name = ?').get(req.params.name);
    res.json({ template, message: 'Template saved' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/email/send
router.post('/send', (req, res) => {
  try {
    if (!['instructor', 'admin'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Instructor access required' });
    }

    const { template_name, to_email, variables = {} } = req.body;
    if (!to_email) return res.status(400).json({ error: 'to_email is required' });

    let subject = 'Message from The Archive';
    let html_body = '<p>No content.</p>';

    if (template_name) {
      const template = db.prepare('SELECT * FROM email_templates WHERE name = ?').get(template_name);
      if (template) {
        subject = mergeVariables(template.subject, variables);
        html_body = mergeVariables(template.html_body, variables);
      }
    }

    // Simulate sending — log to email_logs
    db.prepare(`
      INSERT INTO email_logs (to_email, subject, template_name, status)
      VALUES (?, ?, ?, 'sent')
    `).run(to_email, subject, template_name || null);

    res.json({ message: `Email sent (simulated) to ${to_email}`, subject });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/email/logs
router.get('/logs', (req, res) => {
  try {
    if (!['instructor', 'admin'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Instructor access required' });
    }
    const logs = db.prepare('SELECT * FROM email_logs ORDER BY sent_at DESC LIMIT 200').all();
    res.json({ logs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
