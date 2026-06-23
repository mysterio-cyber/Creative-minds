// ─────────────────────────────────────────────────────────────────
// Creative Minds — Backend Server
// Stack : Node.js + Express + SQLite (via better-sqlite3)
// Run   : npm install && node server.js
// ─────────────────────────────────────────────────────────────────
const express  = require('express');
const cors     = require('cors');
const Database = require('better-sqlite3');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const path     = require('path');
const fs       = require('fs');

const app  = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET  = process.env.JWT_SECRET  || 'cm_super_secret_2025';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL  || 'admin@creativeminds.in';
const ADMIN_PASS  = process.env.ADMIN_PASS   || 'Admin@CM2025';

// ── Middleware ──────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// ── Database setup ──────────────────────────────────────────────
const db = new Database('./creativeminds.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT    NOT NULL,
    email     TEXT,
    phone     TEXT,
    company   TEXT,
    created_at TEXT   DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS contacts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL,
    email     TEXT,
    phone     TEXT,
    company   TEXT,
    service   TEXT,
    message   TEXT NOT NULL,
    status    TEXT DEFAULT 'new',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS reviews (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL,
    role      TEXT,
    text      TEXT NOT NULL,
    rating    INTEGER NOT NULL,
    approved  INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS activity_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    type      TEXT NOT NULL,
    detail    TEXT,
    ip        TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS otps (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    contact   TEXT NOT NULL,
    otp       TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used      INTEGER DEFAULT 0
  );
`);

// ── Helpers ─────────────────────────────────────────────────────
function log(type, detail, ip) {
  db.prepare("INSERT INTO activity_log (type,detail,ip) VALUES (?,?,?)").run(type, detail, ip || '');
}

function authMiddleware(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ─────────────────────────────────────────────────────────────────
// PUBLIC ROUTES
// ─────────────────────────────────────────────────────────────────

// Send OTP
app.post('/api/send-otp', (req, res) => {
  const { contact } = req.body;
  if (!contact) return res.status(400).json({ error: 'Contact required' });

  const otp     = String(Math.floor(1000 + Math.random() * 9000));
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 min

  db.prepare("DELETE FROM otps WHERE contact=?").run(contact);
  db.prepare("INSERT INTO otps (contact,otp,expires_at) VALUES (?,?,?)").run(contact, otp, expires);
  log('OTP_SENT', `OTP sent to ${contact}`, req.ip);

  // In production: integrate Twilio / MSG91 / SendGrid here
  console.log(`[OTP] ${contact} → ${otp}`);
  res.json({ success: true, demo_otp: otp }); // Remove demo_otp in production
});

// Verify OTP + login/register
app.post('/api/verify-otp', (req, res) => {
  const { contact, otp, name, company } = req.body;
  if (!contact || !otp) return res.status(400).json({ error: 'Contact and OTP required' });

  const row = db.prepare("SELECT * FROM otps WHERE contact=? AND used=0 ORDER BY id DESC LIMIT 1").get(contact);
  if (!row)                             return res.status(400).json({ error: 'OTP not found. Please request a new one.' });
  if (new Date(row.expires_at) < new Date()) return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
  if (row.otp !== otp)                  return res.status(400).json({ error: 'Incorrect OTP.' });

  db.prepare("UPDATE otps SET used=1 WHERE id=?").run(row.id);

  let user = db.prepare("SELECT * FROM users WHERE email=? OR phone=?").get(contact, contact);
  if (!user) {
    const info = db.prepare("INSERT INTO users (name,email,phone,company) VALUES (?,?,?,?)").run(
      name || 'User',
      contact.includes('@') ? contact : null,
      contact.includes('@') ? null    : contact,
      company || null
    );
    user = db.prepare("SELECT * FROM users WHERE id=?").get(info.lastInsertRowid);
    log('USER_REGISTERED', `New user: ${user.name} (${contact})`, req.ip);
  } else {
    log('USER_LOGIN', `Login: ${user.name} (${contact})`, req.ip);
  }

  const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, user: { id: user.id, name: user.name, company: user.company } });
});

// Submit contact form
app.post('/api/contact', (req, res) => {
  const { name, email, phone, company, service, message } = req.body;
  if (!name || !message) return res.status(400).json({ error: 'Name and message are required' });

  db.prepare("INSERT INTO contacts (name,email,phone,company,service,message) VALUES (?,?,?,?,?,?)")
    .run(name, email || '', phone || '', company || '', service || '', message);
  log('CONTACT_FORM', `New enquiry from ${name} — ${service || 'General'}`, req.ip);
  res.json({ success: true, message: 'Message received! We will get back to you within 24 hours.' });
});

// Submit review
app.post('/api/reviews', (req, res) => {
  const { name, role, text, rating } = req.body;
  if (!name || !text || !rating) return res.status(400).json({ error: 'Name, review, and rating are required' });
  if (rating < 1 || rating > 5)  return res.status(400).json({ error: 'Rating must be between 1 and 5' });

  db.prepare("INSERT INTO reviews (name,role,text,rating) VALUES (?,?,?,?)").run(name, role || '', text, rating);
  log('REVIEW_SUBMITTED', `Review by ${name} — ${rating} stars`, req.ip);
  res.json({ success: true, message: 'Review published!' });
});

// Get approved reviews
app.get('/api/reviews', (req, res) => {
  const reviews = db.prepare("SELECT * FROM reviews WHERE approved=1 ORDER BY id DESC").all();
  res.json(reviews);
});

// Get site stats (public)
app.get('/api/stats', (req, res) => {
  const totalReviews = db.prepare("SELECT COUNT(*) as c FROM reviews WHERE approved=1").get().c;
  const avgRating    = db.prepare("SELECT AVG(rating) as a FROM reviews WHERE approved=1").get().a;
  const totalUsers   = db.prepare("SELECT COUNT(*) as c FROM users").get().c;
  res.json({
    projects : 200 + totalReviews,
    clients  : 50  + Math.floor(totalUsers / 2),
    reviews  : totalReviews,
    rating   : avgRating ? parseFloat(avgRating).toFixed(1) : null
  });
});

// ─────────────────────────────────────────────────────────────────
// ADMIN ROUTES  (protected by JWT)
// ─────────────────────────────────────────────────────────────────

// Admin login
app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body;
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASS)
    return res.status(401).json({ error: 'Invalid admin credentials' });

  const token = jwt.sign({ admin: true, email }, JWT_SECRET, { expiresIn: '24h' });
  log('ADMIN_LOGIN', `Admin logged in`, req.ip);
  res.json({ success: true, token });
});

// Dashboard overview
app.get('/api/admin/dashboard', authMiddleware, (req, res) => {
  const contacts     = db.prepare("SELECT COUNT(*) as c FROM contacts").get().c;
  const newContacts  = db.prepare("SELECT COUNT(*) as c FROM contacts WHERE status='new'").get().c;
  const users        = db.prepare("SELECT COUNT(*) as c FROM users").get().c;
  const reviews      = db.prepare("SELECT COUNT(*) as c FROM reviews").get().c;
  const pendingRevs  = db.prepare("SELECT COUNT(*) as c FROM reviews WHERE approved=0").get().c;
  const avgRating    = db.prepare("SELECT AVG(rating) as a FROM reviews WHERE approved=1").get().a;
  const todayLogs    = db.prepare("SELECT COUNT(*) as c FROM activity_log WHERE date(created_at)=date('now')").get().c;
  const recentLogs   = db.prepare("SELECT * FROM activity_log ORDER BY id DESC LIMIT 10").all();

  res.json({ contacts, newContacts, users, reviews, pendingRevs,
             avgRating: avgRating ? parseFloat(avgRating).toFixed(1) : 0,
             todayLogs, recentLogs });
});

// All contacts
app.get('/api/admin/contacts', authMiddleware, (req, res) => {
  res.json(db.prepare("SELECT * FROM contacts ORDER BY id DESC").all());
});

// Update contact status
app.patch('/api/admin/contacts/:id', authMiddleware, (req, res) => {
  const { status } = req.body;
  db.prepare("UPDATE contacts SET status=? WHERE id=?").run(status, req.params.id);
  log('CONTACT_STATUS', `Contact #${req.params.id} marked as ${status}`, req.ip);
  res.json({ success: true });
});

// Delete contact
app.delete('/api/admin/contacts/:id', authMiddleware, (req, res) => {
  db.prepare("DELETE FROM contacts WHERE id=?").run(req.params.id);
  log('CONTACT_DELETED', `Contact #${req.params.id} deleted`, req.ip);
  res.json({ success: true });
});

// All users
app.get('/api/admin/users', authMiddleware, (req, res) => {
  res.json(db.prepare("SELECT * FROM users ORDER BY id DESC").all());
});

// Delete user
app.delete('/api/admin/users/:id', authMiddleware, (req, res) => {
  db.prepare("DELETE FROM users WHERE id=?").run(req.params.id);
  log('USER_DELETED', `User #${req.params.id} deleted`, req.ip);
  res.json({ success: true });
});

// All reviews
app.get('/api/admin/reviews', authMiddleware, (req, res) => {
  res.json(db.prepare("SELECT * FROM reviews ORDER BY id DESC").all());
});

// Approve / reject review
app.patch('/api/admin/reviews/:id', authMiddleware, (req, res) => {
  const { approved } = req.body;
  db.prepare("UPDATE reviews SET approved=? WHERE id=?").run(approved, req.params.id);
  log('REVIEW_MODERATED', `Review #${req.params.id} ${approved ? 'approved' : 'rejected'}`, req.ip);
  res.json({ success: true });
});

// Delete review
app.delete('/api/admin/reviews/:id', authMiddleware, (req, res) => {
  db.prepare("DELETE FROM reviews WHERE id=?").run(req.params.id);
  log('REVIEW_DELETED', `Review #${req.params.id} deleted`, req.ip);
  res.json({ success: true });
});

// Full activity log
app.get('/api/admin/activity', authMiddleware, (req, res) => {
  const page  = parseInt(req.query.page  || 1);
  const limit = parseInt(req.query.limit || 50);
  const offset = (page - 1) * limit;
  const total = db.prepare("SELECT COUNT(*) as c FROM activity_log").get().c;
  const logs  = db.prepare("SELECT * FROM activity_log ORDER BY id DESC LIMIT ? OFFSET ?").all(limit, offset);
  res.json({ logs, total, page, pages: Math.ceil(total / limit) });
});

// ── Start ───────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Creative Minds server running on http://localhost:${PORT}`));