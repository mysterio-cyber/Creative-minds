// ─────────────────────────────────────────────────────────────────
// Creative Minds — Backend Server
// Stack : Node.js + Express + JSON file database (no native modules)
// Deploy: Works on Render, Railway, Vercel, any Node host
// ─────────────────────────────────────────────────────────────────
const express = require('express');
const cors    = require('cors');
const jwt     = require('jsonwebtoken');
const path    = require('path');
const fs      = require('fs');
const { v4: uuidv4 } = require('uuid');

const app  = express();
const PORT = process.env.PORT || 4000;

const JWT_SECRET  = process.env.JWT_SECRET  || 'cm_super_secret_2025';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL  || 'admin@creativeminds.in';
const ADMIN_PASS  = process.env.ADMIN_PASS   || 'Admin@CM2025';

// ── Middleware ──────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());
app.get("/", (req, res) => {
  res.send("Creative Minds backend is running 🚀");
});

// ── JSON File Database ──────────────────────────────────────────
const DB_FILE = path.join(__dirname, 'database.json');

function readDB() {
  try {
    if (!fs.existsSync(DB_FILE)) return initDB();
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch(e) {
    return initDB();
  }
}

function initDB() {
  return { users: [], contacts: [], reviews: [], activity: [], otps: [] };
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function logActivity(type, detail, ip) {
  const db = readDB();
  db.activity.push({ id: uuidv4(), type, detail, ip: ip || '', created_at: new Date().toISOString() });
  writeDB(db);
}

// ── Auth Middleware ─────────────────────────────────────────────
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

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Send OTP
app.post('/api/send-otp', (req, res) => {
  const { contact } = req.body;
  if (!contact) return res.status(400).json({ error: 'Contact required' });

  const otp     = String(Math.floor(1000 + Math.random() * 9000));
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  const db = readDB();
  // Remove old OTPs for this contact
  db.otps = db.otps.filter(o => o.contact !== contact);
  db.otps.push({ id: uuidv4(), contact, otp, expires, used: false });
  writeDB(db);

  logActivity('OTP_SENT', `OTP sent to ${contact}`, req.ip);
  console.log(`[OTP] ${contact} → ${otp}`);

  // In production: integrate Twilio / MSG91 / SendGrid here
  res.json({ success: true, demo_otp: otp });
});

// Verify OTP + login/register
app.post('/api/verify-otp', (req, res) => {
  const { contact, otp, name, company } = req.body;
  if (!contact || !otp) return res.status(400).json({ error: 'Contact and OTP required' });

  const db  = readDB();
  const row = db.otps.filter(o => o.contact === contact && !o.used).pop();

  if (!row)                            return res.status(400).json({ error: 'OTP not found. Please request a new one.' });
  if (new Date(row.expires) < new Date()) return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
  if (row.otp !== otp)                 return res.status(400).json({ error: 'Incorrect OTP. Please try again.' });

  // Mark OTP used
  db.otps = db.otps.map(o => o.id === row.id ? { ...o, used: true } : o);

  let user = db.users.find(u => u.email === contact || u.phone === contact);

  if (!user) {
    user = {
      id        : uuidv4(),
      name      : name || 'User',
      email     : contact.includes('@') ? contact : null,
      phone     : contact.includes('@') ? null    : contact,
      company   : company || null,
      created_at: new Date().toISOString()
    };
    db.users.push(user);
    logActivity('USER_REGISTERED', `New user: ${user.name} (${contact})`, req.ip);
  } else {
    if (name && name !== 'User') {
      user.name    = name;
      user.company = company || user.company;
      db.users = db.users.map(u => u.id === user.id ? user : u);
    }
    logActivity('USER_LOGIN', `Login: ${user.name} (${contact})`, req.ip);
  }

  writeDB(db);
  const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, user: { id: user.id, name: user.name, company: user.company } });
});

// Submit contact form
app.post('/api/contact', (req, res) => {
  const { name, email, phone, company, service, message } = req.body;
  if (!name || !message) return res.status(400).json({ error: 'Name and message are required' });

  const db = readDB();
  db.contacts.push({
    id: uuidv4(), name, email: email||'', phone: phone||'',
    company: company||'', service: service||'', message,
    status: 'new', created_at: new Date().toISOString()
  });
  writeDB(db);
  logActivity('CONTACT_FORM', `New enquiry from ${name} — ${service || 'General'}`, req.ip);
  res.json({ success: true, message: 'Message received! We will get back to you within 24 hours.' });
});

// Get approved reviews
app.get('/api/reviews', (req, res) => {
  const db = readDB();
  const reviews = db.reviews.filter(r => r.approved).sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
  res.json(reviews);
});

// Submit review
app.post('/api/reviews', (req, res) => {
  const { name, role, text, rating } = req.body;
  if (!name || !text || !rating) return res.status(400).json({ error: 'Name, review, and rating are required' });
  if (rating < 1 || rating > 5)  return res.status(400).json({ error: 'Rating must be between 1 and 5' });

  const db = readDB();
  db.reviews.push({ id: uuidv4(), name, role: role||'', text, rating: parseInt(rating), approved: true, created_at: new Date().toISOString() });
  writeDB(db);
  logActivity('REVIEW_SUBMITTED', `Review by ${name} — ${rating} stars`, req.ip);
  res.json({ success: true, message: 'Review published!' });
});

// Public stats
app.get('/api/stats', (req, res) => {
  const db      = readDB();
  const reviews = db.reviews.filter(r => r.approved);
  const avg     = reviews.length ? (reviews.reduce((s,r) => s + r.rating, 0) / reviews.length).toFixed(1) : null;
  res.json({
    projects: 200 + reviews.length,
    clients : 50  + Math.floor(db.users.length / 2),
    reviews : reviews.length,
    rating  : avg
  });
});

// ─────────────────────────────────────────────────────────────────
// ADMIN ROUTES
// ─────────────────────────────────────────────────────────────────

// Admin login
app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body;
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASS)
    return res.status(401).json({ error: 'Invalid admin credentials' });
  const token = jwt.sign({ admin: true, email }, JWT_SECRET, { expiresIn: '24h' });
  logActivity('ADMIN_LOGIN', 'Admin logged in', req.ip);
  res.json({ success: true, token });
});

// Dashboard overview
app.get('/api/admin/dashboard', authMiddleware, (req, res) => {
  const db       = readDB();
  const today    = new Date().toDateString();
  const todayAct = db.activity.filter(a => new Date(a.created_at).toDateString() === today).length;
  const reviews  = db.reviews.filter(r => r.approved);
  const avg      = reviews.length ? (reviews.reduce((s,r) => s+r.rating,0)/reviews.length).toFixed(1) : 0;
  res.json({
    contacts   : db.contacts.length,
    newContacts: db.contacts.filter(c => c.status === 'new').length,
    users      : db.users.length,
    reviews    : db.reviews.length,
    pendingRevs: db.reviews.filter(r => !r.approved).length,
    avgRating  : avg,
    todayLogs  : todayAct,
    recentLogs : db.activity.slice().reverse().slice(0, 10)
  });
});

// All contacts
app.get('/api/admin/contacts', authMiddleware, (req, res) => {
  const db = readDB();
  res.json(db.contacts.slice().reverse());
});

// Update contact status
app.patch('/api/admin/contacts/:id', authMiddleware, (req, res) => {
  const { status } = req.body;
  const db = readDB();
  db.contacts = db.contacts.map(c => c.id === req.params.id ? { ...c, status } : c);
  writeDB(db);
  logActivity('CONTACT_STATUS', `Contact ${req.params.id} marked as ${status}`, req.ip);
  res.json({ success: true });
});

// Delete contact
app.delete('/api/admin/contacts/:id', authMiddleware, (req, res) => {
  const db = readDB();
  db.contacts = db.contacts.filter(c => c.id !== req.params.id);
  writeDB(db);
  logActivity('CONTACT_DELETED', `Contact ${req.params.id} deleted`, req.ip);
  res.json({ success: true });
});

// All users
app.get('/api/admin/users', authMiddleware, (req, res) => {
  const db = readDB();
  res.json(db.users.slice().reverse());
});

// Delete user
app.delete('/api/admin/users/:id', authMiddleware, (req, res) => {
  const db = readDB();
  db.users = db.users.filter(u => u.id !== req.params.id);
  writeDB(db);
  logActivity('USER_DELETED', `User ${req.params.id} deleted`, req.ip);
  res.json({ success: true });
});

// All reviews (admin)
app.get('/api/admin/reviews', authMiddleware, (req, res) => {
  const db = readDB();
  res.json(db.reviews.slice().reverse());
});

// Approve/reject review
app.patch('/api/admin/reviews/:id', authMiddleware, (req, res) => {
  const { approved } = req.body;
  const db = readDB();
  db.reviews = db.reviews.map(r => r.id === req.params.id ? { ...r, approved: !!approved } : r);
  writeDB(db);
  logActivity('REVIEW_MODERATED', `Review ${req.params.id} ${approved ? 'approved' : 'rejected'}`, req.ip);
  res.json({ success: true });
});

// Delete review
app.delete('/api/admin/reviews/:id', authMiddleware, (req, res) => {
  const db = readDB();
  db.reviews = db.reviews.filter(r => r.id !== req.params.id);
  writeDB(db);
  logActivity('REVIEW_DELETED', `Review ${req.params.id} deleted`, req.ip);
  res.json({ success: true });
});

// Activity log (paginated)
app.get('/api/admin/activity', authMiddleware, (req, res) => {
  const db    = readDB();
  const page  = parseInt(req.query.page  || 1);
  const limit = parseInt(req.query.limit || 50);
  const all   = db.activity.slice().reverse();
  const total = all.length;
  const logs  = all.slice((page-1)*limit, page*limit);
  res.json({ logs, total, page, pages: Math.ceil(total/limit) });
});

// ── Start ───────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Creative Minds server running on port ${PORT}`);
  // Init DB file if not exists
  if (!fs.existsSync(DB_FILE)) {
    writeDB(initDB());
    console.log('✅ Database initialized');
  }
});
