// ─────────────────────────────────────────────────────────────────
// Creative Minds — Backend Server (hardened)
// Stack : Node.js + Express + JSON file database (no native modules)
// Deploy: Works on Render, Railway, Vercel, any Node host
// ─────────────────────────────────────────────────────────────────
const express      = require('express');
const cors         = require('cors');
const jwt          = require('jsonwebtoken');
const bcrypt       = require('bcryptjs');
const path         = require('path');
const fs           = require('fs');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const app  = express();
const PORT = process.env.PORT || 4000;

// ── Required secrets — fail fast instead of falling back to known values ──
// (Your old fallbacks were hardcoded in source and already leaked publicly
// in render.yaml, so they must never be used as a safety net again.)
const REQUIRED_ENV = ['JWT_SECRET', 'ADMIN_EMAIL', 'ADMIN_PASS_HASH'];
const missing = REQUIRED_ENV.filter(k => !process.env[k]);
if (missing.length) {
  console.error(`❌ Missing required env vars: ${missing.join(', ')}`);
  console.error('   Set these in your Render dashboard (not in render.yaml).');
  console.error('   ADMIN_PASS_HASH must be a bcrypt hash — generate one with:');
  console.error('   node -e "console.log(require(\'bcryptjs\').hashSync(\'yourNewPassword\', 10))"');
  process.exit(1);
}

const JWT_SECRET      = process.env.JWT_SECRET;
const ADMIN_EMAIL     = process.env.ADMIN_EMAIL;
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH; // bcrypt hash, not plaintext
const FRONTEND_URL    = process.env.FRONTEND_URL || 'https://creative-minds-frontend.onrender.com';
const NODE_ENV        = process.env.NODE_ENV || 'development';

// ── Middleware ──────────────────────────────────────────────────
app.use(helmet());
app.use(cors({ origin: FRONTEND_URL }));
app.use(express.json({ limit: '100kb' })); // cap body size

app.get('/', (req, res) => {
  res.send('Creative Minds backend is running 🚀');
});

// ── Rate limiters ───────────────────────────────────────────────
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 5,                   // 5 requests per IP per window
  message: { error: 'Too many requests. Please try again later.' }
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Please try again later.' }
});

// ── JSON File Database ──────────────────────────────────────────
// NOTE: On Render's free tier this file lives on ephemeral disk and
// WILL be wiped on redeploy/restart. Add a persistent disk in Render,
// or migrate to a hosted DB (MongoDB Atlas / Render Postgres) before
// you rely on this data long-term.
const DB_FILE = path.join(__dirname, 'database.json');

function readDB() {
  try {
    if (!fs.existsSync(DB_FILE)) return initDB();
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (e) {
    return initDB();
  }
}

function initDB() {
  return { users: [], contacts: [], reviews: [], activity: [], otps: [] };
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// ── Activity logging ────────────────────────────────────────────
// Structured log: who did it, what happened, and where from.
function logActivity(type, detail, req, actor) {
  const db = readDB();
  db.activity.push({
    id        : uuidv4(),
    type,                                  // e.g. 'USER_LOGIN', 'ADMIN_LOGIN', 'CONTACT_DELETED'
    detail,                                // human-readable summary
    actor     : actor || null,             // { id, name/email, role } of whoever did it
    ip        : req?.ip || '',
    userAgent : req?.headers?.['user-agent'] || '',
    created_at: new Date().toISOString()
  });
  writeDB(db);
}

// ── Auth Middleware ─────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Admin routes must check the token actually belongs to an admin —
// a regular user's valid JWT should NOT pass this.
function adminOnly(req, res, next) {
  authMiddleware(req, res, () => {
    if (!req.user || req.user.admin !== true) {
      logActivity('UNAUTHORIZED_ADMIN_ATTEMPT', `Non-admin token tried to access ${req.originalUrl}`, req, req.user);
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  });
}

// ─────────────────────────────────────────────────────────────────
// PUBLIC ROUTES
// ─────────────────────────────────────────────────────────────────

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Send OTP
app.post('/api/send-otp', otpLimiter, (req, res) => {
  const { contact } = req.body;
  if (!contact) return res.status(400).json({ error: 'Contact required' });

  const otp     = String(Math.floor(100000 + Math.random() * 900000)); // 6 digits, not 4
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  const db = readDB();
  db.otps = db.otps.filter(o => o.contact !== contact);
  db.otps.push({ id: uuidv4(), contact, otp, expires, used: false, attempts: 0 });
  writeDB(db);

  logActivity('OTP_SENT', `OTP requested for ${contact}`, req);

  // TODO: integrate real delivery — Twilio / MSG91 / SendGrid.
  // The OTP must be sent to the user's phone/email, never returned
  // in this API response — returning it lets anyone log in as anyone.
  if (NODE_ENV !== 'production') {
    console.log(`[DEV ONLY] OTP for ${contact}: ${otp}`);
    return res.json({ success: true, dev_note: 'OTP logged to server console in dev mode only' });
  }

  res.json({ success: true, message: 'OTP sent.' });
});

// Verify OTP + login/register
app.post('/api/verify-otp', otpLimiter, (req, res) => {
  const { contact, otp, name, company } = req.body;
  if (!contact || !otp) return res.status(400).json({ error: 'Contact and OTP required' });

  const db  = readDB();
  const row = db.otps.filter(o => o.contact === contact && !o.used).pop();

  if (!row) return res.status(400).json({ error: 'OTP not found. Please request a new one.' });
  if (new Date(row.expires) < new Date()) return res.status(400).json({ error: 'OTP expired. Please request a new one.' });

  // Cap verification attempts per OTP to slow brute force
  if (row.attempts >= 5) {
    return res.status(429).json({ error: 'Too many incorrect attempts. Please request a new OTP.' });
  }
  if (row.otp !== otp) {
    db.otps = db.otps.map(o => o.id === row.id ? { ...o, attempts: o.attempts + 1 } : o);
    writeDB(db);
    return res.status(400).json({ error: 'Incorrect OTP. Please try again.' });
  }

  db.otps = db.otps.map(o => o.id === row.id ? { ...o, used: true } : o);

  let user = db.users.find(u => u.email === contact || u.phone === contact);
  let eventType, eventDetail;

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
    eventType = 'USER_REGISTERED';
    eventDetail = `New user: ${user.name} (${contact})`;
  } else {
    if (name && name !== 'User') {
      user.name    = name;
      user.company = company || user.company;
      db.users = db.users.map(u => u.id === user.id ? user : u);
    }
    eventType = 'USER_LOGIN';
    eventDetail = `Login: ${user.name} (${contact})`;
  }

  writeDB(db);
  const token = jwt.sign({ id: user.id, name: user.name, admin: false }, JWT_SECRET, { expiresIn: '7d' });
  logActivity(eventType, eventDetail, req, { id: user.id, name: user.name, role: 'user' });
  res.json({ success: true, token, user: { id: user.id, name: user.name, company: user.company } });
});

// Submit contact form
app.post('/api/contact', (req, res) => {
  const { name, email, phone, company, service, message } = req.body;
  if (!name || !message) return res.status(400).json({ error: 'Name and message are required' });

  const db = readDB();
  db.contacts.push({
    id: uuidv4(), name, email: email || '', phone: phone || '',
    company: company || '', service: service || '', message,
    status: 'new', created_at: new Date().toISOString()
  });
  writeDB(db);
  logActivity('CONTACT_FORM', `New enquiry from ${name} — ${service || 'General'}`, req);
  res.json({ success: true, message: 'Message received! We will get back to you within 24 hours.' });
});

// Get approved reviews
app.get('/api/reviews', (req, res) => {
  const db = readDB();
  const reviews = db.reviews.filter(r => r.approved).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json(reviews);
});

// Submit review
app.post('/api/reviews', (req, res) => {
  const { name, role, text, rating } = req.body;
  if (!name || !text || !rating) return res.status(400).json({ error: 'Name, review, and rating are required' });
  if (rating < 1 || rating > 5)  return res.status(400).json({ error: 'Rating must be between 1 and 5' });

  const db = readDB();
  db.reviews.push({ id: uuidv4(), name, role: role || '', text, rating: parseInt(rating), approved: true, created_at: new Date().toISOString() });
  writeDB(db);
  logActivity('REVIEW_SUBMITTED', `Review by ${name} — ${rating} stars`, req);
  res.json({ success: true, message: 'Review published!' });
});

// Public stats
app.get('/api/stats', (req, res) => {
  const db      = readDB();
  const reviews = db.reviews.filter(r => r.approved);
  const avg     = reviews.length ? (reviews.reduce((s, r) => s + r.rating, 0) / reviews.length).toFixed(1) : null;
  res.json({
    projects: 200 + reviews.length,
    clients : 50  + Math.floor(db.users.length / 2),
    reviews : reviews.length,
    rating  : avg
  });
});

// ─────────────────────────────────────────────────────────────────
// ADMIN ROUTES  (all protected by adminOnly, not just authMiddleware)
// ─────────────────────────────────────────────────────────────────

app.post('/api/admin/login', adminLoginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const validEmail = email === ADMIN_EMAIL;
  const validPass  = await bcrypt.compare(password, ADMIN_PASS_HASH);

  if (!validEmail || !validPass) {
    logActivity('ADMIN_LOGIN_FAILED', `Failed admin login attempt for ${email}`, req);
    return res.status(401).json({ error: 'Invalid admin credentials' });
  }

  const token = jwt.sign({ admin: true, email }, JWT_SECRET, { expiresIn: '24h' });
  logActivity('ADMIN_LOGIN', 'Admin logged in', req, { email, role: 'admin' });
  res.json({ success: true, token });
});

app.get('/api/admin/dashboard', adminOnly, (req, res) => {
  const db       = readDB();
  const today    = new Date().toDateString();
  const todayAct = db.activity.filter(a => new Date(a.created_at).toDateString() === today).length;
  const reviews  = db.reviews.filter(r => r.approved);
  const avg      = reviews.length ? (reviews.reduce((s, r) => s + r.rating, 0) / reviews.length).toFixed(1) : 0;
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

app.get('/api/admin/contacts', adminOnly, (req, res) => {
  const db = readDB();
  res.json(db.contacts.slice().reverse());
});

app.patch('/api/admin/contacts/:id', adminOnly, (req, res) => {
  const { status } = req.body;
  const db = readDB();
  db.contacts = db.contacts.map(c => c.id === req.params.id ? { ...c, status } : c);
  writeDB(db);
  logActivity('CONTACT_STATUS', `Contact ${req.params.id} marked as ${status}`, req, req.user);
  res.json({ success: true });
});

app.delete('/api/admin/contacts/:id', adminOnly, (req, res) => {
  const db = readDB();
  db.contacts = db.contacts.filter(c => c.id !== req.params.id);
  writeDB(db);
  logActivity('CONTACT_DELETED', `Contact ${req.params.id} deleted`, req, req.user);
  res.json({ success: true });
});

app.get('/api/admin/users', adminOnly, (req, res) => {
  const db = readDB();
  res.json(db.users.slice().reverse());
});

app.delete('/api/admin/users/:id', adminOnly, (req, res) => {
  const db = readDB();
  db.users = db.users.filter(u => u.id !== req.params.id);
  writeDB(db);
  logActivity('USER_DELETED', `User ${req.params.id} deleted`, req, req.user);
  res.json({ success: true });
});

app.get('/api/admin/reviews', adminOnly, (req, res) => {
  const db = readDB();
  res.json(db.reviews.slice().reverse());
});

app.patch('/api/admin/reviews/:id', adminOnly, (req, res) => {
  const { approved } = req.body;
  const db = readDB();
  db.reviews = db.reviews.map(r => r.id === req.params.id ? { ...r, approved: !!approved } : r);
  writeDB(db);
  logActivity('REVIEW_MODERATED', `Review ${req.params.id} ${approved ? 'approved' : 'rejected'}`, req, req.user);
  res.json({ success: true });
});

app.delete('/api/admin/reviews/:id', adminOnly, (req, res) => {
  const db = readDB();
  db.reviews = db.reviews.filter(r => r.id !== req.params.id);
  writeDB(db);
  logActivity('REVIEW_DELETED', `Review ${req.params.id} deleted`, req, req.user);
  res.json({ success: true });
});

// Activity log (paginated) — filterable by type
app.get('/api/admin/activity', adminOnly, (req, res) => {
  const db    = readDB();
  const page  = parseInt(req.query.page  || 1);
  const limit = parseInt(req.query.limit || 50);
  const type  = req.query.type;
  let all     = db.activity.slice().reverse();
  if (type) all = all.filter(a => a.type === type);
  const total = all.length;
  const logs  = all.slice((page - 1) * limit, page * limit);
  res.json({ logs, total, page, pages: Math.ceil(total / limit) });
});

// ── Global error handler (avoid leaking stack traces) ───────────
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong.' });
});

// ── Start ───────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Creative Minds server running on port ${PORT}`);
  if (!fs.existsSync(DB_FILE)) {
    writeDB(initDB());
    console.log('✅ Database initialized');
  }
});
