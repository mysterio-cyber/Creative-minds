// ─────────────────────────────────────────────────────────────────
// Creative Minds — Backend Server (Postgres + real OTP delivery)
// ─────────────────────────────────────────────────────────────────

require('dotenv').config();

const express       = require('express');
const cors          = require('cors');
const jwt           = require('jsonwebtoken');
const bcrypt         = require('bcryptjs');
const helmet         = require('helmet');
const rateLimit      = require('express-rate-limit');

// server.js
const pool = require('./db');
const { sendMail, escapeHtml, isConfigured: emailConfigured } = require('./mailer');
const { createAndSendOtp, verifyOtp, purgeExpiredOtps } = require('./otpservice');

const app  = express();
const PORT = process.env.PORT || 4000;

// ── Required secrets — fail fast instead of silently misbehaving ──
const REQUIRED_ENV = ['JWT_SECRET', 'ADMIN_EMAIL', 'ADMIN_PASS_HASH', 'DATABASE_URL'];
const missing = REQUIRED_ENV.filter(k => !process.env[k]);
if (missing.length) {
  console.error(`❌ Missing required env vars: ${missing.join(', ')}`);
  console.error('   ADMIN_PASS_HASH must be a bcrypt hash, e.g.:');
  console.error('   node -e "console.log(require(\'bcryptjs\').hashSync(\'yourPassword\', 10))"');
  process.exit(1);
}

const JWT_SECRET      = process.env.JWT_SECRET;
const ADMIN_EMAIL     = process.env.ADMIN_EMAIL;
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH;
const FRONTEND_URL    = process.env.FRONTEND_URL || 'https://creative-minds-frontend.onrender.com';
const NODE_ENV        = process.env.NODE_ENV || 'development';
const ADMIN_NOTIFY_EMAIL = process.env.ADMIN_NOTIFY_EMAIL || ADMIN_EMAIL;

if (!emailConfigured) {
  console.warn('⚠️  Email is not configured — OTP emails and notification emails will fail until EMAIL_HOST/EMAIL_USER/EMAIL_PASS are set.');
}

// ── Middleware ──────────────────────────────────────────────────
// Required on Render (and most PaaS) so req.ip reflects the real client
// IP instead of the platform's internal proxy IP. Without this, rate
// limiting and IP logging are both effectively broken.
app.set('trust proxy', 1);

app.use(helmet());
app.use(cors({ origin: FRONTEND_URL }));
app.use(express.json({ limit: '100kb' }));

app.get('/', (req, res) => res.send('Creative Minds backend is running 🚀'));
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ── Rate limiters (separate budgets for send vs verify) ─────────
const sendOtpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many OTP requests. Please try again later.' }
});

const verifyOtpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  message: { error: 'Too many verification attempts. Please try again later.' }
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Please try again later.' }
});

const startProjectLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many requests. Please try again later.' }
});

// ── Live activity feed (Server-Sent Events) ─────────────────────
let sseClients = [];

function broadcastActivity(entry) {
  const payload = `data: ${JSON.stringify(entry)}\n\n`;
  sseClients.forEach(client => {
    try { client.res.write(payload); } catch { /* cleaned up on close */ }
  });
}

// ── Activity logging (Postgres-backed, joinable to users) ───────
async function logActivity(eventType, req, userId, metadata) {
  const { rows } = await pool.query(
    `INSERT INTO activity_logs (user_id, event_type, ip_address, user_agent, metadata)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [
      userId || null,
      eventType,
      req?.ip || '',
      req?.headers?.['user-agent'] || '',
      metadata ? JSON.stringify(metadata) : null
    ]
  );
  broadcastActivity(rows[0]);
  return rows[0];
}

// ── Auth middleware ──────────────────────────────────────────────
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

function adminOnly(req, res, next) {
  authMiddleware(req, res, () => {
    if (!req.user || req.user.admin !== true) {
      logActivity('UNAUTHORIZED_ADMIN_ATTEMPT', req, null, { path: req.originalUrl }).catch(() => {});
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  });
}

// small helper to avoid try/catch boilerplate in every route
function asyncRoute(fn) {
  return (req, res, next) => fn(req, res, next).catch(next);
}

// ─────────────────────────────────────────────────────────────────
// PUBLIC ROUTES
// ─────────────────────────────────────────────────────────────────

// ── OTP: send ─────────────────────────────────────────────────────
app.post('/api/send-otp', sendOtpLimiter, asyncRoute(async (req, res) => {
  const { contact } = req.body;
  if (!contact) return res.status(400).json({ error: 'Contact required' });

  await createAndSendOtp(contact);
  await logActivity('OTP_REQUESTED', req, null, { contact_type: contact.includes('@') ? 'email' : 'phone' });

  // The OTP itself is NEVER returned here, in dev or prod — it only
  // ever leaves the server via the actual email/SMS channel.
  res.json({ success: true, message: 'OTP sent.' });
}));

// ── OTP: verify + login/register ─────────────────────────────────
app.post('/api/verify-otp', verifyOtpLimiter, asyncRoute(async (req, res) => {
  const { contact, otp, name, company } = req.body;
  if (!contact || !otp) return res.status(400).json({ error: 'Contact and OTP required' });

  const result = await verifyOtp(contact, otp);
  if (!result.ok) {
    await logActivity('LOGIN_FAILED', req, null, { contact });
    return res.status(400).json({ error: result.error });
  }

  const isEmailContact = contact.includes('@');
  const { rows: existing } = await pool.query(
    `SELECT * FROM users WHERE ${isEmailContact ? 'email' : 'phone'} = $1`,
    [contact]
  );

  let user = existing[0];
  let eventType;

  if (!user) {
    const { rows } = await pool.query(
      `INSERT INTO users (name, email, phone, company) VALUES ($1, $2, $3, $4) RETURNING *`,
      [name || 'User', isEmailContact ? contact : null, isEmailContact ? null : contact, company || null]
    );
    user = rows[0];
    eventType = 'ACCOUNT_CREATED';
  } else {
    if (name && name !== 'User') {
      const { rows } = await pool.query(
        `UPDATE users SET name = $1, company = $2 WHERE id = $3 RETURNING *`,
        [name, company || user.company, user.id]
      );
      user = rows[0];
    }
    eventType = 'LOGIN_SUCCESS';
  }

  const token = jwt.sign({ id: user.id, name: user.name, admin: false }, JWT_SECRET, { expiresIn: '7d' });
  await pool.query(
    `INSERT INTO sessions (user_id, expires_at) VALUES ($1, $2)`,
    [user.id, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)]
  );
  await logActivity(eventType, req, user.id, { name: user.name });

  res.json({ success: true, token, user: { id: user.id, name: user.name, company: user.company } });
}));

// ── Logout (revokes the session row; JWT itself still expires naturally) ──
app.post('/api/logout', authMiddleware, asyncRoute(async (req, res) => {
  await pool.query(
    `UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
    [req.user.id]
  );
  await logActivity('LOGOUT', req, req.user.id, null);
  res.json({ success: true });
}));

// ── Contact form ──────────────────────────────────────────────────
app.post('/api/contact', asyncRoute(async (req, res) => {
  const { name, email, phone, company, service, message } = req.body;
  if (!name || !message) return res.status(400).json({ error: 'Name and message are required' });

  await pool.query(
    `INSERT INTO contact_submissions (name, email, phone, company, service, message)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [name, email || null, phone || null, company || null, service || null, message]
  );
  await logActivity('CONTACT_FORM_SUBMITTED', req, null, { name, service });

  res.json({ success: true, message: 'Message received! We will get back to you within 24 hours.' });
}));

// ── Start a Project ────────────────────────────────────────────────
app.post('/api/start-project', startProjectLimiter, asyncRoute(async (req, res) => {
  const { name, email, phone, company, projectType, budget, message } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });

  await pool.query(
    `INSERT INTO projects (name, email, phone, company, project_type, budget, message)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [name, email, phone || null, company || null, projectType || null, budget || null, message || null]
  );
  await logActivity('PROJECT_STARTED', req, null, { name, email, projectType });

  let emailStatus = { user: { skipped: true }, admin: { skipped: true } };
  if (emailConfigured) {
    const [userResult, adminResult] = await Promise.allSettled([
      sendMail({
        to: email,
        subject: 'We received your project request — Creative Minds',
        html: `
          <p>Hi ${escapeHtml(name)},</p>
          <p>Thanks for reaching out to start a project with us! Someone from our team will be in touch within 24 hours.</p>
          <ul>
            ${projectType ? `<li>Project type: ${escapeHtml(projectType)}</li>` : ''}
            ${budget ? `<li>Budget: ${escapeHtml(budget)}</li>` : ''}
            ${message ? `<li>Message: ${escapeHtml(message)}</li>` : ''}
          </ul>
          <p>— The Creative Minds Team</p>
        `
      }),
      sendMail({
        to: ADMIN_NOTIFY_EMAIL,
        subject: `🚀 New project request from ${name}`,
        html: `
          <ul>
            <li>Name: ${escapeHtml(name)}</li>
            <li>Email: ${escapeHtml(email)}</li>
            <li>Phone: ${escapeHtml(phone || '—')}</li>
            <li>Company: ${escapeHtml(company || '—')}</li>
            <li>Project type: ${escapeHtml(projectType || '—')}</li>
            <li>Budget: ${escapeHtml(budget || '—')}</li>
            <li>Message: ${escapeHtml(message || '—')}</li>
          </ul>
        `
      })
    ]);
    emailStatus = {
      user:  userResult.status  === 'fulfilled' ? userResult.value  : { sent: false, error: userResult.reason?.message },
      admin: adminResult.status === 'fulfilled' ? adminResult.value : { sent: false, error: adminResult.reason?.message }
    };
  }

  res.json({ success: true, message: 'Thanks! We received your project request and will be in touch soon.', emailStatus });
}));

// ── Reviews (public) ────────────────────────────────────────────
app.get('/api/reviews', asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, name, role, text, rating, created_at FROM reviews WHERE approved = true ORDER BY created_at DESC`
  );
  res.json(rows);
}));

app.post('/api/reviews', asyncRoute(async (req, res) => {
  const { name, role, text, rating } = req.body;
  if (!name || !text || !rating) return res.status(400).json({ error: 'Name, review, and rating are required' });
  const r = parseInt(rating);
  if (r < 1 || r > 5) return res.status(400).json({ error: 'Rating must be between 1 and 5' });

  await pool.query(
    `INSERT INTO reviews (name, role, text, rating) VALUES ($1, $2, $3, $4)`,
    [name, role || null, text, r]
  );
  await logActivity('REVIEW_SUBMITTED', req, null, { name, rating: r });

  res.json({ success: true, message: 'Review published!' });
}));

// ── Public stats ──────────────────────────────────────────────────
app.get('/api/stats', asyncRoute(async (req, res) => {
  const { rows: [reviewStats] } = await pool.query(
    `SELECT COUNT(*)::int AS count, COALESCE(AVG(rating), 0)::numeric(3,1) AS avg
     FROM reviews WHERE approved = true`
  );
  const { rows: [userStats] } = await pool.query(`SELECT COUNT(*)::int AS count FROM users`);

  res.json({
    projects: 200 + reviewStats.count,
    clients : 50 + Math.floor(userStats.count / 2),
    reviews : reviewStats.count,
    rating  : reviewStats.count ? reviewStats.avg : null
  });
}));

// ─────────────────────────────────────────────────────────────────
// ADMIN ROUTES
// ─────────────────────────────────────────────────────────────────

app.post('/api/admin/login', adminLoginLimiter, asyncRoute(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const validEmail = email === ADMIN_EMAIL;
  const validPass  = await bcrypt.compare(password, ADMIN_PASS_HASH);

  if (!validEmail || !validPass) {
    await logActivity('ADMIN_LOGIN_FAILED', req, null, { email });
    return res.status(401).json({ error: 'Invalid admin credentials' });
  }

  const token = jwt.sign({ admin: true, email }, JWT_SECRET, { expiresIn: '24h' });
  await logActivity('ADMIN_LOGIN', req, null, { email });
  res.json({ success: true, token });
}));

// Live activity stream (SSE). EventSource can't send headers, so the
// admin token travels as a short-lived query param instead — verified
// exactly like adminOnly, just adapted for SSE's transport limits.
app.get('/api/admin/activity-stream', (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(401).end();

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).end();
  }
  if (!payload.admin) return res.status(403).end();

  res.writeHead(200, {
    'Content-Type'     : 'text/event-stream',
    'Cache-Control'    : 'no-cache',
    'Connection'       : 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.write(': connected\n\n');

  const client = { id: payload.email + Date.now(), res };
  sseClients.push(client);

  const heartbeat = setInterval(() => {
    try { res.write(': heartbeat\n\n'); } catch { /* handled on close */ }
  }, 25000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients = sseClients.filter(c => c.id !== client.id);
  });
});

// ── Dashboard summary ────────────────────────────────────────────
app.get('/api/admin/dashboard', adminOnly, asyncRoute(async (req, res) => {
  const [contacts, newContacts, users, reviews, pendingRevs, avgRating, todayLogs, recentLogs] = await Promise.all([
    pool.query(`SELECT COUNT(*)::int AS n FROM contact_submissions`),
    pool.query(`SELECT COUNT(*)::int AS n FROM contact_submissions WHERE status = 'new'`),
    pool.query(`SELECT COUNT(*)::int AS n FROM users`),
    pool.query(`SELECT COUNT(*)::int AS n FROM reviews`),
    pool.query(`SELECT COUNT(*)::int AS n FROM reviews WHERE approved = false`),
    pool.query(`SELECT COALESCE(AVG(rating), 0)::numeric(3,1) AS avg FROM reviews WHERE approved = true`),
    pool.query(`SELECT COUNT(*)::int AS n FROM activity_logs WHERE created_at::date = CURRENT_DATE`),
    pool.query(`
      SELECT a.id, a.event_type, a.ip_address, a.created_at, u.name AS user_name
      FROM activity_logs a LEFT JOIN users u ON u.id = a.user_id
      ORDER BY a.created_at DESC LIMIT 10
    `)
  ]);

  res.json({
    contacts   : contacts.rows[0].n,
    newContacts: newContacts.rows[0].n,
    users      : users.rows[0].n,
    reviews    : reviews.rows[0].n,
    pendingRevs: pendingRevs.rows[0].n,
    avgRating  : avgRating.rows[0].avg,
    todayLogs  : todayLogs.rows[0].n,
    recentLogs : recentLogs.rows
  });
}));

// ── Contacts ──────────────────────────────────────────────────────
app.get('/api/admin/contacts', adminOnly, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM contact_submissions ORDER BY created_at DESC`);
  res.json(rows);
}));

app.patch('/api/admin/contacts/:id', adminOnly, asyncRoute(async (req, res) => {
  const { status } = req.body;
  await pool.query(`UPDATE contact_submissions SET status = $1 WHERE id = $2`, [status, req.params.id]);
  await logActivity('CONTACT_STATUS_CHANGED', req, null, { contact_id: req.params.id, status, by_admin: req.user.email });
  res.json({ success: true });
}));

app.delete('/api/admin/contacts/:id', adminOnly, asyncRoute(async (req, res) => {
  await pool.query(`DELETE FROM contact_submissions WHERE id = $1`, [req.params.id]);
  await logActivity('CONTACT_DELETED', req, null, { contact_id: req.params.id, by_admin: req.user.email });
  res.json({ success: true });
}));

// ── Projects ("Start a Project" submissions) ─────────────────────
app.get('/api/admin/projects', adminOnly, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM projects ORDER BY created_at DESC`);
  res.json(rows);
}));

app.patch('/api/admin/projects/:id', adminOnly, asyncRoute(async (req, res) => {
  const { status } = req.body;
  await pool.query(`UPDATE projects SET status = $1 WHERE id = $2`, [status, req.params.id]);
  await logActivity('PROJECT_STATUS_CHANGED', req, null, { project_id: req.params.id, status, by_admin: req.user.email });
  res.json({ success: true });
}));

// ── Users ─────────────────────────────────────────────────────────
app.get('/api/admin/users', adminOnly, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM users ORDER BY created_at DESC`);
  res.json(rows);
}));

app.delete('/api/admin/users/:id', adminOnly, asyncRoute(async (req, res) => {
  await pool.query(`DELETE FROM users WHERE id = $1`, [req.params.id]);
  await logActivity('USER_DELETED', req, null, { user_id: req.params.id, by_admin: req.user.email });
  res.json({ success: true });
}));

// Full activity history for one specific user — "everything this person did"
app.get('/api/admin/users/:id/activity', adminOnly, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM activity_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 200`,
    [req.params.id]
  );
  res.json(rows);
}));

// ── Reviews (moderation) ──────────────────────────────────────────
app.get('/api/admin/reviews', adminOnly, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM reviews ORDER BY created_at DESC`);
  res.json(rows);
}));

app.patch('/api/admin/reviews/:id', adminOnly, asyncRoute(async (req, res) => {
  const { approved } = req.body;
  await pool.query(`UPDATE reviews SET approved = $1 WHERE id = $2`, [!!approved, req.params.id]);
  await logActivity('REVIEW_MODERATED', req, null, { review_id: req.params.id, approved: !!approved, by_admin: req.user.email });
  res.json({ success: true });
}));

app.delete('/api/admin/reviews/:id', adminOnly, asyncRoute(async (req, res) => {
  await pool.query(`DELETE FROM reviews WHERE id = $1`, [req.params.id]);
  await logActivity('REVIEW_DELETED', req, null, { review_id: req.params.id, by_admin: req.user.email });
  res.json({ success: true });
}));

// ── Site-wide activity log (paginated, filterable) ────────────────
app.get('/api/admin/activity', adminOnly, asyncRoute(async (req, res) => {
  const page  = Math.max(parseInt(req.query.page) || 1, 1);
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const { type, user_id: userId } = req.query;

  const conditions = [];
  const params = [];
  if (type)   { params.push(type);   conditions.push(`a.event_type = $${params.length}`); }
  if (userId) { params.push(userId); conditions.push(`a.user_id = $${params.length}`); }
  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const { rows: [{ count }] } = await pool.query(
    `SELECT COUNT(*)::int AS count FROM activity_logs a ${where}`, params
  );

  params.push(limit, (page - 1) * limit);
  const { rows: logs } = await pool.query(
    `SELECT a.id, a.event_type, a.ip_address, a.user_agent, a.metadata, a.created_at,
            u.id AS user_id, u.name AS user_name, u.email AS user_email, u.phone AS user_phone
     FROM activity_logs a
     LEFT JOIN users u ON u.id = a.user_id
     ${where}
     ORDER BY a.created_at DESC
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params
  );

  res.json({ logs, total: count, page, pages: Math.ceil(count / limit) });
}));

// ── Global error handler ───────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('❌ SERVER ERROR:', err);
  res.status(500).json({
    error: err.message || 'Something went wrong.'
  });
});

// ── Housekeeping: purge old OTPs once a day ─────────────────────
setInterval(() => {
  purgeExpiredOtps().catch(e => console.error('OTP purge failed:', e.message));
}, 24 * 60 * 60 * 1000);

// ── Start ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Creative Minds server running on port ${PORT} (${NODE_ENV})`);
});
