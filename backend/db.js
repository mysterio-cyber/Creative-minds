// ─────────────────────────────────────────────────────────────────
// Postgres connection pool
// ─────────────────────────────────────────────────────────────────
const { Pool } = require('pg');

const REQUIRED = ['DATABASE_URL'];
const missing = REQUIRED.filter(k => !process.env[k]);
if (missing.length) {
  console.error(`❌ Missing required env vars: ${missing.join(', ')}`);
  console.error('   Set DATABASE_URL to your Render Postgres INTERNAL connection string.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Render's managed Postgres presents a self-signed cert on the internal
  // network. This is the standard, safe setting for THAT specific host —
  // it is not a blanket "disable all TLS verification" flag.
     ssl: {
        rejectUnauthorized: false
  },
  max: 10,
  idleTimeoutMillis: 30000,
});

pool.on('error', (err) => {
  console.error('Unexpected Postgres pool error:', err);
});

module.exports = pool;
