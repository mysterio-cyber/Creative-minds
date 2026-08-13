-- ─────────────────────────────────────────────────────────────────
-- Creative Minds — Postgres schema
-- Run this once against your Render Postgres instance, e.g.:
--   psql "$DATABASE_URL" -f schema.sql
-- ─────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Users ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL DEFAULT 'User',
  email       TEXT UNIQUE,
  phone       TEXT UNIQUE,
  company     TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT has_contact CHECK (email IS NOT NULL OR phone IS NOT NULL)
);

-- ── OTPs (hashed, never stored in plaintext) ───────────────────
CREATE TABLE IF NOT EXISTS otps (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  contact     TEXT NOT NULL,
  otp_hash    TEXT NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  attempts    INT NOT NULL DEFAULT 0,
  used        BOOLEAN NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_otps_contact ON otps(contact) WHERE used = false;

-- ── Sessions (enables revocation, unlike a bare JWT) ───────────
CREATE TABLE IF NOT EXISTS sessions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL,
  revoked_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- ── Activity logs (full audit trail, joinable to users) ────────
CREATE TABLE IF NOT EXISTS activity_logs (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
  event_type  TEXT NOT NULL,
  ip_address  TEXT,
  user_agent  TEXT,
  metadata    JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_user    ON activity_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_type    ON activity_logs(event_type);

-- ── Reviews ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reviews (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  role        TEXT,
  text        TEXT NOT NULL,
  rating      INT NOT NULL CHECK (rating BETWEEN 1 AND 5),
  approved    BOOLEAN NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_reviews_approved ON reviews(approved);

-- ── Contact form submissions ────────────────────────────────────
CREATE TABLE IF NOT EXISTS contact_submissions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  email       TEXT,
  phone       TEXT,
  company     TEXT,
  service     TEXT,
  message     TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'new',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_contacts_status ON contact_submissions(status);

-- ── "Start a Project" submissions ──────────────────────────────
CREATE TABLE IF NOT EXISTS projects (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT NOT NULL,
  email         TEXT NOT NULL,
  phone         TEXT,
  company       TEXT,
  project_type  TEXT,
  budget        TEXT,
  message       TEXT,
  status        TEXT NOT NULL DEFAULT 'new',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status);
