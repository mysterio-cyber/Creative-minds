// ─────────────────────────────────────────────────────────────────
// OTP generation, delivery (email via SMTP, SMS via Twilio),
// and verification. OTPs are bcrypt-hashed at rest and NEVER
// returned in any API response.
// ─────────────────────────────────────────────────────────────────
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const twilio = require('twilio');
const pool = require('./Db');
const { sendMail } = require('./Mailer');

const TWILIO_REQUIRED = ['TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_PHONE_NUMBER'];
const twilioMissing = TWILIO_REQUIRED.filter(k => !process.env[k]);
if (twilioMissing.length) {
  console.warn(`⚠️  Missing SMS env vars: ${twilioMissing.join(', ')} — phone-number OTPs will fail until these are set.`);
}

const twilioClient = (!twilioMissing.length)
  ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
  : null;

const DEFAULT_COUNTRY_CODE = process.env.DEFAULT_COUNTRY_CODE || '+91';

function isEmail(contact) {
  return contact.includes('@');
}

function normalizePhone(contact) {
  return contact.startsWith('+') ? contact : `${DEFAULT_COUNTRY_CODE}${contact}`;
}

function generateOtp() {
  // crypto.randomInt is cryptographically secure; Math.random is not
  // and must never be used to generate an auth code.
  return String(crypto.randomInt(100000, 999999));
}

async function createAndSendOtp(contact) {
  const otp = generateOtp();
  const otpHash = await bcrypt.hash(otp, 10);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  // Invalidate any previous unused OTPs for this contact before issuing a new one
  await pool.query(`UPDATE otps SET used = true WHERE contact = $1 AND used = false`, [contact]);
  await pool.query(
    `INSERT INTO otps (contact, otp_hash, expires_at) VALUES ($1, $2, $3)`,
    [contact, otpHash, expiresAt]
  );

  if (isEmail(contact)) {
    await sendMail({
      to: contact,
      subject: 'Your Creative Minds verification code',
      html: `
        <p>Your verification code is:</p>
        <h2 style="letter-spacing:4px;">${otp}</h2>
        <p>This code expires in 10 minutes. If you didn't request this, you can safely ignore this email.</p>
      `
    });
  } else {
    if (!twilioClient) {
      throw new Error('SMS delivery is not configured on the server.');
    }
    await twilioClient.messages.create({
      body: `Your Creative Minds verification code is ${otp}. It expires in 10 minutes.`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: normalizePhone(contact)
    });
  }

  return { sent: true };
}

async function verifyOtp(contact, submittedOtp) {
  const { rows } = await pool.query(
    `SELECT * FROM otps WHERE contact = $1 AND used = false ORDER BY created_at DESC LIMIT 1`,
    [contact]
  );
  const row = rows[0];

  if (!row) return { ok: false, error: 'OTP not found. Please request a new one.' };
  if (new Date(row.expires_at) < new Date()) return { ok: false, error: 'OTP expired. Please request a new one.' };
  if (row.attempts >= 5) return { ok: false, error: 'Too many incorrect attempts. Please request a new OTP.' };

  const match = await bcrypt.compare(submittedOtp, row.otp_hash);
  if (!match) {
    await pool.query(`UPDATE otps SET attempts = attempts + 1 WHERE id = $1`, [row.id]);
    return { ok: false, error: 'Incorrect OTP. Please try again.' };
  }

  await pool.query(`UPDATE otps SET used = true WHERE id = $1`, [row.id]);
  return { ok: true };
}

// Housekeeping: call periodically (see server.js) to keep the table small
async function purgeExpiredOtps() {
  await pool.query(`DELETE FROM otps WHERE expires_at < now() - interval '1 day'`);
}

module.exports = { createAndSendOtp, verifyOtp, purgeExpiredOtps, isEmail };
