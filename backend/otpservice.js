const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const pool = require('./db');
const { sendMail } = require('./mailer');

const TWOFACTOR_API_KEY = process.env.TWOFACTOR_API_KEY;
const DEFAULT_COUNTRY_CODE = process.env.DEFAULT_COUNTRY_CODE || '+91';

if (!TWOFACTOR_API_KEY) {
  console.warn('⚠️ Missing TWOFACTOR_API_KEY — phone-number OTPs will fail until this is set.');
} else {
  console.log('✅ 2Factor SMS OTP configured');
}

function isEmail(contact) {
  return contact.includes('@');
}

function normalizePhone(contact) {
  return contact.startsWith('+')
    ? contact
    : `${DEFAULT_COUNTRY_CODE}${contact}`;
}

function generateOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

async function sendSmsOtp(phone, otp) {
  if (!TWOFACTOR_API_KEY) {
    throw new Error('2Factor SMS is not configured on the server.');
  }

  const url =
    `https://2factor.in/API/V1/${TWOFACTOR_API_KEY}/SMS/${phone}/${otp}`;

  const response = await axios.post(url, null, {
    timeout: 15000
  });

  if (response.data?.Status !== 'Success') {
    throw new Error(
      `2Factor SMS failed: ${JSON.stringify(response.data)}`
    );
  }

  return response.data;
}

async function createAndSendOtp(contact) {
  const otp = generateOtp();
  const otpHash = await bcrypt.hash(otp, 10);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  // Invalidate previous unused OTPs
  await pool.query(
    `UPDATE otps
     SET used = true
     WHERE contact = $1
     AND used = false`,
    [contact]
  );

  // Store hashed OTP
  await pool.query(
    `INSERT INTO otps (contact, otp_hash, expires_at)
     VALUES ($1, $2, $3)`,
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
    const phone = normalizePhone(contact);

    await sendSmsOtp(phone, otp);
  }

  return { sent: true };
}

async function verifyOtp(contact, submittedOtp) {
  const { rows } = await pool.query(
    `SELECT *
     FROM otps
     WHERE contact = $1
     AND used = false
     ORDER BY created_at DESC
     LIMIT 1`,
    [contact]
  );

  const row = rows[0];

  if (!row) {
    return {
      ok: false,
      error: 'OTP not found. Please request a new one.'
    };
  }

  if (new Date(row.expires_at) < new Date()) {
    return {
      ok: false,
      error: 'OTP expired. Please request a new one.'
    };
  }

  if (row.attempts >= 5) {
    return {
      ok: false,
      error: 'Too many incorrect attempts. Please request a new OTP.'
    };
  }

  const match = await bcrypt.compare(
    submittedOtp,
    row.otp_hash
  );

  if (!match) {
    await pool.query(
      `UPDATE otps
       SET attempts = attempts + 1
       WHERE id = $1`,
      [row.id]
    );

    return {
      ok: false,
      error: 'Incorrect OTP. Please try again.'
    };
  }

  await pool.query(
    `UPDATE otps
     SET used = true
     WHERE id = $1`,
    [row.id]
  );

  return { ok: true };
}

async function purgeExpiredOtps() {
  await pool.query(
    `DELETE FROM otps
     WHERE expires_at < now() - interval '1 day'`
  );
}

module.exports = {
  createAndSendOtp,
  verifyOtp,
  purgeExpiredOtps,
  isEmail
};
