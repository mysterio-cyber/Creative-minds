// ─────────────────────────────────────────────────────────────────
// Email delivery (SMTP via Nodemailer)
// ─────────────────────────────────────────────────────────────────
const nodemailer = require('nodemailer');

const EMAIL_HOST = process.env.EMAIL_HOST;
const EMAIL_PORT = process.env.EMAIL_PORT || 587;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const EMAIL_FROM = process.env.EMAIL_FROM || EMAIL_USER;

let mailer = null;
if (EMAIL_HOST && EMAIL_USER && EMAIL_PASS) {
  mailer = nodemailer.createTransport({
    host: EMAIL_HOST,
    port: Number(EMAIL_PORT),
    secure: Number(EMAIL_PORT) === 465,
    auth: { user: EMAIL_USER, pass: EMAIL_PASS }
  });
  console.log('✅ Email delivery configured');
} else {
  console.warn('⚠️  EMAIL_HOST / EMAIL_USER / EMAIL_PASS not set — emails (including OTPs) cannot be sent.');
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function sendMail({ to, subject, html }) {
  if (!mailer) {
    throw new Error('Email is not configured on the server (missing EMAIL_HOST/EMAIL_USER/EMAIL_PASS).');
  }
  await mailer.sendMail({ from: EMAIL_FROM, to, subject, html });
  return { sent: true };
}

module.exports = { sendMail, escapeHtml, isConfigured: !!mailer };
