// ─────────────────────────────────────────────────────────────────
// Email delivery (SMTP via Nodemailer)
// ─────────────────────────────────────────────────────────────────
const nodemailer = require('nodemailer');

const EMAIL_HOST = (process.env.EMAIL_HOST || '').trim();
const EMAIL_PORT = String(process.env.EMAIL_PORT || '587').trim();
const EMAIL_USER = (process.env.EMAIL_USER || '').trim();
const EMAIL_PASS = process.env.EMAIL_PASS || '';
const EMAIL_FROM = (process.env.EMAIL_FROM || EMAIL_USER).trim();

let mailer = null;

if (EMAIL_HOST && EMAIL_USER && EMAIL_PASS) {
  mailer = nodemailer.createTransport({
    host: EMAIL_HOST,
    port: Number(EMAIL_PORT),
    secure: Number(EMAIL_PORT) === 465,

    auth: {
      user: EMAIL_USER,
      pass: EMAIL_PASS
    },

    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000
  });

  console.log('✅ Email delivery configured');
  console.log('📧 SMTP host:', JSON.stringify(EMAIL_HOST));
  console.log('📧 SMTP port:', JSON.stringify(EMAIL_PORT));
} else {
  console.warn(
    '⚠️ EMAIL_HOST / EMAIL_USER / EMAIL_PASS not set — emails cannot be sent.'
  );
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
    throw new Error(
      'Email is not configured on the server (missing EMAIL_HOST/EMAIL_USER/EMAIL_PASS).'
    );
  }

  try {
    await mailer.sendMail({
      from: EMAIL_FROM,
      to,
      subject,
      html
    });

    console.log('✅ Email sent successfully to:', to);

    return { sent: true };
  } catch (error) {
    console.error('❌ SMTP send failed:', error.message);
    throw error;
  }
}

module.exports = {
  sendMail,
  escapeHtml,
  isConfigured: !!mailer
};
