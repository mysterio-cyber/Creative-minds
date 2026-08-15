/* =====================================================================
   FILE 3 of 5 — routes/googleAuth.routes.js
   =====================================================================
   Backend route for your Node/Express + Postgres app (Creative Minds
   backend on Render). Mount this the same way you mount your existing
   OTP auth routes.

   Install dependency first:
     npm install google-auth-library

   Add to your .env / Render environment variables:
     GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com

   ===================================================================== */

const express = require('express');
const router = express.Router();
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');       // you likely already use this for OTP-based sessions
const pool = require('../db');             // adjust to however you export your pg Pool/client

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// POST /api/auth/google
router.post('/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) {
      return res.status(400).json({ error: 'Missing Google credential.' });
    }

    // 1. Verify the token with Google. This throws if it's invalid, expired,
    //    or was issued for a different client ID — so a forged token is rejected here.
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    // payload looks like: { sub, email, email_verified, name, picture, ... }

    if (!payload || !payload.email_verified) {
      return res.status(401).json({ error: 'Google account email is not verified.' });
    }

    // 2. Find or create the user in Postgres.
    //    Adjust table/column names to match your existing users schema.
    let result = await pool.query(
      'SELECT id, name, email, company FROM users WHERE email = $1',
      [payload.email]
    );

    let user;
    if (result.rows.length) {
      user = result.rows[0];
      // Keep google_id on record in case they later also use OTP login
      await pool.query(
        'UPDATE users SET google_id = COALESCE(google_id, $1) WHERE id = $2',
        [payload.sub, user.id]
      );
    } else {
      const insert = await pool.query(
        `INSERT INTO users (name, email, google_id, created_at)
         VALUES ($1, $2, $3, NOW())
         RETURNING id, name, email, company`,
        [payload.name || 'User', payload.email, payload.sub]
      );
      user = insert.rows[0];
    }

    // 3. Issue your app's own session token — same shape as what your
    //    OTP verify-otp route already returns, so the frontend code
    //    doesn't need to branch on login method.
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      token,
      user: {
        name: user.name,
        email: user.email,
        company: user.company || null
      }
    });
  } catch (err) {
    console.error('Google auth error:', err.message);
    res.status(401).json({ error: 'Google verification failed.' });
  }
});

module.exports = router;
