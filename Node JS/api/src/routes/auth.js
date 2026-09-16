const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db/connection');

const asyncHandler = require('../middleware/asyncHandler');
const { rateLimit } = require('../middleware/rateLimit');
const {
  REFRESH_COOKIE,
  issueSession,
  rotateSession,
  revokeSession,
  clearRefreshCookie,
} = require('../services/tokens');

const router = express.Router();

// Rate limit for credential submission.
const credentialLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many authentication attempts. Please try again later.',
});

// Rate limit for token refresh, which runs on every reload and token expiry.
const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  message: 'Too many refresh attempts. Please try again later.',
});

router.post('/register', credentialLimiter, asyncHandler(async (req, res) => {
  const { email, password, full_name } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'password must be at least 8 characters' });
  }

  const existing = await db('users').where({ email }).first();
  if (existing) {
    return res.status(409).json({ error: 'An account with that email already exists' });
  }

  const password_hash = await bcrypt.hash(password, 10);
  const [row] = await db('users')
    .insert({ email, password_hash, full_name, role: 'customer' })
    .returning(['id', 'email', 'full_name', 'role']);

  const user = row.id ? row : { id: row, email, full_name, role: 'customer' };
  await db('carts').insert({ user_id: user.id });

  const token = await issueSession(res, user);
  res.status(201).json({ token, user });
}));

router.post('/login', credentialLimiter, asyncHandler(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  const user = await db('users').where({ email }).first();
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = await issueSession(res, user);
  res.json({
    token,
    user: { id: user.id, email: user.email, full_name: user.full_name, role: user.role },
  });
}));

// Exchanges the refresh cookie for a new access token. The old refresh token is
// consumed and replaced in the process, so each cookie is good for one refresh.
router.post('/refresh', refreshLimiter, asyncHandler(async (req, res) => {
  const presented = req.cookies?.[REFRESH_COOKIE];
  if (!presented) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const rotated = await rotateSession(res, presented);
  if (!rotated) {
    clearRefreshCookie(res);
    return res.status(401).json({ error: 'Invalid or expired session' });
  }

  res.json({ token: rotated.accessToken, user: rotated.user });
}));

router.post('/logout', asyncHandler(async (req, res) => {
  await revokeSession(req.cookies?.[REFRESH_COOKIE]);
  clearRefreshCookie(res);
  res.status(204).end();
}));

module.exports = router;
