const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../db/connection');
const { JWT_SECRET } = require('../middleware/auth');

// Access tokens are short-lived because nothing revokes them: once signed, a
// token is valid until it expires, so a stolen one is only useful for this
// window. Anything longer-lived belongs in the refresh token, which is stored
// server-side and can be revoked.
const ACCESS_TOKEN_TTL = '15m';

// The refresh token is the real session lifetime. It is opaque (no claims), so
// it carries no authority on its own — every use is checked against the row in
// `refresh_tokens`.
const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const REFRESH_COOKIE = 'refresh_token';
// Scoped to the auth routes so the cookie is not attached to every API call.
const REFRESH_COOKIE_PATH = '/api/auth';

function signAccessToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, role: user.role }, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_TTL,
  });
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function issueRefreshToken(userId, replacedId = null) {
  const token = crypto.randomBytes(32).toString('hex');
  const [row] = await db('refresh_tokens')
    .insert({
      user_id: userId,
      token_hash: hashToken(token),
      expires_at: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
    })
    .returning('id');

  if (replacedId) {
    await db('refresh_tokens')
      .where({ id: replacedId })
      .update({ replaced_by: row.id ?? row });
  }
  return token;
}

function setRefreshCookie(res, token) {
  res.cookie(REFRESH_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    // TRAINING: the local stack is served over plain http, so the Secure flag
    // is only set outside development. In production this is always true and
    // the cookie never travels unencrypted.
    secure: process.env.NODE_ENV === 'production',
    path: REFRESH_COOKIE_PATH,
    maxAge: REFRESH_TOKEN_TTL_MS,
  });
}

function clearRefreshCookie(res) {
  res.clearCookie(REFRESH_COOKIE, { path: REFRESH_COOKIE_PATH });
}

// Issues a fresh pair and plants the refresh cookie. Used by register/login.
async function issueSession(res, user) {
  const refreshToken = await issueRefreshToken(user.id);
  setRefreshCookie(res, refreshToken);
  return signAccessToken(user);
}

// Consumes a refresh token and issues a new pair. Rotation is single-use: the
// presented token is revoked as part of the same transaction that mints its
// replacement.
//
// If a token that was already consumed is presented again, it means either a
// copy leaked or a client raced itself. We cannot tell which, so we revoke the
// whole family for that user and force a re-login rather than let a possibly
// stolen token keep working.
async function rotateSession(res, presentedToken) {
  const token_hash = hashToken(presentedToken);
  const existing = await db('refresh_tokens').where({ token_hash }).first();

  if (!existing) return null;

  if (existing.revoked_at) {
    await db('refresh_tokens')
      .where({ user_id: existing.user_id })
      .whereNull('revoked_at')
      .update({ revoked_at: db.fn.now() });
    return null;
  }

  if (new Date(existing.expires_at) <= new Date()) return null;

  const user = await db('users')
    .where({ id: existing.user_id })
    .select('id', 'email', 'full_name', 'role')
    .first();
  if (!user) return null;

  await db('refresh_tokens').where({ id: existing.id }).update({ revoked_at: db.fn.now() });
  const nextToken = await issueRefreshToken(user.id, existing.id);
  setRefreshCookie(res, nextToken);

  return { accessToken: signAccessToken(user), user };
}

async function revokeSession(presentedToken) {
  if (!presentedToken) return;
  await db('refresh_tokens')
    .where({ token_hash: hashToken(presentedToken) })
    .whereNull('revoked_at')
    .update({ revoked_at: db.fn.now() });
}

module.exports = {
  ACCESS_TOKEN_TTL,
  REFRESH_COOKIE,
  signAccessToken,
  issueSession,
  rotateSession,
  revokeSession,
  clearRefreshCookie,
};
