const jwt = require('jsonwebtoken');

// Signs and verifies every session token in the app, so this secret is the sole
// thing standing between an anonymous request and any identity or role in the
// system — a holder of it can mint a token asserting any `sub` and any `role`,
// including customer_service (refunds) and admin.
//
// TRAINING: the value comes from the committed .env placeholder
// (`change-me-to-a-long-random-string`), which is effectively public. That is
// tolerable only because this stack holds no real users or money.
//
// PRODUCTION: this placeholder does not survive into production. The deployed
// value is a long random secret stored in a secrets manager (Vault / AWS Secrets
// Manager), injected at runtime into this service alone, distinct per
// environment, and rotated on a schedule. There is intentionally no `||`
// fallback here — an unset secret must break loudly rather than let the service
// come up signing tokens with a value an attacker could guess.
const JWT_SECRET = process.env.JWT_SECRET;

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

module.exports = { requireAuth, requireRole, JWT_SECRET };
