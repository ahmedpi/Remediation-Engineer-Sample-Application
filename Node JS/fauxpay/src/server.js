// FauxPay — a deliberately simplified stand-in for a real payment processor
// (Stripe, Adyen, Braintree), built for this training environment only. It is
// NOT a model of how to build a processor, and nothing here is production code:
// state is in memory, there is no settlement, no 3-D Secure, no Luhn check, and
// no fraud scoring. In production this service does not exist — the API talks to
// the real processor's hosted endpoints over egress-only TLS, and the processor
// owns cardholder data end to end.
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');

// A real processor key is a per-account secret pulled from a secrets manager
// (Vault, AWS Secrets Manager) and injected at runtime into the API service
// alone — never committed, never given a working fallback, never present in
// the web tier. No `||` default: a missing secret fails closed instead of
// silently accepting a known one, matching api/src/server.js's JWT_SECRET check.
if (!process.env.FAUXPAY_API_KEY) {
  console.error('FAUXPAY_API_KEY environment variable is required');
  process.exit(1);
}
const API_KEY = process.env.FAUXPAY_API_KEY;
const PORT = Number(process.env.PORT || 4000);

// Self-signed, generated at container startup by docker-entrypoint.sh — see
// there for why. Callers (nginx's /fauxpay/ relay, api's fauxpayClient) must
// be given this cert to trust explicitly, since it has no public CA behind it.
const TLS_CERT_PATH = process.env.FAUXPAY_TLS_CERT || '/certs/cert.pem';
const TLS_KEY_PATH = process.env.FAUXPAY_TLS_KEY || '/certs/key.pem';

const app = express();
app.use(express.json());

// In-memory stores — FauxPay is a fictional processor for training/demo purposes only.
const tokens = new Map(); // card_token -> { last4, brand }
const transactions = new Map(); // transaction_id -> { amount_cents, refunded_cents }

// Guards the money-moving endpoints (/charge, /refund) with the merchant's
// secret key. Plain `!==` is fine for a fictional key in a training container;
// an equivalent real check uses crypto.timingSafeEqual over equal-length
// buffers. Note this is the processor's own gate — the application's
// authorization for these operations lives in the API service, where refunds
// additionally require an authenticated `customer_service` role and are capped
// against the order total (see api/src/routes/cs.js).
function requireApiKey(req, res, next) {
  const header = req.headers.authorization || '';
  const key = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (key !== API_KEY) return res.status(401).json({ error: 'Invalid FauxPay API key' });
  next();
}

function detectBrand(cardNumber) {
  if (/^4/.test(cardNumber)) return 'visa';
  if (/^5[1-5]/.test(cardNumber)) return 'mastercard';
  return 'unknown';
}

// Unauthenticated by design: tokenization is the one processor call a browser
// makes, so it cannot carry a merchant secret. Real processors gate it with a
// publishable key and defend it with per-account rate limiting and fraud
// scoring; this training stub has neither, and the token Map below has no TTL
// or size bound. Both are acceptable only because this container is disposable
// and holds no real card data.
//
// TRAINING TOPOLOGY: the SPA reaches this endpoint at same-origin
// `/fauxpay/tokenize`, which the web tier's nginx forwards here (web/nginx.conf).
// That means card data DOES pass through infrastructure we operate — contrary to
// what an earlier version of this comment claimed. It is tolerable here because
// the numbers are test cards.
//
// PRODUCTION TOPOLOGY: no such proxy is deployed. The browser loads the
// processor's own JS SDK and posts card data directly to the processor's domain,
// so the PAN never reaches our nginx, our containers, or our logs. That is what
// keeps the web tier out of the cardholder data environment and the assessment
// at SAQ A; proxying tokenization through our own origin would pull nginx into
// scope (SAQ A-EP/D) and put PANs one access-log change away from disk.
app.post('/tokenize', (req, res) => {
  const { card_number, exp_month, exp_year, cvv } = req.body || {};
  if (!card_number || !exp_month || !exp_year || !cvv) {
    return res.status(400).json({ error: 'card_number, exp_month, exp_year, and cvv are required' });
  }
  if (!/^\d{13,19}$/.test(card_number)) {
    return res.status(400).json({ error: 'Invalid card number' });
  }

  const token = `tok_${crypto.randomBytes(16).toString('hex')}`;
  tokens.set(token, { last4: card_number.slice(-4), brand: detectBrand(card_number) });
  res.status(201).json({ card_token: token });
});

app.post('/charge', requireApiKey, (req, res) => {
  const { card_token, amount_cents, order_id } = req.body || {};
  const card = tokens.get(card_token);
  if (!card) return res.status(400).json({ error: 'Unknown card_token' });
  if (!Number.isInteger(amount_cents) || amount_cents < 1) {
    return res.status(400).json({ error: 'amount_cents must be a positive integer' });
  }

  const transactionId = `txn_${crypto.randomBytes(16).toString('hex')}`;
  transactions.set(transactionId, { amount_cents, refunded_cents: 0, order_id });

  res.status(201).json({
    transaction_id: transactionId,
    status: 'captured',
    last4: card.last4,
    brand: card.brand,
  });
});

app.post('/refund', requireApiKey, (req, res) => {
  const { transaction_id, amount_cents } = req.body || {};
  const txn = transactions.get(transaction_id);
  if (!txn) return res.status(404).json({ error: 'Unknown transaction_id' });
  if (!Number.isInteger(amount_cents) || amount_cents < 1) {
    return res.status(400).json({ error: 'amount_cents must be a positive integer' });
  }
  if (txn.refunded_cents + amount_cents > txn.amount_cents) {
    return res.status(400).json({ error: 'Refund amount exceeds original charge' });
  }

  txn.refunded_cents += amount_cents;
  const refundId = `re_${crypto.randomBytes(16).toString('hex')}`;
  res.status(201).json({ refund_id: refundId, status: 'succeeded' });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

https
  .createServer(
    {
      cert: fs.readFileSync(TLS_CERT_PATH),
      key: fs.readFileSync(TLS_KEY_PATH),
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2',
    },
    app
  )
  .listen(PORT, () => console.log(`fauxpay listening on port ${PORT} (https, TLS 1.2)`));
