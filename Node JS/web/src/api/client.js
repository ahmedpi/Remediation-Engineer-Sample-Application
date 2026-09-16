// FauxPay is a fictional payment processor that exists only in this training
// environment. It is reached through the same-origin `/fauxpay` proxy path (see
// web/nginx.conf and vite.config.js) so the demo runs from a single published
// port with no CORS setup.
//
// In production this constant does not exist. The browser loads the real
// processor's JS SDK (e.g. Stripe.js) and posts card data directly to the
// processor's own domain with a publishable key, so no processor traffic passes
// through our web tier at all.
const FAUXPAY_BASE_URL = '/fauxpay';

// The access token is held in memory only. It is deliberately not written to
// localStorage or sessionStorage: anything stored there is readable by any
// script on the origin, so a single XSS flaw would hand over a usable token.
// Surviving a page reload is the refresh cookie's job instead — it is httpOnly,
// so script cannot read it, and the first API call after a reload exchanges it
// for a new access token (see request() below).
let authToken = null;

let sessionEnded = false;

export function setToken(token) {
  authToken = token;
  // A null token means there is no session to resume, so stop trying to
  // refresh until a real login supplies one again.
  sessionEnded = !token;
}

// Access tokens live 15 minutes, so expiry is a normal event rather than an
// error. Both the reload case (no token in memory) and the expiry case (401)
// are handled by exchanging the httpOnly refresh cookie for a new token.
//
// `sessionEnded` stops an anonymous visitor from firing a doomed refresh on
// every request: once one fails, we do not ask again until a login succeeds.
let refreshInflight = null;

function refreshSession() {
  if (!refreshInflight) {
    refreshInflight = fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' })
      .then(async (res) => {
        if (!res.ok) throw new Error('Session expired');
        const data = await res.json();
        setToken(data.token);
        return data;
      })
      .catch((err) => {
        setToken(null);
        throw err;
      })
      .finally(() => {
        refreshInflight = null;
      });
  }
  return refreshInflight;
}

function send(path, { method, body }) {
  const headers = { 'Content-Type': 'application/json' };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;

  return fetch(`/api${path}`, {
    method,
    headers,
    credentials: 'include',
    body: body ? JSON.stringify(body) : undefined,
  });
}

async function request(path, { method = 'GET', body } = {}) {
  // Auth routes carry no access token and must never recurse into a refresh.
  const canRefresh = !path.startsWith('/auth/');

  // After a reload the token is gone but the refresh cookie may still be good,
  // so resume the session before the call rather than spending a certain 401
  // on it. Failure here just means the caller is anonymous; public routes like
  // the catalog still work, and protected ones return their own 401 below.
  if (!authToken && canRefresh && !sessionEnded) {
    await refreshSession().catch(() => {});
  }

  let res = await send(path, { method, body });

  if (res.status === 401 && canRefresh && !sessionEnded) {
    try {
      await refreshSession();
    } catch {
      throw new Error('Your session has expired. Please sign in again.');
    }
    res = await send(path, { method, body });
  }

  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(data?.error || `Request failed with status ${res.status}`);
  }
  return data;
}

export const api = {
  register: (payload) => request('/auth/register', { method: 'POST', body: payload }),
  login: (payload) => request('/auth/login', { method: 'POST', body: payload }),
  logout: () => request('/auth/logout', { method: 'POST' }),
  refresh: () => refreshSession(),
  me: () => request('/users/me'),
  addresses: () => request('/users/me/addresses'),
  addAddress: (payload) => request('/users/me/addresses', { method: 'POST', body: payload }),

  widgets: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/widgets${qs ? `?${qs}` : ''}`);
  },
  categories: () => request('/categories'),

  widgetReviews: (widgetId) => request(`/widgets/${widgetId}/reviews`),
  addReview: (widgetId, payload) => request(`/widgets/${widgetId}/reviews`, { method: 'POST', body: payload }),
  updateReview: (reviewId, payload) => request(`/reviews/${reviewId}`, { method: 'PATCH', body: payload }),
  deleteReview: (reviewId) => request(`/reviews/${reviewId}`, { method: 'DELETE' }),
  adminDeleteReview: (reviewId) => request(`/admin/reviews/${reviewId}`, { method: 'DELETE' }),

  cart: () => request('/cart'),
  addToCart: (widget_id, quantity) => request('/cart/items', { method: 'POST', body: { widget_id, quantity } }),
  updateCartItem: (itemId, quantity) => request(`/cart/items/${itemId}`, { method: 'PATCH', body: { quantity } }),
  removeCartItem: (itemId) => request(`/cart/items/${itemId}`, { method: 'DELETE' }),

  checkout: (payload) => request('/orders', { method: 'POST', body: payload }),
  orders: () => request('/orders'),
  order: (id) => request(`/orders/${id}`),

  adminCreateWidget: (payload) => request('/admin/widgets', { method: 'POST', body: payload }),
  adminUpdateWidget: (id, payload) => request(`/admin/widgets/${id}`, { method: 'PATCH', body: payload }),
  adminDeactivateWidget: (id) => request(`/admin/widgets/${id}`, { method: 'DELETE' }),
  adminOrders: () => request('/admin/orders'),

  csOrders: (email) => request(`/cs/orders${email ? `?email=${encodeURIComponent(email)}` : ''}`),
  csOrder: (id) => request(`/cs/orders/${id}`),
  csRefund: (orderId, payload) => request(`/cs/orders/${orderId}/refunds`, { method: 'POST', body: payload }),
  csExchange: (orderId, payload) => request(`/cs/orders/${orderId}/exchanges`, { method: 'POST', body: payload }),
};

// Exchanges card details for a single-use token so the rest of checkout only
// ever handles the token (see Checkout.jsx -> api.checkout).
//
// TRAINING: this POST goes to same-origin `/fauxpay/tokenize`, so the card
// number travels through our own nginx before reaching the FauxPay container.
// Only test cards are ever entered here.
//
// PRODUCTION: this function is replaced by the processor's SDK, which collects
// card details in an iframe hosted on the processor's domain and tokenizes them
// against the processor directly. Our origin never sees the PAN, which is the
// whole point — it keeps cardholder data out of our infrastructure and out of
// PCI scope for the web tier.
export async function tokenizeCard({ card_number, exp_month, exp_year, cvv }) {
  const res = await fetch(`${FAUXPAY_BASE_URL}/tokenize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ card_number, exp_month, exp_year, cvv }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Card tokenization failed');
  return data.card_token;
}
