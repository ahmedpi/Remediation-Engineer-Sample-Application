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

let authToken = localStorage.getItem('token');

export function setToken(token) {
  authToken = token;
  if (token) {
    localStorage.setItem('token', token);
  } else {
    localStorage.removeItem('token');
  }
}

async function request(path, { method = 'GET', body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;

  const res = await fetch(`/api${path}`, {
    method,
    headers,
    credentials: 'include',
    body: body ? JSON.stringify(body) : undefined,
  });

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
