const test = require('node:test');
const assert = require('node:assert/strict');
const db = require('../src/db/connection');

test.after(async () => {
  await db.destroy();
});

const API_URL = 'http://localhost:3000';

async function request(path, options = {}) {
  const response = await fetch(`${API_URL}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}),
    },
    method: options.method || 'GET',
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const data = await response.json().catch(() => null);
  return { response, data };
}

test('failed payment does not consume inventory', async () => {
  const email = `payment-failure-${Date.now()}@example.test`;
  const password = 'TestPassword123!';

  const registration = await request('/api/auth/register', {
    method: 'POST',
    body: {
      email,
      password,
      full_name: 'Payment Failure Test',
    },
  });

  assert.equal(registration.response.status, 201);
  const token = registration.data.token;
  const userId = registration.data.user.id;

  const address = await request('/api/users/me/addresses', {
    method: 'POST',
    token,
    body: {
      line1: '1 Test Street',
      city: 'Testville',
      state: 'TS',
      postal_code: '12345',
      country: 'US',
    },
  });

  assert.equal(address.response.status, 201);

  const widgets = await request('/api/widgets');
  assert.equal(widgets.response.status, 200);
  assert.ok(widgets.data.length > 0);

  const widget = widgets.data[0];
  const stockBefore = widget.stock_quantity;

  const cartItem = await request('/api/cart/items', {
    method: 'POST',
    token,
    body: {
      widget_id: widget.id,
      quantity: 1,
    },
  });

  assert.equal(cartItem.response.status, 201);

  const order = await request('/api/orders', {
    method: 'POST',
    token,
    body: {
      shipping_address_id: address.data.id,
      card_token: 'invalid-baseline-token',
    },
  });

  assert.equal(order.response.status, 402);
  assert.equal(order.data.error, 'Payment failed');

  const orderRow = await db('orders')
    .where({ user_id: userId })
    .orderBy('id', 'desc')
    .first();

  assert.equal(orderRow.status, 'cancelled');

  const widgetAfter = await db('widgets')
    .where({ id: widget.id })
    .first();

  assert.equal(widgetAfter.stock_quantity, stockBefore);
});