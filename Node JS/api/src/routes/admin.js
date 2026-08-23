const express = require('express');
const db = require('../db/connection');
const { requireAuth, requireRole } = require('../middleware/auth');

const asyncHandler = require('../middleware/asyncHandler');

const router = express.Router();
router.use(requireAuth, requireRole('admin'));

router.post('/widgets', asyncHandler(async (req, res) => {
  const { sku, name, description, price_cents, stock_quantity, category_id, image_url } = req.body || {};
  if (!sku || !name || !Number.isInteger(price_cents) || price_cents < 0) {
    return res.status(400).json({ error: 'sku, name, and a non-negative integer price_cents are required' });
  }

  const [row] = await db('widgets')
    .insert({
      sku,
      name,
      description,
      price_cents,
      stock_quantity: stock_quantity ?? 0,
      category_id,
      image_url,
      created_by: req.user.sub,
      updated_by: req.user.sub,
    })
    .returning('id');
  const widget = await db('widgets').where({ id: row.id ?? row }).first();
  res.status(201).json(widget);
}));

router.patch('/widgets/:id', asyncHandler(async (req, res) => {
  const allowed = ['name', 'description', 'price_cents', 'stock_quantity', 'category_id', 'image_url', 'is_active'];
  const updates = {};
  for (const key of allowed) {
    if (req.body && Object.prototype.hasOwnProperty.call(req.body, key)) updates[key] = req.body[key];
  }
  if (Object.prototype.hasOwnProperty.call(updates, 'price_cents')) {
    if (!Number.isInteger(updates.price_cents) || updates.price_cents < 0) {
      return res.status(400).json({ error: 'price_cents must be a non-negative integer' });
    }
  }
  updates.updated_by = req.user.sub;
  updates.updated_at = db.fn.now();

  const updated = await db('widgets').where({ id: req.params.id }).update(updates);
  if (!updated) return res.status(404).json({ error: 'Widget not found' });
  res.json(await db('widgets').where({ id: req.params.id }).first());
}));

router.delete('/widgets/:id', asyncHandler(async (req, res) => {
  const updated = await db('widgets').where({ id: req.params.id }).update({ is_active: false, updated_by: req.user.sub });
  if (!updated) return res.status(404).json({ error: 'Widget not found' });
  res.status(204).end();
}));

router.post('/categories', asyncHandler(async (req, res) => {
  const { name } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });
  const [row] = await db('categories').insert({ name }).returning('id');
  res.status(201).json({ id: row.id ?? row, name });
}));

router.get('/orders', asyncHandler(async (req, res) => {
  const orders = await db('orders').orderBy('created_at', 'desc');
  res.json(orders);
}));

router.patch('/users/:id/role', asyncHandler(async (req, res) => {
  const { role } = req.body || {};
  if (!['customer', 'admin', 'customer_service'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  const updated = await db('users').where({ id: req.params.id }).update({ role });
  if (!updated) return res.status(404).json({ error: 'User not found' });
  res.json(await db('users').where({ id: req.params.id }).select('id', 'email', 'full_name', 'role').first());
}));

router.delete('/reviews/:id', asyncHandler(async (req, res) => {
  const deleted = await db('reviews').where({ id: req.params.id }).del();
  if (!deleted) return res.status(404).json({ error: 'Review not found' });
  res.status(204).end();
}));

module.exports = router;
