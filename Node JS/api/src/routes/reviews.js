const express = require('express');
const db = require('../db/connection');
const { requireAuth } = require('../middleware/auth');

const asyncHandler = require('../middleware/asyncHandler');

const router = express.Router();

router.get('/widgets/:id/reviews', asyncHandler(async (req, res) => {
  const reviews = await db('reviews')
    .join('users', 'users.id', 'reviews.user_id')
    .where({ widget_id: req.params.id })
    .orderBy('reviews.created_at', 'desc')
    .select('reviews.id', 'reviews.rating', 'reviews.body', 'reviews.created_at', 'reviews.updated_at', 'reviews.user_id', 'users.full_name');

  const { avg_rating, review_count } = await db('reviews')
    .where({ widget_id: req.params.id })
    .avg({ avg_rating: 'rating' })
    .count({ review_count: '*' })
    .first();

  res.json({ reviews, average_rating: avg_rating ? Number(avg_rating) : null, review_count: Number(review_count) });
}));

router.post('/widgets/:id/reviews', requireAuth, asyncHandler(async (req, res) => {
  const { rating, body } = req.body || {};
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'rating must be an integer between 1 and 5' });
  }

  const userId = req.user.sub;
  const widgetId = req.params.id;

  const orderItem = await db('order_items')
    .join('orders', 'orders.id', 'order_items.order_id')
    .where({ 'order_items.widget_id': widgetId, 'orders.user_id': userId, 'orders.status': 'paid' })
    .select('order_items.id')
    .first();
  if (!orderItem) return res.status(403).json({ error: 'A verified purchase of this widget is required to review it' });

  const existing = await db('reviews').where({ user_id: userId, widget_id: widgetId }).first();
  if (existing) return res.status(409).json({ error: 'You have already reviewed this widget' });

  const [row] = await db('reviews')
    .insert({ user_id: userId, widget_id: widgetId, order_item_id: orderItem.id, rating, body })
    .returning('id');
  const review = await db('reviews').where({ id: row.id ?? row }).first();
  res.status(201).json(review);
}));

router.patch('/reviews/:id', requireAuth, asyncHandler(async (req, res) => {
  const review = await db('reviews').where({ id: req.params.id }).first();
  if (!review) return res.status(404).json({ error: 'Review not found' });
  if (review.user_id !== req.user.sub) return res.status(403).json({ error: 'Forbidden' });

  const updates = {};
  if (req.body && Object.prototype.hasOwnProperty.call(req.body, 'rating')) {
    const { rating } = req.body;
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'rating must be an integer between 1 and 5' });
    }
    updates.rating = rating;
  }
  if (req.body && Object.prototype.hasOwnProperty.call(req.body, 'body')) {
    updates.body = req.body.body;
  }
  updates.updated_at = db.fn.now();

  await db('reviews').where({ id: req.params.id }).update(updates);
  res.json(await db('reviews').where({ id: req.params.id }).first());
}));

router.delete('/reviews/:id', requireAuth, asyncHandler(async (req, res) => {
  const review = await db('reviews').where({ id: req.params.id }).first();
  if (!review) return res.status(404).json({ error: 'Review not found' });
  if (review.user_id !== req.user.sub) return res.status(403).json({ error: 'Forbidden' });

  await db('reviews').where({ id: req.params.id }).del();
  res.status(204).end();
}));

module.exports = router;
