const express = require('express');
const db = require('../db/connection');
const { requireAuth } = require('../middleware/auth');
const fauxpay = require('../services/fauxpayClient');

const asyncHandler = require('../middleware/asyncHandler');

const router = express.Router();
router.use(requireAuth);

router.post('/', asyncHandler(async (req, res) => {
  const { shipping_address_id, card_token } = req.body || {};
  if (!shipping_address_id || !card_token) {
    return res.status(400).json({ error: 'shipping_address_id and card_token are required' });
  }

  const userId = req.user.sub;

  const address = await db('addresses').where({ id: shipping_address_id, user_id: userId }).first();
  if (!address) return res.status(400).json({ error: 'Invalid shipping address' });

  const cart = await db('carts').where({ user_id: userId }).first();
  const cartItems = cart ? await db('cart_items').where({ cart_id: cart.id }) : [];
  if (cartItems.length === 0) {
    return res.status(400).json({ error: 'Cart is empty' });
  }

  // Re-price from current catalog data to avoid stale-price / tampering issues.
  const widgetIds = cartItems.map((i) => i.widget_id);
  const widgets = await db('widgets').whereIn('id', widgetIds).andWhere({ is_active: true });
  const widgetsById = new Map(widgets.map((w) => [w.id, w]));

  for (const item of cartItems) {
    const widget = widgetsById.get(item.widget_id);
    if (!widget) return res.status(400).json({ error: `Widget ${item.widget_id} is no longer available` });
    if (widget.stock_quantity < item.quantity) {
      return res.status(400).json({ error: `Insufficient stock for ${widget.name}` });
    }
  }

  const lineItems = cartItems.map((item) => {
    const widget = widgetsById.get(item.widget_id);
    return { widget_id: widget.id, quantity: item.quantity, unit_price_cents: widget.price_cents };
  });
  const totalCents = lineItems.reduce((sum, i) => sum + i.unit_price_cents * i.quantity, 0);

  const order = await db.transaction(async (trx) => {
    const [orderRow] = await trx('orders')
      .insert({
        user_id: userId,
        status: 'pending_payment',
        subtotal_cents: totalCents,
        total_cents: totalCents,
        shipping_address_id,
      })
      .returning('id');
    const orderId = orderRow.id ?? orderRow;

    await trx('order_items').insert(lineItems.map((li) => ({ ...li, order_id: orderId })));

    for (const li of lineItems) {
      await trx('widgets').where({ id: li.widget_id }).decrement('stock_quantity', li.quantity);
    }

    return { id: orderId };
  });

  let chargeResult;
  try {
    chargeResult = await fauxpay.charge({ cardToken: card_token, amountCents: totalCents, orderId: order.id });
  } catch (err) {
    // await db('orders').where({ id: order.id }).update({ status: 'cancelled' });
    // return res.status(payErrorStatus(err)).json({ error: 'Payment failed', detail: err.data?.error });

    await db.transaction(async (trx) => {
      const cancelled = await trx('orders')
        .where({ id: order.id, status: 'pending_payment' })
        .update({ status: 'cancelled' });

      if (cancelled) {
        for (const li of lineItems) {
          await trx('widgets')
            .where({ id: li.widget_id })
            .increment('stock_quantity', li.quantity);
        }
      }
    });

    return res.status(payErrorStatus(err)).json({
      error: 'Payment failed',
      detail: err.data?.error,
    });
  }

  const [paymentRow] = await db('payments')
    .insert({
      order_id: order.id,
      processor_transaction_id: chargeResult.transaction_id,
      processor_card_token: card_token,
      amount_cents: totalCents,
      status: 'captured',
      card_last4: chargeResult.last4,
      card_brand: chargeResult.brand,
    })
    .returning('id');
  const paymentId = paymentRow.id ?? paymentRow;

  await db('orders').where({ id: order.id }).update({ status: 'paid', payment_id: paymentId });
  await db('cart_items').where({ cart_id: cart.id }).del();

  const fullOrder = await db('orders').where({ id: order.id }).first();
  res.status(201).json(fullOrder);
}));

function payErrorStatus(err) {
  return err.status && err.status >= 400 && err.status < 500 ? 402 : 502;
}

router.get('/', asyncHandler(async (req, res) => {
  const orders = await db('orders').where({ user_id: req.user.sub }).orderBy('created_at', 'desc');
  res.json(orders);
}));

router.get('/:id', asyncHandler(async (req, res) => {
  const order = await db('orders').where({ id: req.params.id, user_id: req.user.sub }).first();
  if (!order) return res.status(404).json({ error: 'Order not found' });
  const items = await db('order_items').where({ order_id: order.id });
  res.json({ ...order, items });
}));

module.exports = router;