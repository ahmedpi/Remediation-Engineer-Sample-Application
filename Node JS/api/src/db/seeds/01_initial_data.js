const bcrypt = require('bcryptjs');

exports.seed = async function (knex) {
  await knex('cart_items').del();
  await knex('carts').del();
  await knex('order_items').del();
  await knex('refunds').del();
  await knex('exchanges').del();
  await knex('payments').del();
  await knex('orders').del();
  await knex('widgets').del();
  await knex('categories').del();
  await knex('addresses').del();
  await knex('users').del();

  // TESTING VALUE ONLY — this seed and its fixed admin/CS credentials exist so the
  // training stack boots with sample data and no setup. They do not survive into
  // production, where staff accounts are provisioned through an admin invite flow
  // with a one-time, expiring credential, never a committed password shared across
  // every environment. This seed itself is not run against a production database.
  const passwordHash = await bcrypt.hash('ChangeMe123!', 10);

  const [adminId, csId] = await knex('users')
    .insert([
      { email: 'admin@widgetshop.test', password_hash: passwordHash, full_name: 'Default Admin', role: 'admin' },
      { email: 'support@widgetshop.test', password_hash: passwordHash, full_name: 'Default CS Agent', role: 'customer_service' },
    ])
    .returning('id')
    .then((rows) => rows.map((r) => r.id ?? r));

  const [gadgetsId, gizmosId] = await knex('categories')
    .insert([{ name: 'Gadgets' }, { name: 'Gizmos' }])
    .returning('id')
    .then((rows) => rows.map((r) => r.id ?? r));

  await knex('widgets').insert([
    {
      sku: 'WID-001',
      name: 'Standard Widget',
      description: 'A perfectly ordinary widget.',
      price_cents: 999,
      stock_quantity: 100,
      category_id: gadgetsId,
      created_by: adminId,
      updated_by: adminId,
    },
    {
      sku: 'WID-002',
      name: 'Deluxe Widget',
      description: 'A widget with extra sparkle.',
      price_cents: 2499,
      stock_quantity: 50,
      category_id: gizmosId,
      created_by: adminId,
      updated_by: adminId,
    },
  ]);

  // eslint-disable-next-line no-unused-vars
  void csId;
};
