exports.up = function (knex) {
  return knex.schema.createTable('reviews', (table) => {
    table.increments('id').primary();
    table.integer('user_id').unsigned().notNullable().references('id').inTable('users');
    table.integer('widget_id').unsigned().notNullable().references('id').inTable('widgets');
    table.integer('order_item_id').unsigned().notNullable().references('id').inTable('order_items');
    table.integer('rating').notNullable();
    table.text('body');
    table.timestamp('created_at').defaultTo(knex.fn.now());
    table.timestamp('updated_at').defaultTo(knex.fn.now());
    table.unique(['user_id', 'widget_id']);
  });
};

exports.down = function (knex) {
  return knex.schema.dropTableIfExists('reviews');
};
