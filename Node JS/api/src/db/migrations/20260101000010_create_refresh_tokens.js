exports.up = function (knex) {
  return knex.schema.createTable('refresh_tokens', (table) => {
    table.increments('id').primary();
    table.integer('user_id').unsigned().notNullable().references('id').inTable('users').onDelete('CASCADE');
    // Only the SHA-256 of the refresh token is stored, so a dump of this table
    // does not hand an attacker usable sessions.
    table.string('token_hash').notNullable().unique();
    table.timestamp('expires_at').notNullable();
    table.timestamp('revoked_at');
    // Set when a token is rotated, so a replay of the consumed token can be
    // traced to the family it belonged to.
    table.integer('replaced_by').unsigned().references('id').inTable('refresh_tokens').onDelete('SET NULL');
    table.timestamp('created_at').defaultTo(knex.fn.now());
    table.index(['user_id']);
  });
};

exports.down = function (knex) {
  return knex.schema.dropTableIfExists('refresh_tokens');
};
