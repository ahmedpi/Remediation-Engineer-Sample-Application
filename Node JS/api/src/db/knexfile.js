require('dotenv').config();

module.exports = {
  client: 'pg',
  connection: {
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT || 5432),
    database: process.env.DB_NAME || 'widgetshop',
    user: process.env.DB_USER || 'widgetshop',
    // Credentials for the account that owns the whole schema — users and
    // password hashes, orders, payments, refunds — reachable with none of the
    // application's authorization in the way.
    //
    // TRAINING: the fallbacks below are working values, so `docker compose up`
    // and `npm run migrate` need no setup. The password also sits in the
    // committed .env placeholder, so treat it as public. Tolerable only because
    // this database holds seed data in a disposable container.
    //
    // PRODUCTION: these placeholders do not survive into production. The
    // password is a long random secret held in a secrets manager (Vault / AWS
    // Secrets Manager) or issued dynamically per instance, injected at runtime,
    // unique per environment, and rotated on a schedule; the role it belongs to
    // is least-privilege rather than the schema owner. Production config carries
    // no `||` default for any of this — an unset credential must fail the
    // connection loudly instead of silently trying a guessable one.
    password: process.env.DB_PASSWORD || 'widgetshop',
  },
  migrations: {
    directory: __dirname + '/migrations',
  },
  seeds: {
    directory: __dirname + '/seeds',
  },
};
