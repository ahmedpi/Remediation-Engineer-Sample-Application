# Widget Shop

Sample e-commerce app scaffolded from [`../DESIGN.md`](../DESIGN.md): a React SPA, an Express API, a Postgres database, and a fictional payment processor ("FauxPay"), all run via Docker Compose.

## Run it

```bash
cp .env.example .env
docker compose up --build
```

Then open http://localhost:8080.

The `migrate` service runs schema migrations before `api` starts. To load sample data (an admin, a CS agent, and two widgets — see `api/src/db/seeds`):

```bash
docker compose run --rm api npm run seed
```

Seeded accounts (password `ChangeMe123!`):
- `admin@widgetshop.test` (admin)
- `support@widgetshop.test` (customer service)

If you built images before pulling the latest `master`, rebuild rather than just restarting — `docker compose up --build` — so the `web` and `api` images pick up dependency and source changes; a plain `up` reuses stale images.

## Structure

- `api/` — Express REST API, Knex migrations/seeds, FauxPay client
- `web/` — Vite + React SPA, served by nginx in production (proxies `/api` and `/fauxpay`)
- `fauxpay/` — fictional payment processor mock (tokenize/charge/refund)
- `docker-compose.yml` — wires the above together with Postgres

## Local (non-Docker) development

Each of `api/`, `web/`, and `fauxpay/` is a standalone `npm` project — `npm install && npm run dev` in each, with a local Postgres instance and matching `.env` values for `api`.
