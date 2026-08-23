# Widget Shop — Design & Requirements

## 1. Overview

Widget Shop is a small e-commerce application. It lets customers register, browse a catalog of widgets, add items to a cart, and check out with a credit card processed by a **third-party external payment processor** (e.g. a Stripe-style gateway). Backend admins manage the catalog and pricing; a customer service role handles refunds and exchanges.

The app is a **Single Page Application (SPA)** frontend backed by a **REST API**, with a **SQL database** for persistence, and is deployed as a set of **Docker containers**.

---

## 2. Goals / Non-Goals

**Goals**

- Small-scope e-commerce app: auth, catalog, cart, checkout, order history, refunds/exchanges.
- Customers who have purchased a widget can rate and review it, to help other shoppers evaluate the catalog.
- Clear separation of roles: Customer, Admin, Customer Service.
- Simple enough to reason about end-to-end (schema, API, UI).
- Integration with a real external payment processor's API surface (tokenization, charge, refund).

**Non-Goals**

- No PCI compliance program to build/audit ourselves — card data is tokenized directly with the processor, minimizing our PCI scope.
- No multi-tenancy, internationalization, tax calculation, or shipping-carrier integration.
- No high-availability / multi-region scaling in this phase — a single-region deployment is sufficient for current business volume.

---

## 3. Tech Stack

| Layer       | Choice                                                                                                                                                                               |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Frontend    | SPA (React or similar), calling the backend via JSON REST API                                                                                                                        |
| API Gateway | Single public entry point in front of `web` and `api` (§3.3): TLS termination, rate limiting, JWT authN/token validation                                                             |
| Backend     | Node.js API server (e.g. Express)                                                                                                                                                    |
| Database    | SQL (PostgreSQL or SQLite for local/dev) via an ORM/query builder                                                                                                                    |
| Auth        | Short-lived JWT access tokens (held in-memory client-side) + rotating opaque refresh tokens in an `HttpOnly`/`Secure`/`SameSite` cookie (see §3.2); password hashing (bcrypt/argon2) |
| Email       | Transactional email provider (SMTP relay or API), used to deliver password-reset links                                                                                               |
| Payments    | External payment processor (e.g. Stripe-style gateway), accessed over HTTPS via a thin client module                                                                                 |
| Deployment  | Docker containers, orchestrated via Docker Compose                                                                                                                                   |

---

## 3.1 Architecture Diagram

The following diagram reflects the containers described in §3 and §11: a browser-hosted SPA, an API Gateway fronting the API, an API server backed by a SQL database, and a third-party payment processor that lives outside our infrastructure. All client traffic to our backend passes through the gateway; the SPA talks to the processor directly for tokenization, and the API talks to it server-to-server for charges/refunds.

```mermaid
flowchart TB
    clients["Clients\n(Guest, Customer, Admin, Customer Service)"]

    subgraph dockerhost["Docker Compose Environment (our infrastructure)"]
        gateway["gateway container\nAPI Gateway: TLS termination,\nrate limiting, JWT authN/token validation"]
        spa["web container\nSPA (React), static build served via nginx"]
        api["api container\nREST API (Node.js / Express), business logic + authZ"]
        db[("db container\nSQL Database, PostgreSQL")]
        migrate["migrate (one-shot)\nruns schema migrations/seed"]
    end

    processor["Payment Processor\n(external third-party gateway,\ne.g. Stripe-style)"]

    clients -->|HTTPS| gateway

    gateway -->|"static assets"| spa
    gateway -->|"JSON REST API, rate limited +\nJWT validated (auth, catalog, cart, orders)"| api
    spa -->|"POST /tokenize\n(card details, direct from browser)"| processor

    api -->|"parameterized SQL"| db
    api -->|"POST /charge, POST /refund\n(server-to-server, over the internet)"| processor

    migrate -->|"schema migrations"| db
    migrate -.->|"must complete before api serves traffic"| api

    style processor fill:#fee,stroke:#900
    style db fill:#eef,stroke:#339
    style gateway fill:#ffe,stroke:#960
```

Key architectural points from this document:

- The **API Gateway is the sole public entry point** into our infrastructure (besides the payment processor's direct browser calls) — it terminates TLS, rate-limits requests, and validates the JWT access token before anything reaches `api` (§3.3). `api` and `web` are never directly reachable by clients (§11.2).
- The SPA never routes raw card data through the API (§6) — it goes browser → payment processor directly, returning only an opaque `card_token`.
- The payment processor is an **external system outside our trust boundary**, reached over the public internet — not a container we operate (§11.1).
- The API is the sole client of the database; the gateway enforces authentication (is this a valid token?) while the API enforces authorization (is this role allowed to do this?) (§4).
- `db` is not published to the host; only `api` can reach it (§11.2).
- `migrate` must complete before `api` accepts traffic (§11.4, §11.7.5).

---

## 3.2 Session & Token Security

Storing a JWT somewhere the client-side JavaScript can read it (`localStorage`, `sessionStorage`, or a non-`HttpOnly` cookie) means any successful XSS on the SPA can exfiltrate it — the token then works from anywhere, for as long as it's valid, with no way for the server to tell the difference from the real user. To close that off, the app splits authentication into two tokens with different exposure and lifetimes:

- **Access token**: a short-lived (e.g. 15 minute) JWT returned in the login/refresh response _body_. The SPA keeps it only in memory (a JS variable, scoped to the running tab) — never written to `localStorage`, `sessionStorage`, or any other persistent client-side store. It doesn't survive a page reload and isn't a standing target for exfiltration; even if it's read via XSS, its blast radius is capped at ~15 minutes.
- **Refresh token**: an opaque, random, single-use token delivered _exclusively_ via an `HttpOnly`, `Secure`, `SameSite=Strict` cookie. Because it's `HttpOnly`, injected JavaScript can never read it — the primary XSS token-theft vector doesn't apply to it. The server stores only a hash of it (`refresh_tokens`, see §5), never the plaintext.
- **Refresh & rotation**: `POST /api/auth/refresh` authenticates purely off the cookie (no token in the request body) and returns a new access token. Every refresh **rotates** the refresh token: the presented one is marked used and a new one is issued. If an already-used refresh token is ever presented again, that's a signal it was stolen and replayed — the server revokes the entire token family and forces re-login.
- **CSRF on the refresh endpoint**: since it's cookie-authenticated, `POST /api/auth/refresh` (and any other cookie-authenticated endpoint) additionally requires a custom header (e.g. `X-Requested-With`) that a cross-site form or `<img>`/`<form>` CSRF attempt cannot attach — defense in depth alongside `SameSite=Strict`.
- **Revocation**: wherever this document says a flow "invalidates the user's other active sessions" (§7.1a Forgot/Reset Password, §7.1b Change Password), that means revoking the corresponding rows in `refresh_tokens`. A stateless JWT access token can't be revoked before it expires on its own, so every session-termination guarantee in this document is backed by the refresh-token table, not the access token.
- **Defense in depth**: a strict Content-Security-Policy (no `unsafe-inline`, no `unsafe-eval`) is applied SPA-wide to reduce the underlying XSS risk in the first place — the token-handling design above is what limits the damage _if_ that's ever bypassed, not a substitute for it.
- **Where validation happens**: the API Gateway (§3.3) verifies the access token's signature and expiration on every request to a protected route, rejecting invalid or expired tokens before they reach `api`. That's authentication only — the gateway has no knowledge of the app's role model, so role-based authorization (§4) is still `api`'s responsibility.

---

## 3.3 API Gateway

All client traffic — page loads and API calls alike — enters through a single **API Gateway** (§3.1) in front of both the `web` and `api` containers; neither is reachable directly (§11.2). The gateway is responsible for:

- **TLS termination** and presenting one origin for the SPA and API — this is also what makes `SameSite` cookie enforcement on the refresh-token cookie (§3.2) meaningful rather than merely nominal.
- **Rate limiting**: per-IP (and, once authenticated, per-user) request limits, applied most aggressively to `/api/auth/*` routes (login, register, forgot-password) to slow down credential-stuffing and brute-force attacks — this is complementary to, not a replacement for, the account-lockout mechanism in §7.1c.
- **AuthN / token validation**: verifying the JWT access token's signature and expiration (§3.2) on every request to a non-public route, and rejecting invalid or expired tokens with `401` before they reach `api`. The verified caller identity (user id, role) is forwarded to `api` on an internal, trusted header, so `api` doesn't need to re-parse or re-verify the JWT itself — only read the identity and enforce role-based authorization (§4).

Public routes (catalog browsing, `register`, `login`, `forgot-password`) skip the token-validation step but are still rate-limited.

This can be a dedicated API gateway product (e.g. Kong, or a managed cloud gateway) or the same nginx/Traefik reverse proxy already terminating TLS, extended with a rate-limiting module and a JWT-validation module — the architectural requirement is the separation of concerns in front of `api`, not a specific product.

---

## 4. Roles & Permissions

| Role                      | Capabilities                                                                                                                                                                                    |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Guest**                 | Browse catalog, view widget details, register, log in                                                                                                                                           |
| **Customer**              | Everything Guest can do, plus: manage own profile/addresses, manage cart, checkout, view own order history, request a return/exchange, leave/edit/delete a rating & review on widgets they've purchased |
| **Admin**                 | Manage catalog (create/edit/delete widgets, set prices, manage inventory/stock), manage widget categories, view all orders (read-only), manage user role assignments, remove reviews that violate content policy |
| **Customer Service (CS)** | View all orders and customers, issue refunds (full/partial) against an order/payment, process exchanges (accept returned item, ship replacement / adjust order), add internal notes to an order |

Role checks are enforced **server-side** on every API endpoint — the SPA hides UI it shouldn't show, but the API is the actual authorization boundary. Authentication (is this a valid, unexpired token?) is enforced upstream by the API Gateway (§3.3) before a request ever reaches `api`; authorization (is this role allowed to do this?) is enforced by `api` itself, since that's the only place the role model lives.

Admin and CS accounts are internal/staff accounts, not self-service registrations — they're provisioned by an existing Admin.

---

## 5. Core Domain / Data Model

The full set of tables, columns, types, and foreign keys is captured in the ER diagrams below (§5.1–§5.3). A few business rules aren't visible from column names alone and are called out here:

- **`users.role`** defaults to `customer`; `admin` and `customer_service` are staff-provisioned (§4).
- **`widgets.is_active`** is a soft "delisting" flag — widgets are never hard-deleted.
- **Carts**: one active cart per user (or session for guests, if guest carts are supported — otherwise require login before cart use).
- **`cart_items.unit_price_cents`**: recommend **re-pricing at checkout** from `widgets.price_cents` rather than trusting a price snapshotted at add-time, to avoid stale-price abuse.
- **`order_items.unit_price_cents`** is immutable once set — it is the price at time of purchase and is never affected by later catalog price changes.
- **`password_reset_tokens`** are single-use and time-limited: a token is stored hashed (never plaintext), carries an `expires_at`, and is marked used (or deleted) the moment it's redeemed or superseded by a newer request.
- **`users.failed_login_attempts` / `locked_until`** implement account lockout: consecutive failed logins increment the counter; reaching a configured threshold sets `locked_until` (a cooldown period) and further login attempts are rejected until it elapses. A successful login resets the counter.
- **`refresh_tokens`** back the session/token-theft mitigations in §3.2: each row is a single-use, rotating refresh token stored hashed (never plaintext), with `expires_at` and `revoked_at`. Revoking a user's sessions (e.g. on password change) means setting `revoked_at` on their active rows here — the short-lived JWT access token itself is never persisted or revocable.
- **No table ever stores a full card number, CVV, or expiration date.** Only the processor's opaque token (`payments.processor_card_token`) and display metadata (`card_last4`, `card_brand`) are persisted, consistent with basic PCI-DSS scope reduction.
- **`reviews`**: one review per `(user_id, widget_id)` pair. A customer may only create a review for a widget they have a `paid` order containing (i.e. a verified purchase, tied to the specific `order_items` row) — this is enforced at write time, not just at UI-hint time. `rating` is an integer 1–5; `body` is free text, editable by its author, or removable by its author or an Admin.

The data model is presented as three diagrams grouped by domain — Users & Catalog, Orders & Fulfillment, and Auth & Session Security — so each stays focused and easy to read rather than one large, hard-to-follow schema. An entity referenced without its column list in a diagram below is shown there only to anchor a cross-diagram relationship; its full definition lives in the diagram where it's the primary subject.

### 5.1 Proposed ER Diagram — Users & Catalog

```mermaid
erDiagram
    USERS ||--o{ ADDRESSES : "owns"
    USERS ||--o{ CARTS : "owns"
    CATEGORIES ||--o{ WIDGETS : "categorizes"
    USERS ||--o{ WIDGETS : "created/updated by (admin)"
    CARTS ||--o{ CART_ITEMS : "contains"
    WIDGETS ||--o{ CART_ITEMS : "referenced by"
    USERS ||--o{ REVIEWS : "writes"
    WIDGETS ||--o{ REVIEWS : "reviewed by"
    ORDER_ITEMS ||--o| REVIEWS : "verified purchase for"

    USERS {
        id id PK "primary key"
        string email UK "login identifier"
        string password_hash "bcrypt/argon2 hash"
        string full_name "display name"
        enum role "customer, admin, customer_service"
        int failed_login_attempts "default 0"
        timestamp locked_until "nullable"
        timestamp created_at "account creation time"
    }

    ADDRESSES {
        id id PK "primary key"
        id user_id FK "owning user"
        string line1 "street address line 1"
        string line2 "street address line 2, optional"
        string city "city"
        string state "state/province"
        string postal_code "postal/zip code"
        string country "country"
        bool is_default_shipping "default shipping address flag"
        bool is_default_billing "default billing address flag"
    }

    CATEGORIES {
        id id PK "primary key"
        string name UK "category name"
    }

    WIDGETS {
        id id PK "primary key"
        string sku UK "stock keeping unit"
        string name "widget name"
        text description "widget description"
        int price_cents "current price, set by admin"
        string currency "default USD"
        int stock_quantity "units in stock"
        id category_id FK "nullable"
        string image_url "product image"
        bool is_active "soft delisting flag"
        id created_by FK "admin who created this widget"
        id updated_by FK "admin who last updated this widget"
        timestamp created_at "creation time"
        timestamp updated_at "last update time"
    }

    CARTS {
        id id PK "primary key"
        id user_id FK "cart owner"
    }

    CART_ITEMS {
        id id PK "primary key"
        id cart_id FK "parent cart"
        id widget_id FK "widget being purchased"
        int quantity "quantity requested"
        int unit_price_cents "re-priced at checkout"
    }

    REVIEWS {
        id id PK "primary key"
        id user_id FK "reviewing customer"
        id widget_id FK "widget being reviewed"
        id order_item_id FK "verified-purchase reference (see §5.2)"
        int rating "1-5 stars"
        text body "review text"
        timestamp created_at "review submitted time"
        timestamp updated_at "last edited time"
    }
```

### 5.2 Proposed ER Diagram — Orders & Fulfillment

```mermaid
erDiagram
    USERS ||--o{ ORDERS : "places"
    USERS ||--o{ REFUNDS : "issues (CS)"
    USERS ||--o{ EXCHANGES : "processes (CS)"
    ADDRESSES ||--o{ ORDERS : "ships to"
    ORDERS ||--o{ ORDER_ITEMS : "contains"
    WIDGETS ||--o{ ORDER_ITEMS : "referenced by"
    ORDERS ||--o| PAYMENTS : "paid via"
    PAYMENTS ||--o{ REFUNDS : "refunded via"
    ORDERS ||--o{ REFUNDS : "refunded on"
    ORDERS ||--o{ EXCHANGES : "exchanged on"
    WIDGETS ||--o{ EXCHANGES : "returned/replacement item"

    ORDERS {
        id id PK "primary key"
        id user_id FK "purchasing customer"
        enum status "pending_payment, paid, refunded, partially_refunded, exchange_pending, exchanged, cancelled"
        int subtotal_cents "sum of line items"
        int total_cents "subtotal plus any adjustments"
        id shipping_address_id FK "delivery address"
        id payment_id FK "associated payment"
        timestamp created_at "order placed time"
    }

    ORDER_ITEMS {
        id id PK "primary key"
        id order_id FK "parent order"
        id widget_id FK "widget purchased"
        int quantity "quantity purchased"
        int unit_price_cents "immutable, price at purchase time"
    }

    PAYMENTS {
        id id PK "primary key"
        id order_id FK "associated order"
        string processor_transaction_id "id returned by the payment processor"
        string processor_card_token "tokenized card reference, never raw PAN"
        int amount_cents "amount charged"
        enum status "authorized, captured, failed, refunded, partially_refunded"
        string card_last4 "display only, from processor response"
        string card_brand "display only, from processor response"
        timestamp created_at "charge time"
    }

    REFUNDS {
        id id PK "primary key"
        id order_id FK "refunded order"
        id payment_id FK "refunded payment"
        id issued_by FK "CS agent who issued the refund"
        int amount_cents "refund amount"
        text reason "reason for refund"
        string processor_refund_id "id returned by the payment processor"
        timestamp created_at "refund time"
    }

    EXCHANGES {
        id id PK "primary key"
        id order_id FK "original order"
        id processed_by FK "CS agent who processed the exchange"
        id returned_widget_id FK "item sent back"
        int returned_quantity "quantity returned"
        id replacement_widget_id FK "item shipped instead"
        int replacement_quantity "quantity shipped"
        enum status "requested, received, completed, rejected"
        text notes "internal notes"
        timestamp created_at "exchange requested time"
        timestamp updated_at "last status update time"
    }
```

### 5.3 Proposed ER Diagram — Auth & Session Security

The `password_reset_tokens` and `refresh_tokens` tables that back §3.2 and §7.1a/§7.1b are split out here rather than folded into §5.1/§5.2, both to keep those diagrams smaller and because they're conceptually about session/credential security rather than the commerce domain.

```mermaid
erDiagram
    USERS ||--o{ PASSWORD_RESET_TOKENS : "requests"
    USERS ||--o{ REFRESH_TOKENS : "authenticates via"

    PASSWORD_RESET_TOKENS {
        id id PK "primary key"
        id user_id FK "requesting user"
        string token_hash "hashed, never plaintext"
        timestamp expires_at "single-use, time-limited"
        timestamp used_at "nullable, set when redeemed"
        timestamp created_at "request time"
    }

    REFRESH_TOKENS {
        id id PK "primary key"
        id user_id FK "authenticated user"
        string token_hash "hashed, never plaintext"
        id replaced_by FK "nullable, points to rotated successor"
        timestamp expires_at "token expiry"
        timestamp revoked_at "nullable"
        timestamp created_at "issued time"
    }
```

Together, these three diagrams are a direct rendering of the tables and foreign keys defined above (§5); they do not introduce any structure not already specified there.

---

## 6. Payment Processor Integration

The application integrates with a **real, external, third-party payment processor** (e.g. a Stripe-style gateway) over HTTPS, accessed from the backend through an internal client module (`services/paymentClient.js` or similar). The integration surface:

- `POST /tokenize` — accepts card details **directly from the client-side SPA to the processor**, never through our backend, returning a `card_token`. (This mirrors real-world practice: our server never sees/touches raw PAN, minimizing our PCI scope.)
- `POST /charge` — backend calls with `{ card_token, amount_cents, currency, order_id }`, returns `{ transaction_id, status, last4, brand }`.
- `POST /refund` — backend calls with `{ transaction_id, amount_cents }`, returns `{ refund_id, status }`.

This integration surface is intentionally modeled on how real gateways work (client-side tokenization, server-side charge/refund) rather than being a bespoke protocol, so the app's behavior generalizes to whichever real processor a deployment chooses. See §10 for how this integration is tested without moving real money.

---

## 7. Key Flows

### 7.1 Registration / Login

1. Guest submits email/password (+ name) → server hashes password, creates `users` row with role `customer`.
2. Login validates credentials, then issues a short-lived JWT access token (returned in the response body) and a rotating refresh token (set as an `HttpOnly`/`Secure`/`SameSite` cookie) — see §3.2 for why the two tokens are handled differently. See §7.1c for the account-lockout behavior applied on repeated failures.

### 7.1a Forgot / Reset Password

1. Guest submits their email on a "forgot password" form.
2. Server looks up the user; regardless of whether a match is found, it returns the same generic response (to avoid leaking which emails are registered).
3. If a match is found, server generates a single-use, time-limited reset token, stores only its hash in `password_reset_tokens` (with `expires_at`), and emails a reset link containing the plaintext token to the user's registered email address via the transactional email provider.
4. User follows the link, submits a new password (+ the token from the link).
5. Server validates the token (exists, unexpired, unused), hashes the new password, updates `users.password_hash`, marks the token used, and revokes all of the user's `refresh_tokens` (§3.2) so any existing sessions — including one an attacker may have obtained — are logged out.

### 7.1b Change Password

1. Authenticated customer submits their current password and a new password from their account settings.
2. Server re-verifies the current password against `users.password_hash` before allowing the change (prevents a hijacked session with a stolen token/cookie, but no credentials, from silently taking over the account).
3. On success: server hashes and stores the new password, and revokes all of the user's `refresh_tokens` (§3.2) other than the one backing the current session.
4. On failure (current password incorrect): request rejected, password unchanged.

### 7.1c Account Lockout / Login

1. Login request arrives with email + password.
2. Server looks up the user and first checks `locked_until`: if it's set and still in the future, the request is rejected immediately (generic "account temporarily locked, try again later" response) — the password is not checked.
3. Otherwise, server verifies the password:
   - **Incorrect**: increment `failed_login_attempts`. If the new count reaches the configured threshold (e.g. 5), set `locked_until` to now + a cooldown window (e.g. 15 minutes). Respond with a generic "invalid email or password" error either way (the account-locked message is only shown once the threshold is actually hit, on that same response).
   - **Correct**: reset `failed_login_attempts` to 0, clear `locked_until`, issue an access token + refresh-token cookie as in §7.1/§3.2.

### 7.2 Browse Catalog

- Public endpoint lists active widgets, filterable by category, searchable by name; widget detail view shows description/price/stock.

### 7.2a Customer — Product Reviews

1. Authenticated customer opens a widget's detail page for a widget they have a `paid` order for, and submits a rating (1–5) and review text.
2. Server verifies the customer has at least one `order_items` row for that widget on a `paid` order, and that they don't already have a review on this widget; creates the `reviews` row referencing that `order_items` row.
3. A customer may edit or delete their own review at any time; editing updates `rating`/`body` and `updated_at`.
4. Admin can remove any review that violates content policy.
5. Guests and customers can view all reviews (rating, body, reviewing customer's display name, date) on the widget's detail page (§7.2), alongside the widget's average rating and review count.

### 7.3 Cart & Checkout

1. Authenticated customer adds/updates/removes items in their cart.
2. On checkout: customer supplies shipping address and card details (entered directly into a payment-processor-hosted field/component in the SPA → tokenized client-side).
3. SPA sends `card_token` + cart + shipping address to backend `POST /api/orders`.
4. Backend re-prices cart from current `widgets.price_cents`, creates `orders` (status `pending_payment`) + `order_items`, calls the payment processor `/charge`.
5. On success: create `payments` row, set order status `paid`, decrement `stock_quantity`, clear cart.
6. On failure: order marked failed/cancelled, customer notified, cart preserved.

### 7.4 Admin — Catalog Management

- Admin creates/edits widgets (name, description, price, stock, category, image, active flag).
- Price changes only affect future carts/orders (existing `order_items.unit_price_cents` are immutable history).

### 7.5 Customer Service — Refunds

1. CS looks up an order (by order id, customer email, etc.).
2. CS issues a full or partial refund with a reason.
3. Backend calls the payment processor `/refund` for `amount_cents` against the original `processor_transaction_id`.
4. On success: create `refunds` row, update `payments.status` and `orders.status` (`refunded`/`partially_refunded`).

### 7.6 Customer Service — Exchanges

1. Customer (or CS on their behalf) requests an exchange on a delivered order, specifying returned item(s) and desired replacement.
2. CS marks the return `received` once the item is physically back.
3. CS completes the exchange: system creates/updates the replacement shipment; if replacement price differs from returned item, CS issues a partial refund or requests an additional payment (via a new charge through the payment processor) to settle the difference.
4. Order/exchange status updated to `completed`.

---

## 7.7 Sequence Diagrams

Every SPA→API call shown below passes through the API Gateway first (TLS termination, rate limiting, JWT validation — §3.3). It's omitted from each diagram since it doesn't change the business-level flow being illustrated, and is shown once in the architecture diagram (§3.1).

### 7.7.1 Registration / Login (§7.1)

```mermaid
sequenceDiagram
    actor Guest
    participant SPA
    participant API
    participant DB

    Guest->>SPA: Enter email, password, name
    SPA->>API: POST /api/auth/register
    API->>API: Hash password (bcrypt/argon2)
    API->>DB: INSERT users (role=customer)
    DB-->>API: user row
    API-->>SPA: 201 Created
    SPA-->>Guest: Registration confirmed

    Guest->>SPA: Enter email, password
    SPA->>API: POST /api/auth/login
    API->>DB: SELECT user by email
    DB-->>API: user row (password_hash)
    API->>API: Verify password hash
    API->>API: Generate short-lived JWT access token
    API->>API: Generate opaque refresh token, hash it
    API->>DB: INSERT refresh_tokens {user_id, token_hash, expires_at}
    DB-->>API: ack
    API-->>SPA: 200 OK, access token in body + Set-Cookie refresh_token (HttpOnly, Secure, SameSite)
    SPA->>SPA: Hold access token in memory only (never localStorage/sessionStorage)
    SPA-->>Guest: Logged in
```

_(See §3.2 for why the access token stays in memory while the refresh token lives only in an `HttpOnly` cookie.)_

### 7.7.2 Browse Catalog (§7.2)

```mermaid
sequenceDiagram
    actor User as Guest/Customer
    participant SPA
    participant API
    participant DB

    User->>SPA: Browse / search catalog
    SPA->>API: GET /api/widgets?category=&q=
    API->>DB: SELECT active widgets (filtered)
    DB-->>API: widget rows
    API-->>SPA: 200 OK (widget list)
    SPA-->>User: Render catalog

    User->>SPA: Open widget detail
    SPA->>API: GET /api/widgets/:id
    API->>DB: SELECT widget by id
    DB-->>API: widget row
    API-->>SPA: 200 OK (widget detail)
    SPA-->>User: Render detail page
```

### 7.7.2a Customer — Product Reviews (§7.2a)

```mermaid
sequenceDiagram
    actor Customer
    actor Guest as Guest/Customer
    participant SPA
    participant API
    participant DB

    Customer->>SPA: Open widget detail, submit rating + review text
    SPA->>API: POST /api/widgets/:id/reviews {rating, body}
    API->>DB: SELECT order_items JOIN orders WHERE user_id=... AND widget_id=... AND orders.status=paid
    DB-->>API: matching order_item (or none)

    alt no verified purchase
        API-->>SPA: 403 Forbidden ("purchase required to review")
        SPA-->>Customer: Show error
    else already reviewed this widget
        API-->>SPA: 409 Conflict ("already reviewed")
        SPA-->>Customer: Show error, offer edit instead
    else verified purchase, no existing review
        API->>DB: INSERT reviews {user_id, widget_id, order_item_id, rating, body}
        DB-->>API: review row
        API-->>SPA: 201 Created
        SPA-->>Customer: Review published
    end

    Customer->>SPA: Edit/delete own review
    SPA->>API: PATCH/DELETE /api/reviews/:id
    API->>API: Check review.user_id == caller
    API->>DB: UPDATE/DELETE reviews
    DB-->>API: ack
    API-->>SPA: 200 OK
    SPA-->>Customer: Review updated/removed

    Guest->>SPA: Open widget detail
    SPA->>API: GET /api/widgets/:id/reviews
    API->>DB: SELECT reviews WHERE widget_id=...
    DB-->>API: review rows
    API-->>SPA: 200 OK (reviews, average rating)
    SPA-->>Guest: Render reviews on detail page
```

### 7.7.3 Cart & Checkout (§7.3)

```mermaid
sequenceDiagram
    actor Customer
    participant SPA
    participant Processor as Payment Processor
    participant API
    participant DB

    Customer->>SPA: Add/update/remove cart items
    SPA->>API: POST/PATCH/DELETE /api/cart/items
    API->>DB: Upsert cart_items
    DB-->>API: ack
    API-->>SPA: 200 OK (cart state)

    Customer->>SPA: Enter shipping address + card details
    SPA->>Processor: POST /tokenize (card details, direct from browser)
    Processor-->>SPA: card_token

    SPA->>API: POST /api/orders {card_token, cart, shipping_address}
    API->>DB: Re-price cart from widgets.price_cents
    API->>DB: INSERT orders (status=pending_payment) + order_items
    DB-->>API: order row

    API->>Processor: POST /charge {card_token, amount_cents, order_id}
    alt charge succeeds
        Processor-->>API: {transaction_id, status, last4, brand}
        API->>DB: INSERT payments row
        API->>DB: UPDATE orders SET status=paid
        API->>DB: Decrement widgets.stock_quantity
        API->>DB: Clear cart
        API-->>SPA: 201 Created (order confirmed)
        SPA-->>Customer: Order confirmation
    else charge fails
        Processor-->>API: {status=failed}
        API->>DB: UPDATE orders SET status=cancelled/failed
        API-->>SPA: 402/4xx (payment failed)
        SPA-->>Customer: Show failure, cart preserved
    end
```

### 7.7.4 Admin — Catalog Management (§7.4)

```mermaid
sequenceDiagram
    actor Admin
    participant SPA
    participant API
    participant DB

    Admin->>SPA: Create/edit widget (name, price, stock, category, active flag)
    SPA->>API: POST/PATCH /api/admin/widgets(/:id)
    API->>API: Check role == admin
    API->>DB: INSERT/UPDATE widgets (created_by/updated_by)
    DB-->>API: widget row
    API-->>SPA: 200/201 OK
    SPA-->>Admin: Catalog updated

    Note over API,DB: Existing order_items.unit_price_cents are immutable
    Note over API,DB: price changes only affect future carts/orders
```

### 7.7.5 Customer Service — Refunds (§7.5)

```mermaid
sequenceDiagram
    actor CS as Customer Service
    participant SPA
    participant API
    participant Processor as Payment Processor
    participant DB

    CS->>SPA: Look up order (order id / customer email)
    SPA->>API: GET /api/cs/orders/:id
    API->>API: Check role == customer_service
    API->>DB: SELECT order, payment
    DB-->>API: order + payment rows
    API-->>SPA: 200 OK (order detail)

    CS->>SPA: Issue full/partial refund + reason
    SPA->>API: POST /api/cs/orders/:id/refunds {amount_cents, reason}
    API->>Processor: POST /refund {transaction_id, amount_cents}
    Processor-->>API: {refund_id, status}
    API->>DB: INSERT refunds (issued_by, amount_cents, reason, processor_refund_id)
    API->>DB: UPDATE payments.status, orders.status (refunded/partially_refunded)
    DB-->>API: ack
    API-->>SPA: 200 OK (refund recorded)
    SPA-->>CS: Refund confirmation
```

### 7.7.6 Customer Service — Exchanges (§7.6)

```mermaid
sequenceDiagram
    actor Customer
    actor CS as Customer Service
    participant SPA
    participant API
    participant Processor as Payment Processor
    participant DB

    Customer->>SPA: Request exchange (returned item, desired replacement)
    SPA->>API: POST /api/cs/orders/:id/exchanges
    API->>DB: INSERT exchanges (status=requested)
    DB-->>API: exchange row
    API-->>SPA: 201 Created

    CS->>SPA: Mark return received
    SPA->>API: PATCH /api/cs/exchanges/:id {status=received}
    API->>DB: UPDATE exchanges SET status=received
    DB-->>API: ack

    CS->>SPA: Complete exchange
    SPA->>API: PATCH /api/cs/exchanges/:id {status=completed}
    API->>DB: Create/update replacement shipment

    alt replacement price differs from returned item
        alt replacement cheaper
            API->>Processor: POST /refund (settle difference)
            Processor-->>API: {refund_id, status}
            API->>DB: INSERT refunds row
        else replacement more expensive
            API->>Processor: POST /charge (collect difference)
            Processor-->>API: {transaction_id, status}
            API->>DB: INSERT payments row
        end
    end

    API->>DB: UPDATE exchanges SET status=completed
    API->>DB: UPDATE orders.status accordingly
    DB-->>API: ack
    API-->>SPA: 200 OK
    SPA-->>CS: Exchange completed
```

### 7.7.7 Forgot / Reset Password (§7.1a)

```mermaid
sequenceDiagram
    actor Guest
    participant SPA
    participant API
    participant DB
    participant Email as Email Provider

    Guest->>SPA: Submit email ("forgot password")
    SPA->>API: POST /api/auth/forgot-password {email}
    API->>DB: SELECT user by email

    alt user found
        DB-->>API: user row
        API->>API: Generate single-use token, hash it
        API->>DB: INSERT password_reset_tokens {user_id, token_hash, expires_at}
        DB-->>API: ack
        API->>Email: Send reset link (plaintext token)
        Email-->>Guest: Reset password email
    else user not found
        DB-->>API: no match
        Note over API: No token generated
    end

    API-->>SPA: 200 OK (generic response either way)
    SPA-->>Guest: "If that email exists, a reset link was sent"

    Guest->>SPA: Open reset link, submit new password + token
    SPA->>API: POST /api/auth/reset-password {token, new_password}
    API->>DB: SELECT password_reset_tokens by token_hash
    DB-->>API: token row

    alt token valid (found, unexpired, unused)
        API->>API: Hash new password
        API->>DB: UPDATE users.password_hash
        API->>DB: UPDATE password_reset_tokens SET used_at=now
        API->>DB: UPDATE refresh_tokens SET revoked_at=now WHERE user_id=... (all sessions)
        DB-->>API: ack
        API-->>SPA: 200 OK (password reset)
        SPA-->>Guest: Redirect to login
    else token invalid/expired/used
        API-->>SPA: 400 Bad Request
        SPA-->>Guest: Show error, request a new link
    end
```

### 7.7.8 Change Password (§7.1b)

```mermaid
sequenceDiagram
    actor Customer
    participant SPA
    participant API
    participant DB

    Customer->>SPA: Submit current password + new password
    SPA->>API: POST /api/auth/change-password {current_password, new_password}
    API->>API: Verify access token (from Authorization header)
    API->>DB: SELECT user by access token subject
    DB-->>API: user row (password_hash)
    API->>API: Verify current_password against password_hash

    alt current password correct
        API->>API: Hash new password
        API->>DB: UPDATE users.password_hash
        API->>DB: UPDATE refresh_tokens SET revoked_at=now WHERE user_id=... AND id != current session's
        DB-->>API: ack
        API-->>SPA: 200 OK (password changed)
        SPA-->>Customer: Confirmation
    else current password incorrect
        API-->>SPA: 401/403 (incorrect current password)
        SPA-->>Customer: Show error, password unchanged
    end
```

### 7.7.9 Account Lockout / Login (§7.1c)

```mermaid
sequenceDiagram
    actor User as Guest/Customer
    participant SPA
    participant API
    participant DB

    User->>SPA: Submit email + password
    SPA->>API: POST /api/auth/login {email, password}
    API->>DB: SELECT user by email (failed_login_attempts, locked_until)
    DB-->>API: user row

    alt locked_until is set and in the future
        API-->>SPA: 423/429 "Account temporarily locked, try again later"
        SPA-->>User: Show lockout message
    else not locked
        API->>API: Verify password against password_hash

        alt password correct
            API->>DB: UPDATE users SET failed_login_attempts=0, locked_until=NULL
            API->>API: Issue access token + refresh token (§3.2)
            API->>DB: INSERT refresh_tokens {user_id, token_hash, expires_at}
            DB-->>API: ack
            API-->>SPA: 200 OK, access token in body + Set-Cookie refresh_token (HttpOnly, Secure, SameSite)
            SPA-->>User: Logged in
        else password incorrect
            API->>DB: UPDATE users SET failed_login_attempts += 1
            DB-->>API: new attempt count

            alt attempt count reaches threshold (e.g. 5)
                API->>DB: UPDATE users SET locked_until = now + cooldown
                DB-->>API: ack
                API-->>SPA: 423/429 "Account temporarily locked"
                SPA-->>User: Show lockout message
            else below threshold
                API-->>SPA: 401 "Invalid email or password"
                SPA-->>User: Show generic error
            end
        end
    end
```

### 7.7.10 Token Refresh & Stolen-Token Detection (§3.2)

```mermaid
sequenceDiagram
    actor User as Guest/Customer
    participant SPA
    participant API
    participant DB

    Note over SPA: Access token (in memory) has expired

    SPA->>API: POST /api/auth/refresh (refresh_token cookie, no body)
    API->>DB: SELECT refresh_tokens by token_hash

    alt token not found, expired, or already revoked
        DB-->>API: invalid/revoked/missing
        API-->>SPA: 401 Unauthorized
        SPA-->>User: Redirect to login
    else token valid and unused
        DB-->>API: token row
        API->>API: Generate new access token
        API->>API: Generate new opaque refresh token, hash it
        API->>DB: INSERT new refresh_tokens row
        API->>DB: UPDATE old refresh_tokens SET revoked_at=now, replaced_by=new row id
        DB-->>API: ack
        API-->>SPA: 200 OK, new access token in body + Set-Cookie refresh_token (rotated)
        SPA->>SPA: Replace in-memory access token
    else token already used once before (reuse of a rotated-out token)
        Note over API: Signals the token was likely stolen and replayed
        API->>DB: UPDATE refresh_tokens SET revoked_at=now WHERE user_id=... (entire token family)
        DB-->>API: ack
        API-->>SPA: 401 Unauthorized
        SPA-->>User: Force logout, redirect to login
    end
```

---

## 8. API Surface (representative, not exhaustive)

```
Auth
  POST   /api/auth/register
  POST   /api/auth/login
  POST   /api/auth/forgot-password   (request reset link, always generic response)
  POST   /api/auth/reset-password    (consume token, set new password)
  POST   /api/auth/change-password   (authenticated, requires current password)
  POST   /api/auth/refresh           (cookie-authenticated, rotates refresh token, returns new access token)
  POST   /api/auth/logout            (revokes the current refresh token)

Catalog (public)
  GET    /api/widgets
  GET    /api/widgets/:id
  GET    /api/categories

Reviews
  GET    /api/widgets/:id/reviews    (public)
  POST   /api/widgets/:id/reviews    (customer, requires a verified purchase of that widget)
  PATCH  /api/reviews/:id            (customer, own review only)
  DELETE /api/reviews/:id            (customer, own review only)

Cart (customer)
  GET    /api/cart
  POST   /api/cart/items
  PATCH  /api/cart/items/:itemId
  DELETE /api/cart/items/:itemId

Checkout / Orders (customer)
  POST   /api/orders                 (checkout)
  GET    /api/orders                 (own order history)
  GET    /api/orders/:id

Admin (admin only)
  POST   /api/admin/widgets
  PATCH  /api/admin/widgets/:id
  DELETE /api/admin/widgets/:id
  POST   /api/admin/categories
  GET    /api/admin/orders           (read-only, all orders)
  PATCH  /api/admin/users/:id/role
  DELETE /api/admin/reviews/:id      (moderation removal, any customer's review)

Customer Service (customer_service only)
  GET    /api/cs/orders
  GET    /api/cs/orders/:id
  POST   /api/cs/orders/:id/refunds
  POST   /api/cs/orders/:id/exchanges
  PATCH  /api/cs/exchanges/:id
```

All requests reach this surface through the API Gateway (§3.3), which rate-limits every route and validates the access token on non-public ones before forwarding. All non-public endpoints require authentication; role-restricted endpoints additionally check `role` server-side.

---

## 9. Functional Requirements Summary

1. Users can register and log in with email + password.
2. Any user (including guests) can browse and search the widget catalog.
3. Authenticated customers can add/update/remove items in a cart and check out.
4. Checkout requires a shipping address and a credit card, processed via the external payment processor; the app never stores raw card numbers.
5. Successful checkout creates an order and decrements stock; failed checkout leaves the cart intact.
6. Admins can create, edit, and deactivate widgets, including setting price and stock.
7. Admins can view all orders (read-only) and manage staff role assignments.
8. Customer Service agents can view any order, issue full/partial refunds with a reason, and process exchanges (return + replacement, with price-difference settlement).
9. Every refund/exchange records who performed it and when (audit trail).
10. Role-based access control is enforced on the backend for every state-changing operation.
11. Users can request a password reset email and set a new password via a single-use, time-limited link, without revealing whether a given email is registered.
12. Authenticated users can change their password by re-confirming their current password.
13. An account is temporarily locked out after a configured number of consecutive failed login attempts, and automatically unlocks after a cooldown period.
14. A logged-in session survives beyond the short access-token lifetime via silent refresh, without ever exposing a long-lived credential to client-side JavaScript.
15. Customers who have completed a purchase of a widget can leave a 1–5 star rating and a written review for it; each customer may leave at most one review per widget, editable or deletable by its author. Guests and customers can view all reviews and the widget's average rating on its detail page. Admins can remove any review that violates content policy.

## 10. Non-Functional Requirements

- **Security**: password hashing, parameterized SQL (no string-concatenated queries), server-side authZ on every endpoint, no raw card data at rest, HTTPS assumed in deployment. Password reset tokens are single-use, time-limited, stored hashed, and the forgot-password endpoint is rate-limited and returns a uniform response to avoid user enumeration. Login enforces account lockout after repeated failed attempts to slow down credential-stuffing/brute-force attacks, and the API Gateway (§3.3) rate-limits the same routes as a first line of defense in front of it. **Token theft**: the JWT access token is never persisted client-side (in-memory only, ~15 min lifetime); the refresh token that keeps the session alive is only ever exposed via an `HttpOnly`/`Secure`/`SameSite` cookie, is single-use with rotation, and reuse of an already-rotated refresh token revokes the whole session family as a theft signal (§3.2). A CSP restricting inline scripts limits the underlying XSS surface that this design assumes could otherwise be exploited. `api` is never directly reachable by clients — the gateway is the only public entry point and validates every access token before a request reaches it (§3.3, §11.2).
- **Data integrity**: order line items and prices are immutable once an order is placed; catalog price changes never retroactively alter past orders.
- **Auditability**: refunds and exchanges record the acting staff user, timestamp, and reason.
- **Testability**: the payment processor client is implemented behind an interface/module boundary so it can be pointed at the processor's sandbox/test mode, or replaced with a test double, for local development and automated tests — this is a testing concern and does not change the production architecture, which always talks to the real processor.

---

## 11. Deployment (Docker)

The application ships as a small set of containers, defined via a `docker-compose.yml` for local development and single-host deployment (a larger-scale deployment would split these across separate hosts/services, but Compose is sufficient at current scale).

### 11.1 Containers

| Service                        | Image / Base                                   | Notes                                                                                                                               |
| ------------------------------ | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `gateway`                      | nginx/Traefik or a dedicated API gateway image | Sole publicly published container (§3.3): TLS termination, rate limiting, JWT authN/token validation                                |
| `web`                          | `node:XX-alpine` (multi-stage build)           | Builds and serves the SPA (static build output served via nginx or a lightweight Node static server); reachable only from `gateway` |
| `api`                          | `node:XX-alpine` (multi-stage build)           | Express API server; reachable only from `gateway`                                                                                   |
| `db`                           | `postgres:XX-alpine`                           | SQL database, named volume for data persistence                                                                                     |
| `migrate` (optional, one-shot) | same image as `api`                            | Runs DB migrations/seed on startup, then exits                                                                                      |

The **payment processor is not a container in this Compose stack** — it is a real, external, third-party service reached over the public internet via HTTPS. Only `api` (server-to-server) and the browser running the SPA (for client-side tokenization) talk to it; nothing about it is deployed or operated by us.

### 11.2 Networking

- A single Docker Compose network (or two: `frontend` and `backend`) so that:
  - `gateway` is the only container reachable from the host (published port, e.g. `80`/`443`).
  - `web` and `api` are **not** published to the host; only `gateway` can reach them.
  - `db` is **not** published to the host; only `api` can reach it.
  - `api` requires outbound HTTPS access to the payment processor's public endpoints.
- Presenting `web` and `api` under one origin via `gateway` also avoids CORS and is what makes `SameSite` cookie enforcement on the refresh-token cookie (§3.2) meaningful rather than merely nominal (§3.3).

### 11.3 Configuration & Secrets

- All service configuration (DB connection string, JWT signing secret, payment processor base URL/API key, port numbers) is supplied via environment variables, not hardcoded.
- Local dev uses a `.env` file (excluded from version control via `.gitignore`); example values live in a committed `.env.example`.
- Database credentials and any signing secrets are treated as secrets — for Compose-based deployment, env vars are acceptable; a larger-scale deployment would use Docker secrets or a secrets manager.

### 11.4 Data Persistence & Migrations

- `db` uses a named Docker volume so data survives container recreation (`docker compose down` without `-v`).
- Schema migrations run via the `migrate` one-shot service (or an entrypoint step on `api`) before `api` starts accepting traffic; Compose `depends_on` + a healthcheck on `db` gate startup order.

### 11.5 Images / Build

- Each Node service uses a **multi-stage Dockerfile**: a `build` stage with dev dependencies to compile/bundle, and a slim `runtime` stage (`node:XX-alpine`) that copies only production artifacts and `node_modules --omit=dev`.
- Containers run as a **non-root user** and do not run `npm install`/build steps at container start in production images.
- `.dockerignore` excludes `node_modules`, `.env`, and local build artifacts from the build context.

### 11.6 Representative `docker-compose.yml` shape

```yaml
services:
  gateway:
    build: ./gateway # nginx/Traefik config, or a dedicated gateway image
    ports: ["8080:80", "8443:443"]
    depends_on: [web, api]

  web:
    build: ./web
    expose: ["80"]
    depends_on: [api]

  api:
    build: ./api
    env_file: .env # includes PAYMENT_PROCESSOR_BASE_URL / API key
    depends_on:
      db: { condition: service_healthy }
    expose: ["3000"]

  migrate:
    build: ./api
    command: ["npm", "run", "migrate"]
    env_file: .env
    depends_on:
      db: { condition: service_healthy }

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: widgetshop
      POSTGRES_USER: widgetshop
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    volumes: ["db_data:/var/lib/postgresql/data"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U widgetshop"]

volumes:
  db_data:
```

_(The payment processor is external and has no service entry here — `api` reaches it via `PAYMENT_PROCESSOR_BASE_URL` over the public internet.)_

### 11.7 Deployment-Related Requirements

1. The app must run end-to-end via a single `docker compose up` with no manual host setup beyond providing a `.env` (including payment processor credentials).
2. `db`, `web`, and `api` must not be exposed on host-published ports — `gateway` is the sole published entry point.
3. No secret values are baked into images; all are injected at runtime via env vars/secrets.
4. Container images run as non-root and contain no dev-only tooling in the runtime stage.
5. `api` must not accept traffic until database migrations have completed successfully.
