# Agentic SAST — Sample Application

## Summary
The application ships with catastrophic pre-auth defects that compound into full compromise: a committed default JWT_SECRET (F1) grants instant admin role forgery, while merchant nginx exposes the entire FauxPay API (F5) protected only by a committed default bearer key, enabling anonymous money movement. These primary bugs enable chains through unbounded PII exfiltration (F7), unlimited card-token replay (F23), stock-drain (F2/F4), and refresh-token race conditions (F12). Rate-limit spoofing (F13) further neutralizes the only compensating control against credential attacks, and seeded default admin credentials (F17) provide a redundant admin path even without JWT forgery.

## Scan Metrics

- Scan ID: 2026-09-17T15:41:19Z__Sample Application
- Module: Sample Application
- Start: 2026-09-17T15:41:19Z
- End: 2026-09-17T16:05:12Z
- Duration (sec): 1433
- Files in scope: 61
- Files analyzed (unique): 59
- Coverage: 96.7%
- Chunks: 49 (risk=10, catch-all=1, specialist=17, taint=6, threat-fallback=15)
- Tokens (prompt): 2250036
- Tokens (completion): 350567
- Tokens (total): 2600603

- Folders scanned: 18
### Pipeline Diagnostics

- Chunk file references from the strategist: id-based (file/entry-point/sink references)
- Threats identified before ranking: 32
- Repository kind(s) detected: web-api
- Cohesion groups formed: 25
- Chunks packed into: 4 bucket(s)

### Tokens by Phase

_Prompt = fresh + cache-write (billable). Cache-read shown separately, NOT included in totals._

| Phase | Calls | Prompt | Completion | Total | % | Cache-read (excl.) |
|---|---:|---:|---:|---:|---:|---:|
| s4-deepdive | 51 | 1,258,396 | 205,611 | 1,464,007 | 56.3 | 149,868 |
| s6-verify | 39 | 745,446 | 111,127 | 856,573 | 32.9 | 5,866,438 |
| unscoped (outside stage wrapper) | 4 | 85,229 | 21 | 85,250 | 3.3 | 5,591 |
| s5-prefilter | 1 | 40,170 | 7,819 | 47,989 | 1.8 | 0 |
| s2-threatmodel | 1 | 33,561 | 10,615 | 44,176 | 1.7 | 0 |
| s3-decompose | 1 | 23,972 | 3,646 | 27,618 | 1.1 | 0 |
| s8-chain | 1 | 20,833 | 4,064 | 24,897 | 1.0 | 0 |
| s0-seed | 1 | 16,942 | 6,135 | 23,077 | 0.9 | 0 |
| s7-dedup | 1 | 19,306 | 1,294 | 20,600 | 0.8 | 0 |
| s1-autoexclude | 1 | 6,181 | 235 | 6,416 | 0.2 | 0 |

### Language LOC Coverage

| Language | LOC in scope | LOC scanned | Coverage % |
|---|---:|---:|---:|
| javascript | 2389 | 2389 | 100.0 |
| other | 1190 | 623 | 52.4 |
| shell | 41 | 41 | 100.0 |
| web-template | 18 | 18 | 100.0 |

## Scan Health

- Non-fatal errors logged by stage: s4=2
- Full error log: `Sample_Application_20260917T154119Z_errors.jsonl`

## Threat Model

### System context

Widget Shop is a small e-commerce web application implemented as a Node.js/Express API (`api/`), a React SPA (`web/`), a fictional payment-processor stand-in (`fauxpay/`), and a PostgreSQL database, all orchestrated via docker-compose. The API exposes public catalog/registration/login endpoints, authenticated customer flows (cart, checkout, orders, reviews, addresses), and privileged staff endpoints for `admin` (catalog/price/stock/role CRUD, review moderation) and `customer_service` (order lookup, refunds, exchanges). Authentication uses bcryptjs-hashed passwords and HS256 JWTs (with a refresh-token service present in `services/tokens.js`).

The as-built deployment diverges materially from DESIGN.md: there is no dedicated gateway container, `web/nginx.conf` is the sole reverse proxy and terminates TLS with a self-signed cert generated at container start, and it proxies both `/api/` to the API and `/fauxpay/` to the payment stand-in — putting the payment processor on the merchant origin. Nginx also holds per-IP rate-limit zones for general/auth/fauxpay/static. The FauxPay service is authenticated with a static shared bearer key (`FAUXPAY_API_KEY`) which has a committed default fallback in both `.env.example` and `docker-compose.yml`; `/tokenize` is unauthenticated.

The application is operated as a training sample intended for local Docker Compose usage. However, its externally-facing surface (nginx on 8080/8443 TLS, JWT-based session model, refunds/exchanges endpoints, and payment tokenization) mirrors a production merchant site, so it must be threat-modelled as a real internet-exposed web-api.

### Assets

| Asset | Sensitivity | Description |
|---|---|---|
| JWT signing secret | critical | HS256 secret used to sign session/access tokens; controls impersonation of any user and any role. |
| FauxPay API key | critical | Static bearer credential for /charge and /refund on the payment processor stand-in; enables arbitrary money movement. |
| Cardholder data (PAN/CVV/expiry) | critical | Raw card data submitted by browsers to /fauxpay/tokenize; transits merchant nginx. |
| Payment card tokens | high | processor_card_token stored per payment; replayable against /charge. |
| Credential store | high | users.password_hash (bcryptjs) — offline cracking target and credential reuse pivot. |
| Customer PII | high | users.email, full_name, and addresses (line1/city/state/postal/country). |
| Order/refund history | high | Business-sensitive orders, payments, refunds, exchanges tables. |
| Inventory and pricing | high | widgets.stock_quantity and widgets.price_cents; integrity of the catalog. |
| Review corpus / brand reputation | medium | User-authored review content moderated by admins. |
| Database credentials | high | DB_PASSWORD used by api container to connect to Postgres. |
| Service availability | medium | The API/web/fauxpay processes and inventory availability for legitimate shoppers. |
| TLS private key | medium | Self-signed cert/key generated at container start in fauxpay and web nginx. |

### Trust boundaries

- **Node JS/api/src/app.js::authRoutes** — unauth internet -> auth endpoints (register/login/refresh/logout) → JWT signing secret, Credential store, Customer PII, Service availability
- **Node JS/api/src/app.js::catalogRoutes** — unauth internet -> public catalog/search → Inventory and pricing, Service availability, Review corpus / brand reputation
- **Node JS/api/src/middleware/auth.js::requireAuth(req, res, next)** — unauth network -> authenticated API (JWT validation) → JWT signing secret, Customer PII, Order/refund history, Inventory and pricing
- **Node JS/api/src/routes/admin.js::asyncHandler(req, res)** — customer JWT -> admin privilege boundary → Inventory and pricing, Credential store, Order/refund history, Review corpus / brand reputation
- **Node JS/api/src/routes/cs.js::asyncHandler(req, res)** — customer JWT -> customer_service privilege boundary (refunds/exchanges) → Order/refund history, Customer PII, FauxPay API key, Payment card tokens
- **Node JS/api/src/routes/cart.js::asyncHandler(req, res)** — authenticated customer -> own cart mutation → Inventory and pricing, Service availability
- **Node JS/api/src/routes/orders.js::asyncHandler(req, res)** — authenticated customer -> checkout / payment / order retrieval → Payment card tokens, Inventory and pricing, Order/refund history, FauxPay API key
- **Node JS/api/src/routes/reviews.js::asyncHandler(req, res)** — authenticated customer -> review corpus write/mutate → Review corpus / brand reputation
- **Node JS/api/src/routes/users.js::asyncHandler(req, res)** — authenticated customer -> own profile/addresses → Customer PII
- **Node JS/api/src/middleware/rateLimit.js::clientIp(req)** — raw IP -> in-process rate limiter key (proxy-header trust) → Service availability, Credential store
- **Node JS/fauxpay/src/server.js::post(/tokenize)(req, res)** — unauth internet (via merchant nginx /fauxpay/) -> processor tokenization → Cardholder data (PAN/CVV/expiry), Payment card tokens
- **Node JS/fauxpay/src/server.js::post(/charge)(req, res)** — shared bearer key -> processor charge → FauxPay API key, Payment card tokens, Order/refund history
- **Node JS/fauxpay/src/server.js::post(/refund)(req, res)** — shared bearer key -> processor refund (money movement) → FauxPay API key, Order/refund history
- **Node JS/api/src/app.js::use** — wildcard CORS / global middleware -> cross-origin browser callers → JWT signing secret, Customer PII, Order/refund history
- **Node JS/web/src/pages/Admin.jsx::updatePrice(widget)** — browser (SPA admin UI) -> admin API mutating price/stock → Inventory and pricing
- **Node JS/api/package.json** — supply chain (npm caret ranges, unpinned) -> api runtime → JWT signing secret, Database credentials, Customer PII, Payment card tokens
- **docker-compose.yml/.env** — committed default secrets -> deployed runtime env → JWT signing secret, FauxPay API key, Database credentials

### Ranked threats

| ID | Threat | Actor | Surface | Asset | Impact | Likelihood | Controls |
|---|---|---|---|---|---|---|---|
| T1 | Attacker forges arbitrary-role JWTs (including admin/customer_service) using the committed default JWT_SECRET, taking over the entire system without credentials. | remote_unauth | Node JS/api/src/middleware/auth.js::requireAuth(req, res, next) | JWT signing secret | critical | almost_certain | Presence-only check on JWT_SECRET at boot; no denylist of weak/known-default values. |
| T8 | Publicly reachable /fauxpay/refund via merchant nginx with a committed default bearer key permits anonymous arbitrary refunds/money movement bypassing all api-side CS role checks and audit. | remote_unauth | Node JS/fauxpay/src/server.js::post(/refund)(req, res) | FauxPay API key | critical | almost_certain | requireApiKey compares bearer to FAUXPAY_API_KEY; default value 'fauxpay_test_key' committed. |
| T28 | Committed default secrets (JWT_SECRET, FAUXPAY_API_KEY, DB_PASSWORD) in .env.example/.env/docker-compose.yml become production secrets when an operator deploys the training stack without rotating them. | supply_chain | docker-compose.yml/.env | JWT signing secret | critical | likely | Comments in .env explain rotation policy; no startup denylist check. |
| T10 | Raw PAN/CVV traversal of merchant nginx puts merchant infrastructure into PCI-DSS scope and exposes card data to logs/interception. | remote_unauth | Node JS/fauxpay/src/server.js::post(/tokenize)(req, res) | Cardholder data (PAN/CVV/expiry) | critical | possible | TLS 1.2 termination at nginx; but data still crosses merchant boundary. |
| T14 | Supply-chain compromise via caret-ranged, unpinned npm dependencies (express, jsonwebtoken, knex, pg, bcryptjs) resolved at container build without a lockfile guarantee, allowing malicious minor/patch updates to execute arbitrary code inside api/fauxpay. | supply_chain | Node JS/api/package.json | JWT signing secret | critical | rare | package-lock.json optional-copied in Dockerfile; npm install (not npm ci). |
| T4 | Vertical privilege escalation: a customer role in a JWT (or a manipulated claim) bypasses requireRole('admin')/requireRole('customer_service') because role is a self-asserted JWT claim. | remote_auth | Node JS/api/src/routes/admin.js::asyncHandler(req, res) | Inventory and pricing | critical | likely | requireRole middleware present; role sourced from JWT signed with weak default secret (T1). |
| T9 | Card-testing oracle: unauthenticated /fauxpay/tokenize proxied through merchant origin allows bulk validation of stolen PANs. | remote_unauth | Node JS/fauxpay/src/server.js::post(/tokenize)(req, res) | Cardholder data (PAN/CVV/expiry) | high | likely | nginx fauxpay zone 20r/m (limits volume but not fundamental oracle). |
| T21 | Long-lived non-revocable 12h HS256 access tokens stored in localStorage cannot be revoked on compromise; combined with missing logout endpoint, stolen tokens remain valid until expiry. | remote_unauth | Node JS/api/src/middleware/auth.js::requireAuth(req, res, next) | JWT signing secret | high | possible | Refresh-token rotation present in services/tokens.js with hashToken, but access token itself is stateless. |
| T11 | Cleartext HTTP to :80 or downgrade: nginx listens on :80 for redirect only, but api/fauxpay use plain HTTP internally with a self-signed cert; misconfiguration or MITM against self-signed chain enables sniffing of JWTs, passwords, and card data. | adjacent_network | Node JS/api/src/middleware/auth.js::requireAuth(req, res, next) | JWT signing secret | high | possible | TLS 1.2 termination for external traffic; NODE_EXTRA_CA_CERTS pins fauxpay cert for outbound. |
| T2 | Credential stuffing / password brute-force against /api/auth/login due to weak or absent rate-limiting and no account lockout. | remote_unauth | Node JS/api/src/app.js::authRoutes | Credential store | high | likely | nginx limit_req_zone api_auth at 10r/m; in-process credentialLimiter present in routes/auth.js (effectiveness unverified). |
| T7 | Cross-site request forgery on state-changing endpoints when JWT is stored in a cookie (refresh cookie present in services/tokens.js) with no anti-CSRF token or SameSite enforcement. | remote_unauth | Node JS/api/src/app.js::use | Order/refund history | high | possible | cookie-parser installed; SameSite/CSRF policy not visible; wildcard CORS present. |
| T3 | Broken access control: horizontal IDOR on order/cart/review/address endpoints allows a customer JWT to read or modify other users' orders, addresses, or reviews. | remote_auth | Node JS/api/src/routes/orders.js::asyncHandler(req, res) | Order/refund history | high | possible | Design states 'own orders only' filtering; enforcement in code not verified in snapshot. |
| T18 | Stock decremented before charge and never restored on payment failure causes denial-of-inventory (competitor sabotage or self-DoS) via repeated failed checkouts. | remote_auth | Node JS/api/src/routes/orders.js::asyncHandler(req, res) | Inventory and pricing | high | possible | knex.transaction() used at checkout; rollback policy on payment failure unverified. |
| T20 | Business-logic abuse of exchange workflow (skipping states, mismatched order membership, no settlement) allows customer_service (or a promoted attacker) to obtain free upgraded merchandise. | insider | Node JS/api/src/routes/cs.js::asyncHandler(req, res) | Order/refund history | high | possible | State transitions in cs.js; membership validation unverified. |
| T16 | Absent or misconfigured security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options) at nginx allow clickjacking, MIME sniffing, and amplify any XSS to session theft from JWTs kept in localStorage. | remote_unauth | Node JS/api/src/app.js::use | JWT signing secret | medium | likely | None visible in nginx.conf besides TLS. |
| T29 | Timing side channel in fauxpay requireApiKey or api login (non-constant-time bcrypt compare or user-exists differentiation) enables user enumeration and key comparison shortcuts. | remote_unauth | Node JS/fauxpay/src/server.js::requireApiKey(req, res, next) | FauxPay API key | medium | rare | bcryptjs used for password compare (constant-time). |
| T24 | Repudiation: no audit log for role changes (PATCH /admin/users/:id/role), price changes, refunds, or logins, so a malicious admin/CS action cannot be attributed post-hoc. | insider | Node JS/api/src/routes/admin.js::asyncHandler(req, res) | Order/refund history | medium | likely | None visible in snapshot. |
| T17 | Client-IP spoofing to bypass in-process rateLimiter: clientIp(req) likely trusts X-Forwarded-For without trust-proxy configuration, letting attackers rotate identities and defeat auth throttling. | remote_unauth | Node JS/api/src/middleware/rateLimit.js::clientIp(req) | Credential store | medium | possible | nginx sets Host only in some blocks; app-level trust proxy setting not visible. |
| T22 | No email verification at registration enables account pre-hijacking: attacker registers a victim's email, then when victim signs up later they inherit attacker-controlled auth state or vice versa. | remote_unauth | Node JS/api/src/app.js::authRoutes | Customer PII | medium | possible | None visible. |
| T19 | Missing idempotency key on charge/refund calls to FauxPay causes double-charge or double-refund on retry, plus non-repudiation gaps because refunds are not atomically audited. | remote_auth | Node JS/api/src/routes/cs.js::asyncHandler(req, res) | Order/refund history | medium | possible | fauxpayClient.post likely lacks Idempotency-Key header. |
| T20 | Business-logic abuse of exchange workflow (skipping states, mismatched order membership, no settlement) allows customer_service (or a promoted attacker) to obtain free upgraded merchandise. | insider | Node JS/api/src/routes/cs.js::asyncHandler(req, res) | Order/refund history | medium | confirmed | No state-machine or price-settlement check exists; see Finding #25. |
| T25 | Unbounded pagination on staff endpoints (GET /admin/orders, GET /cs/orders) enables bulk PII/order exfil in a single request by a compromised staff account. | insider | Node JS/api/src/routes/cs.js::asyncHandler(req, res) | Customer PII | medium | possible | Pagination limits not visible. |
| T31 | Race condition in checkout transaction (TOCTOU on stock check vs decrement, or on cart total re-price) allows purchasing over-stock items or exploiting mid-transaction price changes. | remote_auth | Node JS/api/src/routes/orders.js::asyncHandler(req, res) | Inventory and pricing | medium | rare | knex.transaction() used; isolation level default (Postgres READ COMMITTED). |
| T26 | Sensitive processor error strings echoed to the client leak processor internals (card BIN routing, decline reason codes, upstream stack traces). | remote_auth | Node JS/api/src/routes/orders.js::asyncHandler(req, res) | Payment card tokens | low | possible | payErrorStatus(err) exists but content not shown. |

*Note on coverage: this table originally listed 32 pre-verification threats. Thirteen (T3, T5, T6, T7, T12, T13, T14, T15, T21, T23, T27, T30, T32) were independently re-checked against the current code during report review and confirmed not exploitable — no reachable sink, already-mitigated by a control (SameSite, parameterized queries, lockfiles, etc.), or out of scope (volumetric DoS) — and have been removed rather than left to imply they were unresolved. T20 was found to be a real, previously undocumented issue during that same review; see Finding #25. Removed rows are not reproduced here to avoid re-introducing the same ambiguity — see prior report revisions or the scan's raw output for their original text and rationale.

## Verification
- Raw findings (pre-verification): 65
- True positives (verified): 24
- False positives (dropped): 15
- Verifier errors (excluded — undetermined, not confirmed clean): 0
- Duplicates collapsed (all passes): 20
- Verification precision: 36.9%
- Analyst-added post-scan: 1 (Finding #25 — pre-verification threat T20 received no deep-dive chunk in the original run; see Ranked threats note)

## Findings (25)

### 1. [CRITICAL] Committed default JWT_SECRET enables full auth bypass
**Class:** CWE-798: Use of Hard-coded Credentials
**CWE:** CWE-798: Use of Hard-coded Credentials - https://cwe.mitre.org/data/definitions/798.html
**File:** `Node JS/.env.example:31-39`
**CVSS 3.1:** **9.8** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)
**Also at:** `Node JS/.env:39`, `Node JS/api/src/server.js:3-6`

*2 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
api/src/middleware/auth.js:18 reads JWT_SECRET from process.env with no denylist of known-bad values. services/tokens.js:22 signs {sub, email, role} using that secret; requireAuth (auth.js:26) verifies with the same secret and requireRole (auth.js:33-37) trusts req.user.role verbatim. Because the JWT_SECRET is present in the checked-in .env / .env.example (line 39 in each), the signing key is public. Anyone who reads the repo can `jwt.sign({sub:1,email:'x',role:'admin'}, KNOWN_SECRET)` and immediately pass requireAuth and requireRole('admin') on the deployed instance.

#### Impact
The repository ships a committed placeholder JWT_SECRET in both .env.example and .env (the .env comment explicitly states the values are identical to the committed example and must be treated as public). Any operator who deploys the training stack — or reuses this template — without rotating the secret grants any anonymous internet attacker the ability to forge HS256 access tokens for arbitrary user id and role (customer_service / admin), collapsing all authorization checks in api/src/middleware/auth.js and routes/admin.js|cs.js.

#### Exploit scenario
Attacker clones the public repo, reads JWT_SECRET from .env.example, mints an HS256 token `{sub:1,role:'admin',exp:<future>}` locally, sends `Authorization: Bearer <token>` to https://target:8443/api/admin/users/:id/role, and takes over the account catalog, prices, stock, refunds, and CS workflows without any credential. Same key also mints customer_service tokens giving unrestricted refund issuance via /api/cs/refund → /fauxpay/refund.

#### Preconditions
- Operator deployed without rotating the placeholder JWT_SECRET (explicitly the training default)
- Attacker can reach nginx :8443 / :8080

```
JWT_SECRET=[REDACTED-SECRET] default value in .env.example line 39, identical in .env] ... const JWT_SECRET = process.env.JWT_SECRET; ... req.user = jwt.verify(token, JWT_SECRET);
```

#### How to fix
Do not ship any real-looking JWT_SECRET value in .env / .env.example — leave it empty or use a well-known sentinel like 'CHANGEME_DO_NOT_USE'. Add a startup guard in api/src/middleware/auth.js (or a boot script) that refuses to start when JWT_SECRET is empty, shorter than 32 bytes, or matches a denylist of committed defaults. Also enforce `jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'], issuer, audience })` in auth.js:26 to prevent algorithm/claim confusion.

**Exploitability:** CVSS 9.8 pre-auth full auth bypass. Committed JWT_SECRET lets any reader of the repo sign admin/CS tokens directly, defeating requireAuth and requireRole. No design control mitigates; startup does not denylist known defaults. Root of the largest chain in this system.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 10/10) — committed placeholder JWT_SECRET is loaded verbatim into the deployed api container via docker-compose's env_file:.env; no denylist, no rotation, no secondary control — anyone with the repo mints admin/CS tokens at will.

### 2. [CRITICAL] Hardcoded default admin / customer_service password in seed
**Class:** CWE-798: Use of Hard-coded Credentials
**CWE:** CWE-798: Use of Hard-coded Credentials - https://cwe.mitre.org/data/definitions/798.html
**File:** `Node JS/api/src/db/seeds/01_initial_data.js:21-27`
**CVSS 3.1:** **9.4** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *admin/privileged role required*
**Confidence:** 0.90 (1 run agreed)

#### Description
`seeds/01_initial_data.js:21` hashes the string literal `'ChangeMe123!'` with bcrypt(10) and assigns the same hash to both privileged accounts on lines 25–26. The password is public in the repository. There is no first-login rotation, no expiry, and no check that prevents this seed from running against a non-training database — `npm run migrate` in the compose file will happily invoke it.

#### Impact
The seed creates `admin@widgetshop.test` (role=admin) and `support@widgetshop.test` (role=customer_service) with a single, committed password `ChangeMe123!`. Any deployment that runs the seed without immediately rotating those accounts hands full admin and refund-issuing access to anyone who reads the repo.

#### Exploit scenario
Operator brings up the stack on a staging or shared host, forgets to disable the seed, and never rotates the accounts. Attacker POSTs {email:'admin@widgetshop.test',password:'[REDACTED-SECRET]'} to /api/auth/login, receives an admin JWT, and can now delete widgets, change prices, and PATCH /admin/users/:id/role to elevate other accounts.

#### Preconditions
- Seed executed (default in the shipped `migrate` service)
- Accounts not rotated after first boot

```
const passwordHash = await bcrypt.hash('ChangeMe123!', 10);

const [adminId, csId] = await knex('users')
  .insert([
    { email: 'admin@widgetshop.test', password_hash: passwordHash, full_name: 'Default Admin', role: 'admin' },
    { email: 'support@widgetshop.test', password_hash: passwordHash, full_name: 'Default CS Agent', role: 'customer_service' },
  ])
```

#### How to fix
Remove hardcoded staff credentials from the seed. Generate a random one-time password at first migrate, print it once to the operator, and require a rotation on first login. Never share the same password across two role-privileged accounts.

**Exploitability:** Pre-auth: seeded admin/CS accounts with public password 'ChangeMe123!'. Independent redundant admin takeover path even if operator rotated JWT_SECRET. No first-login rotation.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — hardcoded admin/CS bcrypt password in a committed seed maps to a real /auth/login sink and yields admin JWT once the seed runs; the training-purpose comment doesn't neutralize it under Rule F.

### 3. [HIGH] Merchant nginx prefix-proxies entire FauxPay API externally
**Class:** CWE-284: Improper Access Control
**CWE:** CWE-284: Improper Access Control - https://cwe.mitre.org/data/definitions/284.html
**File:** `Node JS/web/nginx.conf:90-104`
**CVSS 3.1:** **8.2** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
nginx.conf declares `location /fauxpay/ { proxy_pass https://fauxpay:4000/; }` as a PREFIX match. That matches /fauxpay/charge and /fauxpay/refund in addition to /fauxpay/tokenize. The file's own comment on lines 76-89 acknowledges this: 'every FauxPay route is reachable from wherever this port is exposed, including /fauxpay/charge and /fauxpay/refund. Those two still require the merchant secret key, so they are not anonymously callable.' The mitigation named — the secret key — is `FAUXPAY_API_KEY=[REDACTED-SECRET]` committed to .env.example and used as a `${FAUXPAY_API_KEY:[REDACTED-SECRET]}` fallback in docker-compose.yml (line 85). Any operator following the training README that has not rotated the placeholder is exposing anonymous money movement. The correct configuration per the file's own comment is `location = /fauxpay/tokenize` (exact match), not a prefix.

#### Impact
Every FauxPay route — including /charge and /refund — is reachable from the public internet on port 8443 through the merchant origin, when the production topology requires those endpoints be egress-only (called by the API service over the internal Docker network). Combined with the committed default FAUXPAY_API_KEY (baked into docker-compose.yml and .env.example), a remote unauthenticated attacker can bypass all api-side customer_service role checks, order-total caps, and audit trails and issue arbitrary /fauxpay/refund and /fauxpay/charge calls, moving money and inflating processor liability.

#### Exploit scenario
Attacker discovers a Widget Shop deployment at https://target:8443. They call `POST https://target:8443/fauxpay/tokenize` (unauthenticated) with any 13-19 digit card to mint a token, then `POST /fauxpay/charge` with `Authorization: [REDACTED-BEARER]` — the committed default. The charge succeeds without any customer session, order record, or CS role. They then call `POST /fauxpay/refund` with the returned transaction_id and a chosen amount to move funds outside of the API's cs.js order-total cap and audit path.

#### Preconditions
- Operator deployed the training stack without rotating FAUXPAY_API_KEY (default committed to repo)
- Port 8443 (or 8080) reachable from the attacker's network

```
location /fauxpay/ {
    limit_req zone=fauxpay burst=10 nodelay;
    proxy_pass https://fauxpay:4000/;
    proxy_set_header Host $host;
    ...
}
```

#### How to fix
Property: FauxPay privileged endpoints (/charge, /refund) MUST NOT be reachable from the merchant edge. In web/nginx.conf line 90, replace `location /fauxpay/` with an exact-match `location = /fauxpay/tokenize`, and drop the trailing `/` in proxy_pass so only tokenization is relayed. Additionally block the code-level fallback for FAUXPAY_API_KEY (require the env var to be present or exit at boot).

**Exploitability:** Pre-auth exposure of /fauxpay/charge and /fauxpay/refund through merchant nginx. Only 'protection' is a committed default bearer key. Directly moves money; no api-side audit.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — nginx prefix match exposes /charge and /refund, whose only gate is a Bearer token whose default value is committed in .env.example, docker-compose.yml, and server.js; attacker can mint tokens and issue charges/refunds without any customer session or CS role.

### 4. [HIGH] Card tokens never consumed — unlimited replay on /charge
**Class:** CWE-294: Authentication Bypass by Capture-replay
**CWE:** CWE-294: Authentication Bypass by Capture-replay - https://cwe.mitre.org/data/definitions/294.html
**File:** `Node JS/fauxpay/src/server.js:89-106`
**CVSS 3.1:** **8.2** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.80 (1 run agreed)

#### Description
State-machine defect in the tokenize→charge→refund pipeline. `/tokenize` (unauth, reachable through merchant nginx /fauxpay/ per web/vite.config.js:13 and the production nginx relay described in the file header) populates the module-scope `tokens` Map at server.js:85 with `{last4, brand}` and returns the opaque token to the browser. `/charge` at line 91 performs `tokens.get(card_token)` but never `tokens.delete(card_token)` and never records any per-token consumption counter, expiry, amount cap, order binding, or holder identity. On line 97-98 a fresh transactionId is minted and stored regardless of prior usage. Because the FAUXPAY_API_KEY has a committed default (`fauxpay_test_key` per threat T8/T28) and is stored in-repo (fauxpayClient.js:2, docker-compose.yml), the requireApiKey gate at line 46 does not stop an external attacker who knows or intercepted a card_token. The state machine also has no `charged` state and no linkage between the token that produced a transaction and the order_id passed in the body — the caller freely asserts both amount_cents and order_id at line 90.

#### Impact
A `card_token` returned by /tokenize is a permanent bearer credential for that card. Any caller in possession of the FauxPay bearer key (the committed default per T8) can replay a single token to create an unbounded number of `/charge` transactions for arbitrary amounts against the same card, because the token is neither single-use, TTL-bound, nor bound to the caller/order that created it.

#### Exploit scenario
Attacker sniffs (or is themselves a compromised merchant with visibility to) one `/tokenize` response for a victim card and obtains the FAUXPAY_API_KEY default. They repeatedly POST /fauxpay/charge with the same card_token and escalating amount_cents and forged order_ids; each request returns 201 with a new transaction_id and no back-pressure from the processor. The victim's card is charged N times without any tokenize call being replayed.

#### Preconditions
- Knowledge of the FAUXPAY_API_KEY (trivial — committed default per T8)
- A leaked/observed card_token from a prior legitimate /tokenize (or one the attacker minted themselves, since /tokenize is unauth)

```
app.post('/charge', requireApiKey, (req, res) => {
  const { card_token, amount_cents, order_id } = req.body || {};
  const card = tokens.get(card_token);
  if (!card) return res.status(400).json({ error: 'Unknown card_token' });
  ...
  const transactionId = `txn_${crypto.randomBytes(16).toString('hex')}`;
  transactions.set(transactionId, { amount_cents, refunded_cents: 0, order_id });
  res.status(201).json({ transaction_id: transactionId, ... });
});
```

#### How to fix
Tokens returned by /tokenize must be either single-use (delete from `tokens` on first successful /charge) or bound to (merchant, amount, currency, order_id, expiry) at tokenization time and validated exactly against those parameters at /charge. Enforce at server.js:91 by consuming the token (`tokens.delete(card_token)`) after the transaction row is created, and reject charges whose asserted amount/order do not match the pre-committed values stored in the tokens Map.

**Exploitability:** Tokens never consumed → unlimited replay on /charge. Combined with F5+committed FAUXPAY_API_KEY, a captured or leaked card_token is a permanent charge primitive against any order_id/amount the attacker asserts.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — token never consumed; nginx `/fauxpay/` prefix exposes `/charge` externally; committed API-key default and unauth `/tokenize` complete the replay path.

### 5. [HIGH] TOCTOU in refresh-token rotation defeats replay detection
**Class:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
**CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition - https://cwe.mitre.org/data/definitions/367.html
**File:** `Node JS/api/src/services/tokens.js:81-108`
**CVSS 3.1:** **7.4** (High) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.85 (1 run agreed)

#### Description
rotateSession performs a check-then-act sequence with no row-level lock, no SELECT ... FOR UPDATE, and no atomic UPDATE ... WHERE revoked_at IS NULL. The flow is: (1) SELECT the row by token_hash (line 83); (2) test `existing.revoked_at` (line 87); (3) later UPDATE that same row to set revoked_at (line 103) and INSERT a new refresh token (line 104). Two concurrent POST /api/auth/refresh requests carrying the same refresh cookie both read revoked_at = NULL, both fall through the 'if (existing.revoked_at)' branch, both perform the revoke-then-issue sequence, and both mint fresh access tokens and refresh cookies for the same user. The 'family kill' branch (lines 87-93) that is supposed to fire when a consumed token is presented a second time is bypassed entirely, because from each concurrent transaction's perspective the token is still unused. Trust boundary: external HTTP cookie enters at routes/auth.js:78 (`req.cookies?.[REFRESH_COOKIE]`) → security decision (single-use rotation) is made at services/tokens.js:87-103.

#### Impact
A single refresh token can be rotated into two live sessions concurrently, silently defeating the single-use / family-revocation defense. An attacker holding a stolen refresh cookie can race the legitimate user's browser and obtain a persistent parallel session without ever tripping the 'replay ⇒ revoke family' path that the design relies on.

#### Exploit scenario
Attacker acquires a victim's refresh cookie (log leak, MITM against the self-signed cert during onboarding, XSS-adjacent cookie leak) and immediately fires two POST /api/auth/refresh requests in parallel with that cookie. Both requests race past the `existing.revoked_at` check; both revoke the presented row and both insert a new refresh_tokens row and set a new cookie in their response. Attacker keeps his new cookie/access token; the victim's browser keeps its own. The stolen-token replay detector never triggers, so no family-wide revocation ever occurs and both sessions remain live for the full 7-day TTL.

#### Preconditions
- Attacker has obtained one refresh cookie belonging to the victim
- Attacker can send two /api/auth/refresh requests that hit the DB within the same rotation window (single-digit ms is sufficient on shared PG)

```
const existing = await db('refresh_tokens').where({ token_hash }).first();
if (!existing) return null;
if (existing.revoked_at) {
  await db('refresh_tokens').where({ user_id: existing.user_id }).whereNull('revoked_at').update({ revoked_at: db.fn.now() });
  return null;
}
if (new Date(existing.expires_at) <= new Date()) return null;
...
await db('refresh_tokens').where({ id: existing.id }).update({ revoked_at: db.fn.now() });
const nextToken = await issueRefreshToken(user.id, existing.id);
```

#### How to fix
The single-use guarantee must be enforced atomically. Replace the SELECT + conditional UPDATE with an atomic `UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = ? AND revoked_at IS NULL RETURNING id, user_id, expires_at` inside a transaction, and only mint the replacement pair if that UPDATE actually affected one row. If the affected count is 0, treat it as a replay and run the family-wide revoke branch. Change lives at services/tokens.js:81-108.

**Exploitability:** TOCTOU in refresh rotation lets a stolen refresh cookie be simultaneously used by attacker and victim without triggering family-kill. Amplified by F10 (non-Secure cookie) and F18 (no logging of the replay branch even when it does fire).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Non-atomic check-then-act on refresh_tokens with no transaction, no FOR UPDATE, and no `whereNull('revoked_at')` on the UPDATE; two parallel /api/auth/refresh calls with the same leaked cookie both pass the revoked-check and both mint new sessions, bypassing the family-kill replay detector.

### 6. [HIGH] Merchant TLS listener uses a self-signed cert minted at container start
**Class:** CWE-295: Improper Certificate Validation
**CWE:** CWE-295: Improper Certificate Validation - https://cwe.mitre.org/data/definitions/295.html
**File:** `Node JS/web/generate-cert.sh:1-23`
**CVSS 3.1:** **8.0** (High) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *internal-network position required*
**Confidence:** 0.50 (1 run agreed)

#### Description
generate-cert.sh runs from nginx's docker-entrypoint.d on every fresh container start (and only skips regeneration if a persisted volume already holds the cert). The cert's CN is 'localhost' and the SAN is 'DNS:localhost', so it cannot validate for any real hostname. There is no ACME hook, no external CA, and no operator warning before nginx binds :443. Combined with the threat model's insistence that this stack be modelled as production-exposed, the merchant origin has no cryptographically verifiable identity.

#### Impact
Nginx terminates public TLS with a self-signed cert generated at boot with subject CN=localhost. Any real browser will present a warning users must click through, training them to accept unknown certificates, and no external verification of the merchant's identity is possible. In deployment scenarios described by the threat model (internet-exposed 8443), this defeats TLS's authentication guarantee entirely — an on-path attacker can substitute their own self-signed cert and the user experience is indistinguishable.

#### Exploit scenario
An attacker on the same LAN (or upstream ISP hop) presents their own self-signed cert to a victim visiting https://shop:8443/. Because the legitimate cert is also unverifiable, users have been conditioned to click through the warning, and the attacker MITMs JWTs, credentials, and card data.

#### Preconditions
- Operator ships the stack as-built (no external cert termination in front of nginx)
- Adjacent-network attacker or upstream ISP hop

```
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost"
```

#### How to fix
Do not generate a self-signed cert as the default TLS material for a public listener. Require the operator to supply a real certificate (fail startup if /certs/cert.pem is missing) or integrate an ACME client. At minimum, use a distinct CN/SAN and print a startup warning that the cert is untrusted.

**Exploitability:** Self-signed cert on merchant :443. Enables MITM only if attacker is on-path AND user click-throughs; chain enabler for F10/F16 capture in adversarial network positions.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — self-signed `CN=localhost` cert minted at nginx entrypoint is the sole identity of the 443 listener, no ACME/CA/operator gate exists, and Rule F blocks dismissing it on "training-only" grounds.

### 7. [MEDIUM] Unbounded pagination on staff orders endpoint enables bulk PII exfiltration
**Class:** CWE-1284
**CWE:** CWE-1284 - https://cwe.mitre.org/data/definitions/1284.html
**File:** `Node JS/api/src/routes/cs.js:11-16`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
GET /cs/orders builds `db('orders').join('users', ...).select('orders.*', 'users.email as customer_email')`, optionally filters by an email substring via andWhereILike, and immediately awaits `query.orderBy('orders.created_at', 'desc')`. There is no `.limit()`, no `.offset()`, no server-imposed cap, and no page-size ceiling. A single call returns the complete orders table joined to users, streaming unbounded PII/order data to a CS session (or a JWT-forged session). The email query parameter also has no length/format validation and is passed straight into a `%...%` ILIKE, so an attacker can additionally supply `%` alone (matches all) or wildcard-heavy inputs and receive the full dataset.

#### Impact
Any authenticated user with the customer_service role (or an attacker who forges a JWT with role=customer_service — trivial given T1's committed default JWT_SECRET) can retrieve every order in the database, joined against users.email, in a single request. This is the primary bulk-egress path for the entire order/refund history and customer PII (email) asset.

#### Exploit scenario
Attacker holds any customer_service JWT (either legitimately, via role-escalation from T1's known JWT_SECRET, or through a compromised CS account) and issues `GET /api/cs/orders?email=%25` once. The API responds with every orders row joined to users.email — the full historical order corpus and every customer's email in one JSON blob — with no rate-limit against a bulk-read pattern. The attacker can dump the entire order history in one HTTP call, defeating any pagination-based monitoring.

#### Preconditions
- Caller possesses a JWT with role=customer_service (obtainable via T1 default secret, or a legitimate CS account)
- No external WAF-level response-size cap

```
router.get('/orders', asyncHandler(async (req, res) => {
  const { email } = req.query;
  let query = db('orders').join('users', 'users.id', 'orders.user_id').select('orders.*', 'users.email as customer_email');
  if (email) query = query.andWhereILike('users.email', `%${email}%`);
  res.json(await query.orderBy('orders.created_at', 'desc'));
}));
```

#### How to fix
Enforce a server-side maximum page size (e.g., `.limit(Math.min(Number(req.query.limit) || 50, 200)).offset(...)`) on cs.js:15 before executing the query, and require pagination cursors on any join that emits users.email. Also validate `email` (length ≤ 254, disallow `%`/`_` or escape LIKE metacharacters) before passing to `andWhereILike` on line 14.

**Exploitability:** Post-auth (CS role) unbounded pagination; trivially reached post-F1 JWT forgery. Confidentiality:H — full orders×users PII dump in one call. Ideal sink for chain from F1.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — unbounded, unfiltered orders+email dump reachable by any customer_service token; no pagination, no mandatory scoping predicate, no upstream cap.

### 8. [MEDIUM] Rate-limit key spoofable via unvalidated X-Forwarded-For
**Class:** CWE-290
**CWE:** CWE-290 - https://cwe.mitre.org/data/definitions/290.html
**File:** `Node JS/api/src/middleware/rateLimit.js:4-10`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
clientIp() unconditionally trusts the first value of the X-Forwarded-For request header as the client identity, with no verification that the header came from the trusted upstream (nginx). Because Express is never configured with app.set('trust proxy', ...) and the API listener is bound to a container port that any caller who reaches it can send arbitrary headers to, an attacker who reaches the api process (directly or via the nginx proxy that forwards X-Forwarded-For through) can inject any address they like. Nginx does not strip the client-supplied X-Forwarded-For before appending its own; only the first comma-separated element is used, so an attacker sending `X-Forwarded-For: 1.2.3.<n>` gets a fresh rate-limit bucket per request. The credentialLimiter (routes/auth.js) then never triggers, and every bcrypt.compare attempt on /login succeeds through to the password hash check.

#### Impact
An unauthenticated attacker can bypass the in-process credentialLimiter that protects /api/auth/login and /api/auth/register by rotating the X-Forwarded-For header value on each request. This defeats the primary application-layer control against credential stuffing and account brute-force against the bcrypt password store.

#### Exploit scenario
Attacker scripts POST /api/auth/login with `X-Forwarded-For: 10.0.0.<i>` where i increments each request. Each request lands in a distinct hits Map bucket, so entry.count stays at 1 and the 429 branch is never hit. The attacker can now brute-force passwords or run credential-stuffing at the network's full throughput, gated only by nginx's 10r/m zone (which is itself per source IP and can be defeated by rotating source addresses through commodity proxies).

#### Preconditions
- Attacker can reach /api/auth/login through the merchant nginx (public endpoint)
- nginx forwards X-Forwarded-For to the api container (default proxy behavior)

```
function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return String(forwarded).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}
```

#### How to fix
Do not read X-Forwarded-For directly from the request; call app.set('trust proxy', <hop count or specific CIDR>) once and use req.ip so Express strips untrusted values, or hard-code the key to req.socket.remoteAddress when the app knows it sits behind a single reverse proxy. Combine with an account-scoped counter (email or user id) so a distributed attack against one account is also throttled.

**Exploitability:** Pre-auth rate-limit key spoof via X-Forwarded-For. Nullifies credentialLimiter, feeding brute-force against F21 (timing enumeration) and F11 (existence oracle) to enumerate then crack accounts unhindered.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — XFF is untrusted, nginx forwards the client-supplied header, and rotating XFF yields a fresh bucket per request, defeating the auth rate limit.

### 9. [MEDIUM] Missing security response headers (HSTS/CSP/XFO/XCTO)
**Class:** CWE-693: Protection Mechanism Failure
**CWE:** CWE-693: Protection Mechanism Failure - https://cwe.mitre.org/data/definitions/693.html
**File:** `Node JS/web/nginx.conf:28-109`
**CVSS 3.1:** **4.2** (Medium) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *internal-network position required*
**Confidence:** 0.90 (1 run agreed)

#### Description
The server block at nginx.conf L28–L109 configures TLS, rate-limits, proxy_pass rules, and try_files, but never issues an `add_header` for `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, or `Referrer-Policy`. The API layer (api/src/app.js L14–L37) also installs no helmet/equivalent middleware and only mounts `cors()`, `express.json()`, `cookieParser()`. Combined with the design that stores the access token in browser storage (script-accessible), the absence of a CSP means script injection anywhere in the SPA — including third-party content, dev-tooled snippets, or an admin review-body render — reads the JWT and posts it to an attacker origin; absence of X-Frame-Options allows framing the app for clickjacking on state-changing admin forms (Admin.jsx updatePrice, role changes); absence of HSTS allows a first-visit downgrade to plaintext HTTP where the 301-only :80 vhost is trivially MITM-able (the redirect happens BEFORE the browser has an HSTS pin).

#### Impact
The edge proxy emits no HSTS, CSP, X-Frame-Options, X-Content-Type-Options, or Referrer-Policy headers. Because the SPA persists the HS256 access JWT in localStorage (see AuthContext usage), any reflected/stored XSS in the SPA — or a malicious iframe embedding it — is silently upgraded to full session theft against every logged-in user, and downgrade attacks against the TLS listener are unmitigated after first-visit.

#### Exploit scenario
1) A user visits https://shop over a hostile Wi-Fi network for the first time; the attacker MITMs the initial http://shop navigation and never issues the 301, capturing subsequent credentials/JWTs (no HSTS pin exists to block this). 2) Alternatively, any stored XSS vector (e.g., a review body rendered without escaping) exfiltrates `localStorage['token']` to `https://evil/`, and — with no CSP `connect-src` allowlist — the browser permits the outbound POST. The attacker then makes authenticated API calls for 12h (access-token TTL).

#### Preconditions
- Any XSS sink in the SPA OR one-time MITM opportunity on the victim's first visit
- SPA continues to hold the access JWT in a script-accessible store

```
server {
    listen 443 ssl;
    server_name _;
    root /usr/share/nginx/html;
    ...
    ssl_certificate     /certs/cert.pem;
    ssl_certificate_key /certs/key.pem;
    ssl_protocols       TLSv1.2;
    # <-- no add_header Strict-Transport-Security / CSP / X-Frame-Options / X-Content-Type-Options
    ...
    location / {
        limit_req zone=static burst=80 nodelay;
        try_files $uri /index.html;
    }
}
```

#### How to fix
In the 443 server block add: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`, `add_header X-Content-Type-Options nosniff always;`, `add_header X-Frame-Options DENY always;`, `add_header Referrer-Policy no-referrer always;`, and a `Content-Security-Policy` restricted to `'self'` with an explicit `connect-src` for the API/FauxPay origins. Also install `helmet()` in api/src/app.js right after `const app = express();` to apply the same defaults if nginx is ever bypassed.

**Exploitability:** No HSTS/CSP/XFO/XCTO. Enables downgrade capture of F10 refresh cookie, clickjacking of admin mutations, and XSS→JWT theft from localStorage. Chain amplifier rather than standalone RCE.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — nginx.conf L28-L109 is verified to omit HSTS, CSP, XFO, XCTO, and Referrer-Policy; api/src/app.js has no helmet. Scanner's localStorage claim is wrong (token is in-memory, refresh is httpOnly cookie), but the header gap still enables first-visit HSTS-downgrade MITM, clickjacking on admin state-changing routes, and amplifies any XSS via the httpOnly refresh cookie — impact is limited but real, not hypothetical.

### 10. [MEDIUM] Raw PAN/CVV posted through merchant origin
**Class:** CWE-319: Cleartext Transmission of Sensitive Information
**CWE:** CWE-319: Cleartext Transmission of Sensitive Information - https://cwe.mitre.org/data/definitions/319.html
**File:** `Node JS/web/src/api/client.js:152-161`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.85 (1 run agreed)

#### Description
The SPA collects PAN and CVV in plain form fields (Checkout.jsx:108-133) and calls `tokenizeCard(card)` which stringifies them and POSTs to /fauxpay/tokenize. The comment on lines 147-151 explicitly notes that in production this must be replaced by a processor-hosted iframe so 'Our origin never sees the PAN' — the shipped code violates that invariant. Because nginx logs request lines and (with typical debug configs) request bodies, and because /fauxpay/ shares the merchant origin, any operator log-aggregation pipeline harvests full card data.

#### Impact
`tokenizeCard()` posts the full card_number, exp_month/year, and CVV from the browser to `${FAUXPAY_BASE_URL}/tokenize`, which per the deployed nginx.conf resolves to `/fauxpay/tokenize` on the merchant domain. All cardholder data traverses merchant infrastructure (nginx TLS-terminates and proxies), which places merchant nginx logs, error handlers, and any adjacent workload inside PCI-DSS scope and exposes CVV/PAN to nginx `access_log` or any accidental body logging.

#### Exploit scenario
A JavaScript XSS on any merchant page reads window.fetch responses on same-origin /fauxpay/tokenize before submission, or an operator with read access to nginx access_log/error_log recovers PAN+CVV pairs from body-logging or accidental error dumps. Either yields raw usable card data because tokenization happens on-domain rather than out-of-scope on the processor.

#### Preconditions
- SPA served through the merchant nginx (as shipped)
- Card details entered by a real customer

```
export async function tokenizeCard({ card_number, exp_month, exp_year, cvv }) {
  const res = await fetch(`${FAUXPAY_BASE_URL}/tokenize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ card_number, exp_month, exp_year, cvv }),
  });
```

#### How to fix
Do not accept PAN or CVV at the merchant origin. Replace `tokenizeCard` with a hosted-fields / iframe integration served from the processor's domain so cardholder data never crosses merchant infrastructure. Remove the /fauxpay/ location from web/nginx.conf.

**Exploitability:** Raw PAN/CVV traverses merchant origin. PCI-scope-expanding leak; combined with F8 processor-error echo, becomes a card-testing oracle. UI:R lowers score but harvesting via nginx logs is passive.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — PAN/CVV verifiably traverse the merchant origin via same-origin tokenize POST; any merchant-origin XSS captures raw card data, and the design violates the invariant the code itself documents.

### 11. [MEDIUM] Stock decremented pre-charge, never restored on payment failure
**Class:** CWE-840: Business Logic Errors
**CWE:** CWE-840: Business Logic Errors - https://cwe.mitre.org/data/definitions/840.html
**File:** `Node JS/api/src/routes/orders.js:61-74`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
The checkout handler runs a knex transaction that both creates the order and decrements widgets.stock_quantity (lines 47-66). Only AFTER the transaction commits does it call fauxpay.charge (line 70). If the charge throws (network error, insufficient funds, processor 4xx/5xx) the catch block on line 71-74 only updates the order's status to 'cancelled' — it never re-increments widgets.stock_quantity for the line items. An attacker with a valid card_token that reliably declines (or by pointing at an unreachable processor) can loop this endpoint to drain stock without ever paying, since server-side stock is deducted before payment is authorized.

#### Impact
Any authenticated customer can permanently zero out inventory of any active widget by submitting checkouts whose payments fail. The order is marked 'cancelled' but the widget stock_quantity is not incremented back, enabling a low-cost denial-of-inventory attack against the entire catalog (competitor sabotage, self-DoS).

#### Exploit scenario
Attacker registers an account, adds N units of a widget to their cart, obtains any card_token that will decline (or exhausts their card so /charge returns a 4xx), and POSTs /api/orders. The transaction decrements widgets.stock_quantity by N; charge fails; order is cancelled but stock stays deducted. Repeat until stock_quantity is 0, making the widget appear out-of-stock to all real customers.

#### Preconditions
- Valid customer JWT (self-registration is open)
- Ability to cause fauxpay.charge to reject (declining test tokens or provoking any 4xx/5xx)

```
for (const li of lineItems) {
  await trx('widgets').where({ id: li.widget_id }).decrement('stock_quantity', li.quantity);
}
...
} catch (err) {
  await db('orders').where({ id: order.id }).update({ status: 'cancelled' });
  return res.status(payErrorStatus(err)).json({ error: 'Payment failed', detail: err.data?.error });
}
```

#### How to fix
Either (a) authorize the charge BEFORE decrementing stock and only decrement inside the same transaction as marking the payment captured, or (b) in the catch block at line 71-74, restore stock by iterating line items and calling `.increment('stock_quantity', li.quantity)` within a compensating transaction before returning the error. Also delete/void the created order_items on rollback.

**Exploitability:** Post-auth stock drain via failed charge loop. Combined with F4 (race) and F22 (price race) forms an inventory-integrity primitive; competitor-DoS and free-goods logic feasible.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — stock decrement commits before payment; catch path never restores it, and self-registration + attacker-chosen declining card_token make looping trivial.

### 12. [MEDIUM] No email verification enables account pre-hijacking
**Class:** CWE-287: Improper Authentication
**CWE:** CWE-287: Improper Authentication - https://cwe.mitre.org/data/definitions/287.html
**File:** `Node JS/api/src/routes/auth.js:31-55`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.85 (1 run agreed)

#### Description
POST /api/auth/register at auth.js:31 accepts arbitrary email/password/full_name from the request body, inserts the user with role='customer', and immediately issues an access token plus a refresh cookie (issueSession, line 53). There is no email format validation, no case/normalization step, no confirmation-token issuance, and no 'unverified' state on the user row. The pre-existence check at line 40-43 unconditionally responds 409 when the email exists, which both (a) confirms account existence to any anonymous caller (enumeration) and (b) permanently blocks the true owner from registering after an attacker has squatted their address. There is also no password-reset / recovery flow visible in the auth router, so once an email is squatted the legitimate owner has no recovery path and remains locked out. When a victim later realises and tries to register, they get 'account already exists' and cannot dislodge the attacker; if any future feature (SSO merge, password reset via email) is added it would inherit an attacker-controlled shadow account.

#### Impact
An unauthenticated attacker can register an account using a victim's email address before the victim signs up. Because there is no proof-of-ownership step (no verification email, no confirmation link), the account is immediately usable and prevents the legitimate owner from ever registering that email themselves. Combined with the 409 leak, this also enables bulk user enumeration.

#### Exploit scenario
Attacker calls POST /api/auth/register with {email:'victim@corp.example', password:'[REDACTED-SECRET]', full_name:'V'} — 201 with token. Victim later tries to register the same address and receives 409 'An account with that email already exists'; they cannot reclaim it and have no recovery endpoint. Meanwhile the attacker holds a valid session bound to the victim's email, receives any future correspondence delivered by email address, and can be silently upgraded to whatever downstream identity ties to that email (e.g., support contacting via the address on file, or a future merge flow).

#### Preconditions
- Attacker knows or guesses target's email address (or iterates a list)
- Registration endpoint is publicly reachable (default via nginx /api/)

```
router.post('/register', credentialLimiter, asyncHandler(async (req, res) => {
  const { email, password, full_name } = req.body || {};
  ...
  const existing = await db('users').where({ email }).first();
  if (existing) {
    return res.status(409).json({ error: 'An account with that email already exists' });
  }
  const password_hash = await bcrypt.hash(password, 10);
  const [row] = await db('users').insert({ email, password_hash, full_name, role: 'customer' }).returning(...);
  ...
  const token = await issueSession(res, user);
  res.status(201).json({ token, user });
}));
```

#### How to fix
Enforce proof-of-ownership before the account is usable: on register, create the row in an 'unverified' state, send a signed one-time verification link to the supplied address, and refuse login/session issuance until the link is consumed. Return a uniform 202 response regardless of whether the email already exists (eliminating the 409 enumeration oracle at auth.js:41-43). Normalize email to lower-case before the existence check and unique index. Add a password-reset flow that invalidates existing sessions so a squatted account can be reclaimed by proving mailbox control.

**Exploitability:** Pre-auth account pre-hijacking; no email verification, no recovery. Chains with F11 enumeration to systematically squat known victim addresses.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — public /api/auth/register issues a full session with no email verification, no recovery path, and confirms existing emails via 409, giving anonymous attackers both enumeration and pre-hijack of arbitrary addresses.

### 13. [MEDIUM] User enumeration via registration response
**Class:** CWE-204
**CWE:** CWE-204 - https://cwe.mitre.org/data/definitions/204.html
**File:** `Node JS/api/src/routes/auth.js:40-43`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
POST /api/auth/register queries the users table for the submitted email and, if a row exists, returns a 409 with a message that unambiguously discloses account presence. There is no rate-limiter tuned for enumeration on this response class (the same credentialLimiter allows many small POSTs), and no delay/normalized response between the exists/does-not-exist branches. Untrusted input (req.body.email) reaches the disclosing sink at line 42.

#### Impact
An unauthenticated attacker can enumerate valid customer/admin email addresses by attempting to register each candidate address. The endpoint returns HTTP 409 with an explicit 'An account with that email already exists' message when the address is registered, and HTTP 201 otherwise. Confirmed email lists then feed credential stuffing, password reset abuse, and phishing.

#### Exploit scenario
Attacker scripts POST /api/auth/register with each email from a target list and a random password. Every 409 confirms the address is registered on the site; every 201 is either a new signup they can immediately delete or ignore. In minutes they harvest a validated customer list to use in credential stuffing against /api/auth/login (where a valid email produces bcrypt-length responses).

#### Preconditions
- Attacker can reach /api/auth/register (default public endpoint)

```
const existing = await db('users').where({ email }).first();
if (existing) {
  return res.status(409).json({ error: 'An account with that email already exists' });
}
```

#### How to fix
Return an identical 202/'confirmation email sent' response for both branches and finalize registration only after email verification, or throttle 409 responses per source aggressively. Change the branch at api/src/routes/auth.js:41-43 to not distinguish the existing-account case in the wire response.

**Exploitability:** Pre-auth enumeration via 409 branch. Feeds F13-defeated brute force and F17 password reuse checks. Standalone confidentiality only.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — public /register returns a distinct 409 on existing emails with only a per-IP 10/15min limiter, enabling account enumeration

### 14. [MEDIUM] Username enumeration via bcrypt timing skip on missing user
**Class:** CWE-208
**CWE:** CWE-208 - https://cwe.mitre.org/data/definitions/208.html
**File:** `Node JS/api/src/routes/auth.js:57-66`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.85 (1 run agreed)

#### Description
The condition `if (!user || !(await bcrypt.compare(password, user.password_hash)))` short-circuits when `user` is undefined, so no bcrypt work is performed. bcrypt with cost 10 (line 45) takes 50-100 ms on typical hardware, giving a large, reliably-measurable timing gap between the two branches.

#### Impact
An attacker learns which email addresses have accounts by measuring response latency of POST /api/auth/login. Requests for non-existent users skip bcrypt.compare entirely and return in a few milliseconds; requests for existing users incur ~50-100 ms of bcrypt work. This produces a directory of valid emails for phishing or targeted credential-stuffing.

#### Exploit scenario
Attacker scripts POST /api/auth/login with each candidate email and a fixed dummy password; requests taking <10 ms indicate 'no such user' while requests taking >40 ms indicate the account exists. Combined with the XFF rate-limit bypass finding, enumeration of an arbitrary email list is trivial.

#### Preconditions
- Reachable /api/auth/login (public)

```
const user = await db('users').where({ email }).first();
if (!user || !(await bcrypt.compare(password, user.password_hash))) {
  return res.status(401).json({ error: 'Invalid email or password' });
}
```

#### How to fix
Compute a dummy bcrypt.compare against a fixed valid hash whenever `user` is not found so both branches perform the same work, then return the same 401. Alternatively normalize the response with a fixed delay above the worst-case bcrypt time.

**Exploitability:** Bcrypt timing enumeration. Redundant with F11 but harder to alert on; chains identically into the F13-bypassed brute force pipeline.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — public login route short-circuits bcrypt on missing user, producing a large, reliably measurable timing oracle; the co-located XFF-trusting rate limiter is trivially bypassable, so enumeration scales.

### 15. [MEDIUM] Missing Idempotency-Key on charge/refund enables double-charge on retry
**Class:** CWE-799
**CWE:** CWE-799 - https://cwe.mitre.org/data/definitions/799.html
**File:** `Node JS/api/src/services/fauxpayClient.js:4-29`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.80 (1 run agreed)
**Also at:** `Node JS/api/src/routes/orders.js:68-89`

*1 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
fauxpayClient.post issues POSTs to /charge and /refund with no Idempotency-Key header (lines 5-12). orders.js:70 awaits charge inside an HTTP handler with no request-level deduplication. If the network drops after the processor debits the card but before the response returns, the caller sees an error, cancels the order (leaving stock over-decremented, per finding above), and the customer's card is charged with no order fulfilled. On the refund path in cs.js, a retried refund request will refund twice.

#### Impact
Any transient network hiccup or client retry can cause the same order to be charged twice (or refunded twice), because no Idempotency-Key header is sent and the processor cannot de-duplicate. Customers see duplicate captures on their card; refunds triggered by CS may double-refund. Combined with the lack of a payments-unique constraint on order_id, orders can accumulate multiple 'captured' payment rows.

#### Exploit scenario
A user clicks 'Place order' twice quickly (or their browser retries on a slow response). Both POSTs reach /api/orders concurrently. Each calls fauxpayClient.charge; both /charge requests reach fauxpay and both succeed with distinct transaction_ids. The customer is billed twice for one intended order.

#### Preconditions
- Authenticated customer or CS user
- Retry / duplicate submission (natural network conditions or intentional double-click)

```
async function post(path, body) {
  const res = await fetch(`${FAUXPAY_BASE_URL}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${FAUXPAY_API_KEY}`,
    },
    body: JSON.stringify(body),
  });
```

#### How to fix
Generate a deterministic Idempotency-Key per logical operation (e.g., `order:<id>:charge`, `refund:<order_id>:<amount>:<sequence>`) and pass it as an `Idempotency-Key` header from fauxpayClient. Have the FauxPay service store and return the original response for repeats within a TTL. Add a unique constraint on payments(order_id, status='captured') to prevent duplicate captured rows.

**Exploitability:** Missing Idempotency-Key → double-charge/double-refund on retry. Combined with F5+F23 an attacker can weaponize retries to multiply refunds through the exposed /refund.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — No Idempotency-Key on outbound /charge or /refund and no server-side request dedup; a retried/double-submitted checkout produces two real card charges, and a retried refund produces two real refunds.

### 16. [MEDIUM] Refresh cookie Secure flag conditional on NODE_ENV
**Class:** CWE-614
**CWE:** CWE-614 - https://cwe.mitre.org/data/definitions/614.html
**File:** `Node JS/api/src/services/tokens.js:49-60`
**CVSS 3.1:** **6.8** (Medium) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.75 (1 run agreed)

#### Description
`setRefreshCookie` sets `secure: process.env.NODE_ENV === 'production'`. The api container in the training docker-compose does not set NODE_ENV=production, so the cookie is created without the Secure attribute. nginx does redirect :80 → :443 via HTTP 301, but the browser attaches the (non-Secure) refresh cookie to the initial HTTP request before it sees the redirect, meaning the token is exposed on the wire. Because refresh tokens carry 7-day validity and mint fresh 12-hour access JWTs, capture is high-value. This matches the T28 threat that the training defaults become production defaults.

#### Impact
The refresh_token cookie (7-day, unrotated until used) is emitted without the `Secure` attribute whenever `NODE_ENV !== 'production'` — the default in the shipped docker-compose training stack. Any browser request from the same site to plain http://<host>/api/auth/... (e.g., a user typing the URL, a mixed-content resource, or a network-adjacent attacker forcing a plaintext navigation) will transmit the cookie in cleartext before the :80→:443 redirect fires, letting a passive on-path attacker steal a long-lived refresh token and mint fresh access JWTs for 7 days.

#### Exploit scenario
A user on hostile Wi-Fi has an authenticated session. The attacker triggers any plain http://shop/api/auth/refresh navigation (e.g., an <img> tag in an unrelated site, an HTTP-only captive-portal probe, or DNS/ARP poisoning to force one plaintext request). The browser attaches the refresh cookie because it lacks the Secure attribute. The attacker captures it, calls /api/auth/refresh with it, and obtains a live access JWT plus a fresh 7-day refresh cookie, effectively hijacking the session indefinitely.

#### Preconditions
- Deployment leaves NODE_ENV unset or non-'production' (the shipped compose default)
- Any single plaintext HTTP request to /api/auth path during the session

```
function setRefreshCookie(res, token) {
  res.cookie(REFRESH_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: REFRESH_COOKIE_PATH,
    maxAge: REFRESH_TOKEN_TTL_MS,
  });
}
```

#### How to fix
Always set `secure: true` on the refresh cookie in tokens.js:56 (or set it based on request protocol, not NODE_ENV) and refuse to boot if NODE_ENV is not 'production'. Additionally, in nginx.conf, add `Strict-Transport-Security` so browsers refuse the initial HTTP request outright.

**Exploitability:** Non-Secure refresh cookie in non-production NODE_ENV. Chains with F9 (no HSTS) for first-visit downgrade capture and then F12 to bypass replay detection.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — cookie ships without Secure under shipped compose; MITM on hostile Wi-Fi can force a top-level nav to /api/auth path and capture the plaintext refresh token, enabling indefinite session hijack via rotation.

### 17. [MEDIUM] Processor error detail forwarded to unauthenticated client
**Class:** CWE-209: Generation of Error Message Containing Sensitive Information
**CWE:** CWE-209: Generation of Error Message Containing Sensitive Information - https://cwe.mitre.org/data/definitions/209.html
**File:** `Node JS/api/src/routes/orders.js:71-74`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.75 (1 run agreed)
**Also at:** `Node JS/api/src/services/fauxpayClient.js:13-19`

*1 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
On line 73 the handler returns `{ error: 'Payment failed', detail: err.data?.error }` — the second field is whatever JSON `error` string the FauxPay server chose to emit. There is no allow-list mapping (e.g., 'declined' vs 'processor_error'); the processor's exact response body reaches the browser. Combined with card-testing via /fauxpay/tokenize this improves signal-to-noise for an attacker distinguishing valid PANs from throwaway BINs.

#### Impact
The API forwards the raw `err.data.error` string returned by FauxPay in the response body, exposing processor-internal error messages (declined-reason strings, AVS/CVV mismatch codes, backend identifiers) to the customer. This aids card-testing/enumeration attackers by revealing which /charge failures are 'insufficient funds' vs 'invalid CVV' vs 'blocked BIN'.

#### Exploit scenario
Attacker checks out with various stolen PANs and observes the `detail` field distinguishing 'card_declined' vs 'invalid_expiry' vs 'insufficient_funds', turning the checkout endpoint into a richer card-validity oracle than /tokenize alone.

#### Preconditions
- Authenticated customer (self-registration open)

```
return res.status(payErrorStatus(err)).json({ error: 'Payment failed', detail: err.data?.error });
```

#### How to fix
Drop the `detail` field entirely, or map err.data.error through an allow-list into a small set of generic strings ('declined', 'processor_unavailable') before returning to the client. Log the raw detail server-side only.

**Exploitability:** Processor error detail leaked. Amplifies card-testing signal for chain F16→/fauxpay/tokenize→F8 oracle.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — processor error string is forwarded verbatim to any authenticated customer with no allow-list; the anti-pattern is real even though the training stub's error vocabulary is thin

### 18. [MEDIUM] Public review endpoint discloses reviewer user_id and full_name
**Class:** CWE-359
**CWE:** CWE-359 - https://cwe.mitre.org/data/definitions/359.html
**File:** `Node JS/api/src/routes/reviews.js:9-23`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *admin/privileged role required*
**Confidence:** 0.70 (1 run agreed)

#### Description
`reviews.js:9-14` registers the endpoint without `requireAuth` and selects `users.full_name` plus `reviews.user_id`. The row is emitted verbatim in the JSON response. Nothing masks the name to initials, and the numeric user_id exposes an oracle for id-based enumeration against other routes (e.g., admin role-change target IDs).

#### Impact
GET /api/widgets/:id/reviews is unauthenticated and returns each reviewer's `full_name` and internal `user_id`. Anyone on the internet can iterate widgets, harvest customer full names, and correlate them with stable internal identifiers — a directory of paying customers plus a mapping to internal keys used by other endpoints.

#### Exploit scenario
Attacker scrapes /api/widgets to list widget IDs, then unauthenticated GETs /api/widgets/{id}/reviews for each, harvesting `{user_id, full_name}` tuples for every reviewer. The resulting list is fed to phishing or credential-stuffing against /api/auth/login, and the user_id column lets the attacker precompute targets for role-escalation POSTs once any admin session is captured.

#### Preconditions
- Application deployed with reviews enabled and any reviewer signed up

```
.select('reviews.id', 'reviews.rating', 'reviews.body', 'reviews.created_at', 'reviews.updated_at', 'reviews.user_id', 'users.full_name');
```

#### How to fix
Do not return the internal `user_id` on the public reviews response, and consider returning a display name (first name + initial) rather than the full legal name. Update the `.select()` in reviews.js:14 to omit `reviews.user_id` for anonymous callers and derive a masked display name in a serializer.

**Exploitability:** Public review endpoint discloses user_id and full_name. Provides ID oracle for admin role-change endpoints, feeding F1-forged admin chains.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — unauthenticated GET returns reviewer full_name and internal user_id; no upstream auth or masking.

### 19. [MEDIUM] Non-constant-time comparison of FauxPay API key
**Class:** CWE-208
**CWE:** CWE-208 - https://cwe.mitre.org/data/definitions/208.html
**File:** `Node JS/fauxpay/src/server.js:43-48`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.65 (1 run agreed)

#### Description
requireApiKey compares `key !== API_KEY` using JS string equality. V8's string-equality short-circuits on the first unequal byte, so a request whose bearer starts with a correct prefix takes measurably longer to reject than one that differs in the first byte. The in-file comment acknowledges this and defers to a real timingSafeEqual — but the training deployment is being threat-modelled as a real internet-facing service, and the FauxPay container is exposed through merchant nginx via /fauxpay/.

#### Impact
The processor's shared bearer key is validated with `!==`, which returns as soon as the first differing character is found. An attacker who can measure high-precision response latency (localhost neighbour, colocated container) can recover the key byte-by-byte. Once recovered, the key authorises /charge and /refund — arbitrary money movement.

#### Exploit scenario
Attacker in the same host or network sends /fauxpay/refund with varying `Authorization: Bearer <candidate>` prefixes, measuring server response time; longest response indicates the longest matching prefix. Extending byte-by-byte recovers FAUXPAY_API_KEY, after which the attacker calls /fauxpay/refund with any known transaction_id to move funds.

#### Preconditions
- Ability to time responses accurately (low-latency network access)
- Knowledge of at least one transaction_id to abuse the recovered key

```
function requireApiKey(req, res, next) {
  const header = req.headers.authorization || '';
  const key = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (key !== API_KEY) return res.status(401).json({ error: 'Invalid FauxPay API key' });
  next();
}
```

#### How to fix
Compare using `crypto.timingSafeEqual(Buffer.from(key), Buffer.from(API_KEY))` after length check; return the same 401 shape either way.

**Exploitability:** Non-constant-time API-key compare. Practical remote-timing extraction over WAN is extremely difficult; blocked in practice by network jitter. Useful only as theoretical stepping-stone; F5's public default key already trivializes the same asset.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — non-constant-time bearer comparison reachable via nginx `/fauxpay/`; class-valid but exploitability is marginal due to nanosecond-scale JS timing signal and 20 r/m nginx rate limit.

### 20. [LOW] TOCTOU on stock check enables overselling / negative stock
**Class:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
**CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition - https://cwe.mitre.org/data/definitions/367.html
**File:** `Node JS/api/src/routes/orders.js:30-63`
**CVSS 3.1:** **3.1** (Low) — `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)

#### Description
Lines 30-39 read widgets rows via a plain select (outside any transaction) and compare widget.stock_quantity to requested quantity. Then in the transaction on lines 61-63, an unconditional `.decrement('stock_quantity', li.quantity)` is issued. There is no row-lock (`forUpdate()`), no `where('stock_quantity', '>=', li.quantity)` guard on the decrement, and no verification after the decrement that stock is still >= 0. Under PostgreSQL's default READ COMMITTED isolation and concurrent traffic, the check-then-act sequence is racy: two orders for the last unit both observe stock=1, both decrement, resulting in stock=-1 while both charges succeed.

#### Impact
Concurrent checkouts read widget.stock_quantity before decrementing it, with no SELECT ... FOR UPDATE and no post-decrement validation. Two customers hitting checkout at the same time for the last remaining unit can both pass the stock check and both decrement, causing negative stock, oversold merchandise, and integrity loss in the inventory ledger.

#### Exploit scenario
Attacker (or two colluding buyers) races two POSTs to /api/orders for the same low-stock widget. Both requests read stock_quantity=1, both pass validation, both decrement inside their own transactions, and both charges succeed. The merchant now owes two units when only one exists; widgets.stock_quantity is -1.

#### Preconditions
- Any authenticated customer
- A widget with low stock relative to concurrent demand

```
if (widget.stock_quantity < item.quantity) { return res.status(400)... }
...
await trx('widgets').where({ id: li.widget_id }).decrement('stock_quantity', li.quantity);
```

#### How to fix
Inside the transaction, use `trx('widgets').where('id', li.widget_id).andWhere('stock_quantity', '>=', li.quantity).decrement('stock_quantity', li.quantity)` and check the affected-row count — abort the transaction if 0. Alternatively perform the stock check inside the transaction with `forUpdate()`.

**Exploitability:** TOCTOU on stock enables overselling / negative stock. Concurrency required (AC:H). Chains with F2 to weaponize inventory abuse.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — plain non-locking SELECT then unconditional decrement inside a READ COMMITTED transaction, no `forUpdate`, no conditional `where('stock_quantity','>=',qty)`, reachable by any authenticated user via POST /api/orders.

### 21. [LOW] Order re-price races admin price mutations
**Class:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)
**CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition) - https://cwe.mitre.org/data/definitions/362.html
**File:** `Node JS/api/src/routes/orders.js:28-45`
**CVSS 3.1:** **3.1** (Low) — `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.70 (1 run agreed)

#### Description
The re-price step at line 30 (`db('widgets').whereIn('id', widgetIds)`) runs outside the transaction started at line 47. Between reading widgets.price_cents and inserting order_items with unit_price_cents=widget.price_cents (line 43/59), an admin PATCH /admin/widgets/:id can commit a new price. The transaction sees the stale in-memory `widget.price_cents` snapshot and charges FauxPay `totalCents` computed from it, regardless of the price the customer currently sees or the price admins believe is in effect.

#### Impact
An admin lowering a widget's price after the SELECT at line 30 but before the order row is inserted at line 48 results in an order stored at the pre-change price and the customer charged the higher amount despite paying at the newer displayed price; the reverse allows the customer to lock in an older lower price after a raise. Impacts pricing integrity and enables scripted 'flash sale' exploitation.

#### Exploit scenario
Attacker watches /api/widgets and detects a price drop. They fire many concurrent POST /api/orders in a loop starting just before the change is expected (e.g., a known promo window). Some requests capture the old-then-new mismatch and receive orders at the price they prefer while charging the other; combined with the TOCTOU stock issue above, this compounds inventory and financial loss.

#### Preconditions
- Valid customer JWT
- Some price mutation happens (scheduled promo, admin churn) or attacker is racing an admin action

```
const widgets = await db('widgets').whereIn('id', widgetIds).andWhere({ is_active: true });
...
const totalCents = lineItems.reduce((sum, i) => sum + i.unit_price_cents * i.quantity, 0);
const order = await db.transaction(async (trx) => { ... });
```

#### How to fix
Read widget rows for pricing inside the transaction using `SELECT ... FOR UPDATE` (or knex `.forUpdate()`), and derive totalCents inside the transaction rather than from the outside snapshot at line 45. Ensure the same rows locked for pricing are locked for stock decrement.

**Exploitability:** Order re-price race outside transaction. Chains with F3 (no audit on admin price changes) so a colluding/forged admin can flip price mid-checkout with no attribution.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Widget prices are read outside the order transaction and never re-verified/locked inside it, letting a concurrent admin PATCH /admin/widgets/:id create a stale-price window that a customer can race for financial gain.

### 22. [LOW] No audit log for admin catalog mutations or role changes
**Class:** CWE-778
**CWE:** CWE-778 - https://cwe.mitre.org/data/definitions/778.html
**File:** `Node JS/api/src/routes/admin.js:10-37`
**CVSS 3.1:** **2.7** (Low) — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *PR:H - high-privilege auth required*
**Confidence:** 0.80 (1 run agreed)

#### Description
The admin router applies `requireAuth, requireRole('admin')` (line 8) and then handles high-impact mutations (POST /widgets, PATCH /widgets/:id, and the role-change / review-delete endpoints listed in the entry-point inventory at admin.js:52-80). None of these handlers emit a log entry or write to any audit table before or after the mutation. Combined with the absence of a `logins` audit table, there is no way to answer 'who changed this price to $0.01 at 3am, from where?'. This matches the T24 repudiation finding in the threat model but is unmitigated at code level.

#### Impact
Widget create/update (and the role-change / review-moderation endpoints reached via the same router at admin.js) execute with no audit record of who performed the action, from what IP, or what values were changed. A compromised or malicious admin — reachable because JWT role is a self-asserted claim signed with a secret that may be the committed default (T1/T4) — can silently zero prices, elevate accounts, or delete reviews with no post-hoc attribution.

#### Exploit scenario
An insider (or an outside attacker who forged an admin JWT with the default JWT_SECRET) issues PATCH /api/admin/widgets/:id to slash prices to zero, buys stock, then reverts. Because no row records the change, the price manipulation cannot be attributed to a specific admin session, and no alert fires on the anomalous mutation.

#### Preconditions
- Attacker holds or forges an admin JWT
- Operator lacks database-level auditing (pg_audit) as compensating control

```
router.use(requireAuth, requireRole('admin'));

router.post('/widgets', asyncHandler(async (req, res) => {
  ...
  const [row] = await db('widgets').insert({...}).returning('id');
  const widget = await db('widgets').where({ id: row.id ?? row }).first();
  res.status(201).json(widget);
}));
```

#### How to fix
In every admin.js and cs.js mutating handler, insert a row into an append-only audit_log table capturing (actor_user_id, actor_ip, route, target_id, before, after, timestamp). Persist role changes, refunds, price/stock edits, and review deletions. Also emit a structured log line to the standard sink for real-time alerting.

**Exploitability:** No audit for admin catalog/role changes. Non-repudiation gap; enables F22 mid-checkout price manipulation to be untraceable after F1-forged admin takeover.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Admin router handlers for widget/category/user-role/review mutations write straight to the DB with no audit table, no logging middleware, and no per-handler audit call; confirmed absent in code, migrations, and app wiring.

### 23. [LOW] No logging of failed logins or successful authentication events
**Class:** CWE-778
**CWE:** CWE-778 - https://cwe.mitre.org/data/definitions/778.html
**File:** `Node JS/api/src/routes/auth.js:57-73`
**CVSS 3.1:** **3.7** (Low) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.85 (1 run agreed)

#### Description
In `router.post('/login', ...)` the failure path at lines 64-66 returns a 401 without calling any logger. The success path at lines 68-72 issues a session token and returns without logging that user X authenticated from IP Y. `revokeSession` (logout) at line 92 similarly emits nothing. Combined with the same absence in /register, /refresh, and all admin.js state-changing routes (widget create/update at admin.js:10-37, role changes, etc.), there is no audit trail for any security-relevant identity event. The only logging call in the entire API is the generic `console.error(err)` in app.js:33, which fires only on thrown exceptions — an intentional 401 is not thrown.

#### Impact
Neither the credential-mismatch branch nor the success branch of /api/auth/login writes anything to a log or audit store. Brute-force / credential-stuffing campaigns against the exposed login endpoint (only rate-limited in-process by an X-Forwarded-For-trusting counter, T17) produce zero detectable signal, and a successful post-breach login is indistinguishable from a legitimate one during forensics. This defeats OWASP A09 baseline expectations for an internet-facing merchant auth endpoint that guards payment/refund flows.

#### Exploit scenario
An attacker runs a low-and-slow credential-stuffing attack against /api/auth/login using rotated X-Forwarded-For headers (which the in-process limiter honours per rateLimit.js:5-9). The operator has no per-account failure log, no source-IP tally, and no alertable event stream, so the campaign runs until a hit lands and the attacker mints a valid JWT for a real customer or, worse, an admin seed account.

#### Preconditions
- Login endpoint is reachable from the internet via nginx (as designed)
- No external WAF or SIEM inspects raw request bodies

```
  const user = await db('users').where({ email }).first();
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = await issueSession(res, user);
  res.json({
    token,
    user: { id: user.id, email: user.email, full_name: user.full_name, role: user.role },
  });
```

#### How to fix
Add structured logging (with sanitisation to strip \r\n from any user-supplied field such as email) to both branches of /login, to /register, /refresh, /logout, and to all admin/CS mutations. Log outcome (success/fail/lockout), user id or email, IP, user agent, and correlation id. Route these to a persistent audit table or an external log sink, not stdout only.

**Exploitability:** No login success/failure logging. Ensures F13-enabled brute force and F1 JWT forgery leave no detection surface.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — No audit logging on any auth or admin state-changing route; only a generic 500-path `console.error` exists. Externally reachable via nginx, no upstream control provides equivalent event recording.

### 24. [LOW] Refresh-token replay/family-revoke event is silently swallowed
**Class:** CWE-778
**CWE:** CWE-778 - https://cwe.mitre.org/data/definitions/778.html
**File:** `Node JS/api/src/services/tokens.js:87-93`
**CVSS 3.1:** **3.7** (Low) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.80 (1 run agreed)

#### Description
`rotateSession` at line 87 explicitly branches on `existing.revoked_at`, which by design means an already-consumed refresh token was replayed. The comment above (lines 77-80) states this is the token-theft heuristic — 'either a copy leaked or a client raced itself'. On that path the code mass-revokes all outstanding tokens for the user (lines 88-91) and returns null, but there is no `console.warn`, structured log, audit-table insert, or notification. The very event the design says is a probable compromise produces zero observable output. Same for expired-token attempts (line 95) and unknown user_id (line 101).

#### Impact
The single strongest indicator of a stolen refresh token — the presentation of an already-consumed token — is detected here and used to revoke the whole token family, but no log, metric, or alert is emitted. Incident responders are left with no signal that a session was likely compromised, so credential theft, XSS-exfil of the refresh cookie, or a leaked backup goes unnoticed until the victim complains.

#### Exploit scenario
An attacker who has stolen a refresh token via cookie theft (network MITM against the self-signed cert, or supply-chain XSS) uses it once to mint a new access token. When the legitimate user returns, their still-cached refresh cookie triggers the replay branch, forcing them to re-login — but no operator ever learns a compromise occurred, so the underlying leak (malicious dependency, poisoned CDN, phished session) is never investigated, and the same class of theft happens repeatedly against other users.

#### Preconditions
- A refresh token has been stolen or replayed
- No external log-shipping catches the missing audit event

```
  if (existing.revoked_at) {
    await db('refresh_tokens')
      .where({ user_id: existing.user_id })
      .whereNull('revoked_at')
      .update({ revoked_at: db.fn.now() });
    return null;
  }

  if (new Date(existing.expires_at) <= new Date()) return null;
```

#### How to fix
Emit a security-level log entry (with user_id, source IP, user agent, and refresh-token id) on every non-success branch of rotateSession — especially the replay-of-consumed-token branch — and, ideally, insert an audit row that surfaces in the admin console. Do the same for revokeSession and for logins after a family revocation so responders can correlate.

**Exploitability:** Family-revoke event silently swallowed. Even where F12 race doesn't apply, the detection primitive produces zero output — pure detection gap.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — replay/family-revoke branch is real, unlogged, and reachable via public /api/auth/refresh; no logger or audit table exists anywhere in the API to catch it.

### 25. [MEDIUM] Exchange workflow skips required states and settles no price difference
**Class:** CWE-840: Business Logic Errors
**CWE:** CWE-840: Business Logic Errors - https://cwe.mitre.org/data/definitions/840.html
**File:** `Node JS/api/src/routes/cs.js:93-114`
**CVSS 3.1:** **6.7** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.90 (1 run agreed)
**Added by analyst:** 2026-09-19 — missed by the automated threat-fallback pass (T20 in the pre-verification threat model received no dedicated verification chunk; see note on ranked-threat coverage below the Ranked threats table).

#### Description
`PATCH /exchanges/:id` accepts any `status` in `['requested', 'received', 'completed', 'rejected']` (line 95) and writes it unconditionally (line 105) — there is no check that the current `exchange.status` permits the requested transition, so a request can jump straight from `requested` to `completed` without ever passing through `received`. Separately, the `exchanges` table (`db/migrations/20260101000008_create_refunds_exchanges.js:13-25`) has no price, payment, or processor-reference column at all, and neither `POST /orders/:id/exchanges` nor this handler ever looks up `widgets.price_cents` for `returned_widget_id` or `replacement_widget_id`. No code path anywhere in the API computes or charges a price delta between the returned and replacement items. `returned_widget_id`/`returned_quantity` are also taken from the request body with no check that they match an item actually present on the order (no join against `order_items`).

#### Impact
Any customer_service session (legitimate, or a JWT forged via T1's committed default JWT_SECRET) can manufacture a "completed" exchange for an order that swaps a cheap or non-existent returned item for an expensive replacement widget, with zero settlement and zero verification that the returned item was ever part of the order. This is a direct free-merchandise primitive with no compensating control, and it chains with Finding #1 (JWT forgery) and Finding #22 (no audit log on staff mutations) for undetectable abuse.

#### Exploit scenario
A customer_service agent (or an attacker holding a forged customer_service JWT) calls `POST /api/cs/orders/<id>/exchanges` with `returned_widget_id` set to any cheap widget and `replacement_widget_id` set to the most expensive widget in the catalog, then immediately calls `PATCH /api/cs/exchanges/<exchange_id>` with `{"status":"completed"}`. The order is marked `exchanged`, no payment is created or captured, and no field records a price difference — the replacement ships at no cost.

#### Preconditions
- A customer_service session, obtainable legitimately, via the seeded default credentials (Finding #2), or via a forged JWT (Finding #1)
- Any existing order ID to attach the exchange to

```
router.patch('/exchanges/:id', asyncHandler(async (req, res) => {
  const { status, notes } = req.body || {};
  if (status && !['requested', 'received', 'completed', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  ...
  if (status) updates.status = status;
  await db('exchanges').where({ id: req.params.id }).update(updates);
  if (status === 'completed') {
    await db('orders').where({ id: exchange.order_id }).update({ status: 'exchanged' });
  }
```

#### How to fix
Enforce a state machine instead of a value allowlist: only permit `requested → received`, `received → completed`, and `requested|received → rejected`, rejecting any other transition with 409. Add a `price_delta_cents` computation at `received` time (`widgets.price_cents[replacement] - widgets.price_cents[returned]`) and require a captured payment (or a refund, if negative) via `fauxpayClient` before allowing the transition to `completed`. Validate `returned_widget_id`/`returned_quantity` against `order_items` for the same order before accepting the exchange request.

**Exploitability:** Business-logic gap with no compensating control; requires only a staff-role session (or Finding #1's JWT forgery) and two HTTP calls. Direct, repeatable financial loss.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — `cs.js:93-114` verified to allow any status transition and to never reference `widgets.price_cents` or create a payment/refund row; `20260101000008_create_refunds_exchanges.js:13-25` confirms the `exchanges` table has no settlement column. Not present among this report's Findings or Dropped Findings prior to this pass; the corresponding pre-verification threat (T20) never received deep-dive coverage.

## Exploit Chains

### [CRITICAL] Committed JWT_SECRET → forged admin → bulk PII exfil + price/role manipulation
**Path:** #1 Committed default JWT_SECRET enables full auth bypass → #7 Unbounded pagination on staff orders endpoint enables bulk PII exfiltration → #22 No audit log for admin catalog mutations or role changes → #21 Order re-price races admin price mutations

Read JWT_SECRET from checked-in .env; sign {role:'admin'|'customer_service'} tokens; call GET /cs/orders once for the entire orders×users dataset (F7); mutate widget prices with no audit (F3); race price mutation against in-flight checkouts (F22) to charge inflated totals — all with zero attribution due to F3+F15.

### [CRITICAL] Public FauxPay API + public bearer + token replay → arbitrary money movement
**Path:** #3 Merchant nginx prefix-proxies entire FauxPay API externally → #4 Card tokens never consumed — unlimited replay on /charge → #15 Missing Idempotency-Key on charge/refund enables double-charge on retry

External attacker calls /fauxpay/tokenize (or reuses any observed token), then POSTs /fauxpay/charge with the committed FAUXPAY_API_KEY via the merchant-nginx prefix proxy. Tokens are never consumed (F23) so replay is unlimited. Missing Idempotency-Key (F0) further enables refund multiplication on /fauxpay/refund.

### [CRITICAL] Seeded default admin creds → full takeover without JWT forgery
**Path:** #2 Hardcoded default admin / customer_service password in seed → #7 Unbounded pagination on staff orders endpoint enables bulk PII exfiltration → #22 No audit log for admin catalog mutations or role changes

Attacker logs in as admin@example / customer_service@example with 'ChangeMe123!' from the seed script and immediately obtains the same primitives as the JWT-forgery chain — bulk PII dump and unaudited catalog/role mutation.

### [HIGH] Rate-limit bypass → enumeration → password brute force
**Path:** #8 Rate-limit key spoofable via unvalidated X-Forwarded-For → #13 User enumeration via registration response → #14 Username enumeration via bcrypt timing skip on missing user → #2 Hardcoded default admin / customer_service password in seed

Attacker rotates X-Forwarded-For per request to defeat credentialLimiter (F13); enumerates valid accounts via 409 on /register (F11) and bcrypt-skip timing on /login (F21); then brute-forces or tests the seeded 'ChangeMe123!' (F17) and any common passwords against the discovered accounts.

### [HIGH] First-visit downgrade → refresh cookie theft → TOCTOU replay
**Path:** #9 Missing security response headers (HSTS/CSP/XFO/XCTO) → #16 Refresh cookie Secure flag conditional on NODE_ENV → #5 TOCTOU in refresh-token rotation defeats replay detection → #24 Refresh-token replay/family-revoke event is silently swallowed  
**Blocked by:** requires on-path MITM before first HSTS pin

No HSTS (F9) means initial :80 request leaks the non-Secure refresh cookie (F10) to a network attacker; the attacker then races the legitimate refresh (F12) so both parties mint valid access tokens; the replay-detection branch that could have caught this produces no log (F18) so operators never notice.

### [HIGH] Card-testing oracle via merchant origin
**Path:** #10 Raw PAN/CVV posted through merchant origin → #3 Merchant nginx prefix-proxies entire FauxPay API externally → #17 Processor error detail forwarded to unauthenticated client  
**Blocked by:** nginx fauxpay zone 20r/m rate-limit (volume only)

Attacker submits candidate PANs to /fauxpay/tokenize through merchant nginx (F16 confirms raw PAN traverses the origin), attempts /fauxpay/charge or the api /checkout, and reads processor-error detail forwarded verbatim (F8) to distinguish valid PANs from junk BINs. Rate limit slows but does not eliminate the oracle.

### [MEDIUM] Inventory drain / oversell
**Path:** #20 TOCTOU on stock check enables overselling / negative stock → #11 Stock decremented pre-charge, never restored on payment failure

Concurrent checkouts (F4) drive stock negative or exactly to zero; failure-path never restores stock (F2) so a stream of guaranteed-decline charges from a throwaway token depletes inventory without a single successful payment — competitor sabotage or self-DoS.


## Dropped Findings

- **[EXCLUDED]** `api/src/middleware/rateLimit.js:12` other (chunk-06) — file not in repo inventory
- **[EXCLUDED]** `api/src/middleware/rateLimit.js:4` logic-flaw (chunk-06) — file not in repo inventory
- **[EXCLUDED]** `api/src/routes/auth.js:57` info-leak (chunk-06) — file not in repo inventory
- **[EXCLUDED]** `api/src/routes/auth.js:40` info-leak (chunk-06) — file not in repo inventory
- **[EXCLUDED]** `api/src/routes/auth.js:57` logic-flaw (chunk-06) — file not in repo inventory
- **[UNCONFIRMED]** `Node JS/docker-compose.yml:97` other (spec-iac-01) — s4 confidence 0.40 < gate 0.50
- **[DUP (pre-verify)]** `Node JS/api/src/routes/auth.js:63` info-leak (threat-t29-fallback) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Node JS/api/src/routes/orders.js:68` info-leak (threat-t26-fallback) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Node JS/.env:39` info-leak (chunk-09) — pre-verify semantic: Same committed default JWT_SECRET issue, one fix (rotate/denylist) closes both.
- **[DUP (pre-verify)]** `Node JS/api/src/middleware/auth.js:20` logic-flaw (threat-t21-fallback) — pre-verify semantic: Same missing server-side access-token revocation; one revocation mechanism fixes both.
- **[DUP (pre-verify)]** `Node JS/api/src/routes/orders.js:68` logic-flaw (threat-t19-fallback) — pre-verify semantic: Same missing idempotency on FauxPay charge; one Idempotency-Key implementation covers both.
- **[DUP (pre-verify)]** `Node JS/api/src/routes/orders.js:47` logic-flaw (threat-t18-fallback) — pre-verify semantic: Identical stock-decremented-pre-charge/no-restore defect on same handler.
- **[DUP (pre-verify)]** `Node JS/api/src/db/knexfile.js:26` info-leak (spec-sensitive-data-01) — pre-verify semantic: Same shared 'widgetshop' default password; one credential rotation/denylist closes both.
- **[DUP (pre-verify)]** `Node JS/api/src/services/fauxpayClient.js:1` info-leak (spec-crypto-02) — pre-verify semantic: Same committed FAUXPAY_API_KEY default; one rotation covers all references.
- **[DUP (pre-verify)]** `Node JS/fauxpay/src/server.js:75` info-leak (spec-sensitive-data-02) — pre-verify semantic: Same unauthenticated /tokenize handler on same lines; single fix (auth+topology) closes both angles.
- **[DUP (pre-verify)]** `Node JS/api/src/services/fauxpayClient.js:13` info-leak (spec-sensitive-data-02) — pre-verify semantic: Same processor-error verbatim propagation; one sanitization at the boundary covers both.
- **[DUP (pre-verify)]** `Node JS/docker-compose.yml:59` other (spec-iac-01) — pre-verify semantic: Same docker-compose DB password default; one fix closes both.
- **[DUP (pre-verify)]** `Node JS/docker-compose.yml:82` other (spec-iac-01) — pre-verify semantic: Same committed FAUXPAY_API_KEY default in compose file.
- **[DUP (pre-verify)]** `Node JS/api/src/routes/cs.js:11` info-leak (threat-t21-fallback) — pre-verify semantic: Same unbounded /cs/orders pagination; one .limit() fix closes both.
- **[DUP (pre-verify)]** `Node JS/.env.example:47` other (threat-t27-fallback) — pre-verify semantic: Same committed FAUXPAY_API_KEY default in .env.example.
- **[DUP (pre-verify)]** `Node JS/.env.example:39` other (threat-t27-fallback) — pre-verify semantic: Same committed default JWT_SECRET; one rotation/denylist closes both.
- **[DUP (pre-verify)]** `Node JS/.env.example:26` other (threat-t27-fallback) — pre-verify semantic: Same committed default 'widgetshop' Postgres password.
- **[DUP (pre-verify)]** `Node JS/api/src/routes/catalog.js:8` logic-flaw (threat-t32-fallback) — pre-verify semantic: Same unescaped LIKE wildcards in catalog search endpoint.
- **[DUP (pre-verify)]** `Node JS/api/src/services/tokens.js:49` logic-flaw (threat-t30-fallback) — pre-verify semantic: Same Secure-flag-gated-on-NODE_ENV setRefreshCookie bug.
- **[DUP (pre-verify)]** `Node JS/api/src/server.js:3` logic-flaw (threat-t30-fallback) — pre-verify semantic: Same committed JWT_SECRET issue; startup denylist is the shared fix.
- **[DUP (pre-verify)]** `Node JS/api/Dockerfile:3` logic-flaw (threat-t30-fallback) — pre-verify semantic: Same api/Dockerfile npm install without lockfile enforcement.
- **[FP]** `Node JS/api/src/services/tokens.js:21` logic-flaw (chunk-01) — 15-min access token with revocable, rotating, httpOnly refresh token is the standard OWASP pattern; scanner misread the TTL as "long-lived" and ignored the refresh-token revocation layer.
- **[FP]** `Node JS/api/src/middleware/auth.js:25` logic-flaw (chunk-01) — jsonwebtoken v9.0.2 rejects alg=none by default and blocks HS/RS confusion via key-shape checks; the "exploit" is contingent on a future RS256 migration that has not happened.
- **[FP]** `Node JS/fauxpay/src/server.js:75` logic-flaw (chunk-02) — /charge in FauxPay has no real acquirer; it cannot signal live-vs-dead PANs, so the claimed validated-card-oracle chain is not physically realizable in this code.
- **[FP]** `Node JS/fauxpay/src/server.js:75` other (chunk-02) — bounded-per-request accumulation behind a per-IP nginx rate limit is a volumetric/infra DoS (Rule D), not a single-request complexity blowup; `transactions.set` half of the finding is additionally gated by `requireApiKey`.
- **[FP]** `Node JS/api/src/routes/admin.js:33` logic-flaw (chunk-03) — price_cents IS validated on PATCH (lines 39–43) and updated_by IS set (line 44); the scanner's snippet stopped one line short of the defense.
- **[FP]** `Node JS/docker-compose.yml:82` info-leak (chunk-02) — FauxPay is an in-memory mock not deployed to prod; the "default key" only guards ephemeral fake charge/refund state, and the real processor secret has no code-level fallback anywhere in the repo.
- **[FP]** `Node JS/api/src/routes/cart.js:39` logic-flaw (chunk-04) — checkout stock check in orders.js:36-38 short-circuits before the transaction, so the described `subtotal_cents`/`total_cents` overflow and noisy `pending_payment` rows never materialize; remaining cart-side accumulation just yields a 500 with no security impact.
- **[FP]** `Node JS/api/src/routes/cs.js:14` other (chunk-05) — requires privileged customer_service auth; PostgreSQL ILIKE does not exhibit pathological complexity from `%`/`_` injection, so the wildcard-escape gap is a best-practice concern with no realistic DoS or data-impact path independent of the co-reported bulk-export/JWT findings.
- **[FP]** `Node JS/fauxpay/Dockerfile:3` other (chunk-09) — Dockerfile hygiene / hypothetical supply-chain risk; owned by SCA pipeline (Rule D) and a best-practice gap with no in-repo exploitable path (Rule E). No defect in the two cited lines themselves.
- **[FP]** `Node JS/api/Dockerfile:1` other (spec-iac-01) — lockfiles exist in-repo and `npm install` honors them (locked versions + integrity hashes); "silent supply-chain drift on rebuild" is a hypothetical hardening gap, not a concrete vuln.
- **[FP]** `Node JS/api/src/app.js:16` logic-flaw (threat-t30-fallback) — API auth is `Authorization: Bearer` (not ambient), refresh cookie is httpOnly+SameSite=Lax, cors() does not set ACAC:true, and the "exfil" target endpoint is anonymous-readable anyway; no cross-origin privilege gained.
- **[FP]** `Node JS/docker-compose.yml:59` info-leak (chunk-09) — Documented dev/training boot convenience; production uses managed Postgres + secrets manager with no fallback (Rule B dev-profile fallback exception); DB only reachable inside compose network on disposable seed data.
- **[FP]** `Node JS/api/src/routes/catalog.js:8` injection (spec-batch-etl-01) — Knex parameterises the value so it is not SQL injection; the only claimed impact is CPU DoS via LIKE wildcards, but Postgres LIKE is linear (no ReDoS-style blow-up) so exploitation requires request flooding — volumetric DoS excluded by Rule D.
- **[FP]** `Node JS/api/src/app.js:31` other (spec-log-injection-01) — Global handler writes raw errors to stdout, but no structured logger, log shipper, or SIEM ingestion is configured anywhere in the repo/compose; per scope Rule E, log-forging without a downstream parser is not reportable, and no other security impact (data exposure, authz, RCE) exists on this path.
- **[FP]** `Node JS/web/Dockerfile:3` other (threat-t14-fallback) — lockfile v3 with integrity hashes is committed; caret ranges in package.json do not override pinned transitive versions, so the "compromised patch auto-picked-up on rebuild" chain doesn't fire. Residual `npm install` vs `npm ci` gap is SCA/hardening territory.


---

## Appendix: Scan Scope

### Folders scanned (18)

- `./`
- `.claude/`
- `Node JS/`
- `Node JS/.claude/`
- `Node JS/api/`
- `Node JS/api/src/`
- `Node JS/api/src/db/`
- `Node JS/api/src/db/migrations/`
- `Node JS/api/src/db/seeds/`
- `Node JS/api/src/middleware/`
- `Node JS/api/src/routes/`
- `Node JS/api/src/services/`
- `Node JS/fauxpay/`
- `Node JS/fauxpay/src/`
- `Node JS/web/`
- `Node JS/web/src/`
- `Node JS/web/src/api/`
- `Node JS/web/src/pages/`

### Excluded from scan (5728 files)

**Folders** (matched `exclude_dirs`):

- `Node JS/api/node_modules/` — 2422 files
- `Node JS/web/node_modules/` — 2342 files
- `Node JS/fauxpay/node_modules/` — 618 files
- `.git/` — 328 files

**Patterns** (matched `exclude_globs`):

- `**/.dockerignore` — 3 files
- `**/package-lock.json` — 3 files
- `ANSWER_KEY-*.md` — 1 files
- `ANSWER_KEY.md` — 1 files
- `DESIGN.md` — 1 files
- `threat-model-design.md` — 1 files
- `THREAT_MODEL.md` — 1 files
- `**/.gitattributes` — 1 files
- `**/.gitignore` — 1 files
- `Node JS/.scratch_vvah_dump.json` — 1 files
- `Node JS/Node_JS_*_report.md` — 1 files
- `Node JS/Node_JS_*_report.sarif` — 1 files
- `Node JS/Node_JS_*_s8_raw.txt` — 1 files
- `Node JS/THREAT_MODEL-*.md` — 1 files
