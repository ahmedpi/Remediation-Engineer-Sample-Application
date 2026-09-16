# Threat Model: Widget Shop — Design Document Review

**Source material:** `DESIGN.md` only — no source code was consulted for this review.
**Scope:** Architecture, data flows, and controls as *specified* in the document. Findings below are about gaps, ambiguities, or risks in the design itself, not implementation bugs.

## System Overview (as designed)

Browser clients (Guest/Customer/Admin/CS) reach an **API Gateway** (§3.3) — the sole public entry point — which terminates TLS, rate-limits, and validates JWT access tokens before forwarding to either the `web` (SPA) or `api` (Express) container. `api` is the only client of `db` (Postgres). A third-party **Payment Processor** sits outside the trust boundary entirely: the SPA talks to it directly (browser → processor) for tokenization, and `api` talks to it server-to-server for charge/refund (§3.1).

Trust boundaries crossed:
1. Public internet → Gateway (TLS termination, the only boundary a Guest crosses)
2. Gateway → `api` (identity asserted via an internal "trusted header" per §3.3, not re-verified by `api`)
3. `api` → `db` (credentialed, internal-only)
4. Browser / `api` → external Payment Processor (outside our operational control, §3.1/§11.1)

---

## Threats by Data Flow

### 1. Registration / Login (§7.1, §7.1c, §7.7.1, §7.7.9)

| # | Threat | STRIDE | Severity | Notes |
|---|---|---|---|---|
| 1.1 | **Per-account lockout enables attacker-triggered denial of service.** §7.1c locks the account (not the source IP) after N failed attempts. Anyone who knows a victim's email can deliberately fail login enough times to lock that victim out for the cooldown window, repeatedly, indefinitely. | Denial of Service | Medium | The gateway's per-IP rate limit (§3.3) doesn't stop this — the attacker only needs a handful of requests per cooldown cycle, well under any reasonable IP limit. |
| 1.2 | **No email verification at registration.** §7.1 creates an active, logged-in account for any syntactically valid email with no confirmation step. | Spoofing | Low–Medium | Enables registering accounts against emails the registrant doesn't control (impersonation in order confirmations sent to that address, mailbox-squatting scenarios). Design doesn't state this is out of scope, so likely an oversight rather than a deliberate non-goal. |
| 1.3 | **Registration's duplicate-email handling is unspecified and may leak account existence**, unlike forgot-password (§7.1a) which explicitly designs around this with a generic response. If `/api/auth/register` returns a distinguishable "email already registered" error, it becomes a user-enumeration oracle that the rest of the design deliberately closed elsewhere. | Information Disclosure | Low | Recommend the design explicitly state register's behavior on duplicate email (generic error is the safer, if less usable, choice — or accept the trade-off explicitly). |
| 1.4 | **No MFA for any role**, including Admin and Customer Service — the two roles with the largest blast radius (catalog/price control, all-customer PII, refund issuance). A single phished/reused password fully compromises one of these accounts. | Elevation of Privilege | Medium | Not called out as a non-goal; worth an explicit decision given §4's staff roles carry outsized impact. |

### 2. Forgot / Reset Password (§7.1a, §7.7.7)

| # | Threat | STRIDE | Severity | Notes |
|---|---|---|---|---|
| 2.1 | **Reset token likely travels in a URL**, which the design doesn't rule out. URL-embedded tokens are exposed via browser history, `Referer` headers (if the reset page loads any third-party resource), and the Gateway's own access logs (it terminates TLS and sees the full URL, per §3.3/§11 the gateway is trusted infra, but logs are a common leak point). | Information Disclosure | Medium | Recommend the design specify a `Referrer-Policy: no-referrer` on the reset page and note whether the token is a query param or path segment. |
| 2.2 | **No CAPTCHA / abuse control specified for `forgot-password` beyond generic rate limiting** (§3.3, §10). An attacker can mass-trigger reset emails against a victim's inbox (email-bombing / harassment) using only volume low enough to stay under per-IP limits by rotating source IPs. | Denial of Service | Low | Complementary to 1.1 — the design leans entirely on IP-based rate limiting for anti-abuse across multiple auth-adjacent endpoints. |
| 2.3 | **Recovery security is bounded by the email provider/mailbox, which is outside this design's control.** Anyone who can read the victim's email can take over the account. This is inherent to email-based recovery and likely an accepted risk, but the document doesn't state it as such. | Spoofing | Low (accepted risk — flag for explicit sign-off) | |

### 3. Change Password (§7.1b, §7.7.8)

No significant gaps — current-password re-verification and full session revocation (except current session) are both explicitly designed. This flow is a good template the rest of the document should be held to (see 6.1 below).

### 4. Token Refresh & Rotation (§3.2, §7.7.10)

| # | Threat | STRIDE | Severity | Notes |
|---|---|---|---|---|
| 4.1 | **`api` trusts an unauthenticated-to-it internal header for identity** (§3.3: "verified caller identity... forwarded to `api` on an internal, trusted header, so `api` doesn't need to re-parse or re-verify the JWT itself"). This collapses authentication entirely onto the Gateway. If the Gateway↔`api` network segment is ever reachable by another workload (misconfiguration, a future container added to the same network, a compromised `web` container that turns out to share a network with `api`), that workload can set the trusted header directly and impersonate **any user, including admin**, with zero cryptographic check on `api`'s side. | Spoofing / Elevation of Privilege | **High** | This is a single point of failure by design. Recommend: `api` independently verifies the JWT signature (cheap, defense-in-depth) rather than trusting the header alone, or the internal network is enforced via mTLS between Gateway and `api`, not just Compose network isolation. |
| 4.2 | **No user-facing notification on detected token-family theft.** §3.2/§7.7.10 correctly revokes the whole refresh-token family when a reused/rotated-out token is replayed, but the user is only silently logged out — they're never told a theft was detected, so they have no signal to change their password or investigate. | Repudiation | Low | Cheap to add: an email notification on family revocation. |

### 5. Browse Catalog (§7.2, §7.7.2)

No material design-level threats — public, read-only, no state change. Bulk scraping of catalog/pricing is a possible business concern but not a security threat per se given the design's own goals.

### 6. Cart & Checkout / Payment (§7.3, §6, §7.7.3)

| # | Threat | STRIDE | Severity | Notes |
|---|---|---|---|---|
| 6.1 | **`POST /api/orders` accepts a `card_token` with no stated binding to the requesting session.** §6/§7.3 don't require that the token was produced by *this* customer's own tokenize call. Because `/tokenize` is deliberately unauthenticated (§6, by design, to keep card data off `api`), anyone can call the processor's tokenize endpoint directly — without ever visiting the SPA — for any card number they hold, then feed the resulting token into our authenticated `/api/orders`. This turns our checkout into a **card-testing oracle**: an attacker with a list of stolen/candidate card numbers can determine which are valid by watching which of our orders succeed vs. fail, at low cost (they need one of our real customer accounts, or their own). | Elevation of Privilege / Repudiation (fraud) | **High** | This is a known risk pattern with client-side tokenization and is usually mitigated processor-side (e.g., tying tokens to a short-lived session/publishable-key context) — worth calling out explicitly since the document doesn't address it, and confirming the chosen processor's tokenize call is scoped in a way that prevents anonymous, high-volume token minting. |
| 6.2 | **No idempotency key on the `/charge` call** (§6, §7.3 step 4). A network retry (client-side or `api`-side) after a charge actually succeeded, before the response is received, can result in a duplicate charge for the same order. | Repudiation | Medium | Standard fix: an idempotency key derived from `order_id` passed to the processor's `/charge`. |
| 6.3 | **No stock reservation during checkout — `stock_quantity` is decremented only after a successful charge** (§7.3 step 5). Two concurrent checkouts for the last unit of a widget can both pass a pre-charge stock check (if any exists — not specified) and both succeed, overselling. | Tampering (data integrity) | Medium | The document should specify either a reservation/hold on `stock_quantity` at order-creation, or an atomic decrement-with-check at charge-success time with a defined behavior for the loser (refund + apology, not documented). |
| 6.4 | **Re-pricing at checkout (§5, "recommend re-pricing... to avoid stale-price abuse") is a recommendation, not a requirement**, and is the *only* place a client-supplied cart is validated against server truth before money moves. Good design instinct, but phrased as advisory language in an otherwise prescriptive document — worth tightening to a hard requirement. | Tampering | Low | Wording/rigor issue, not a new class of threat. |

### 7. Admin — Catalog Management (§7.4, §7.7.4)

| # | Threat | STRIDE | Severity | Notes |
|---|---|---|---|---|
| 7.1 | **Price/stock changes have no audit-trail requirement**, unlike refunds/exchanges which explicitly must record acting staff, timestamp, and reason (§9 item 9). A compromised or malicious Admin account can silently zero out a price, drain stock via bogus "corrections", or reprice items for personal orders, with no attributable record. | Repudiation | Medium | Recommend extending §9's audit-trail requirement to catalog mutations, not just refunds/exchanges. |
| 7.2 | **`PATCH /api/admin/users/:id/role` has no documented safeguard against self-escalation, unbounded admin creation, or dual-control.** Any single Admin can grant itself or any account `admin`/`customer_service` unilaterally. Combined with 1.4 (no MFA), one phished Admin password is a full compromise of the role model. | Elevation of Privilege | Medium–High | Consider requiring a second Admin's approval for role grants, or at minimum logging + alerting on role changes. |
| 7.3 | **A role change doesn't revoke existing sessions.** §7.1b (password change) and §7.1a (password reset) both explicitly revoke `refresh_tokens` on the affected user; the role-change flow (§7.4/API surface `PATCH /api/admin/users/:id/role`) has no equivalent step. A demoted or de-provisioned staff member's still-valid access token (up to 15 min, §3.2) *and* refresh token (until it naturally expires/rotates) continue to authenticate at the old privilege level. | Elevation of Privilege | Medium | Straightforward fix: role changes should revoke the target user's `refresh_tokens`, exactly as password changes do. |

### 8. Customer Service — Refunds (§7.5, §7.7.5)

| # | Threat | STRIDE | Severity | Notes |
|---|---|---|---|---|
| 8.1 | **No stated validation that cumulative refunds on a payment can't exceed the original `amount_cents`.** §5/§7.5 describe issuing "a full or partial refund" and recording it, but never state a check against `payments.amount_cents` minus prior refunds. A bug or malicious CS agent could over-refund a payment beyond what was ever charged. | Tampering (financial integrity) | Medium–High | This is exactly the kind of "value recomputed from authoritative data" check the rest of the document is careful about elsewhere (e.g., checkout re-pricing) — it's a gap by omission here. |
| 8.2 | **Any CS agent can look up and act on any customer's order with no scoping, and lookups aren't required to be logged** (§7.5 step 1: "CS looks up an order (by order id, customer email, etc.)"). With multiple staff accounts and full PII/order visibility, there's no way to detect or investigate improper browsing of customer data after the fact. | Information Disclosure / Repudiation | Medium | Recommend an access-log requirement for CS order lookups, separate from the existing refund/exchange audit trail. |

### 9. Customer Service — Exchanges (§7.6, §7.7.6)

| # | Threat | STRIDE | Severity | Notes |
|---|---|---|---|---|
| 9.1 | **No stated stock check on the replacement item.** §7.6 step 3 lets CS ship a `replacement_widget` with no mention of verifying `stock_quantity` first, unlike checkout's (recommended) re-pricing discipline. | Tampering | Low | Minor relative to 6.3/8.1 but same family of issue: staff-initiated stock/money movement without a stated authoritative check. |

### 10. API Gateway as Sole Entry Point (§3.3, §11.2)

| # | Threat | STRIDE | Severity | Notes |
|---|---|---|---|---|
| 10.1 | **Centralizing TLS termination, rate limiting, and the *only* authentication check in one component makes the Gateway a single point of total compromise** — a vulnerability in the gateway product itself (or its config) bypasses every downstream control in one shot, and (per 4.1) `api` has no independent check to fall back on. | Elevation of Privilege | Medium (design trade-off, not necessarily wrong, but worth an explicit risk acceptance) | Mitigate via 4.1's recommendation (defense-in-depth re-verification at `api`) rather than removing the gateway pattern, which is otherwise sound. |
| 10.2 | **Per-IP/per-user rate limiting is explicitly acknowledged as only "complementary"** (§3.3) to account lockout, but no distributed/credential-stuffing-specific control (e.g., device fingerprinting, CAPTCHA after N failures) is described anywhere in the document for `/api/auth/*`. A low-and-slow distributed credential-stuffing attack across many IPs, each under the per-IP threshold, is not addressed by anything specified. | Spoofing | Low–Medium | Acceptable for the stated scale (§2 non-goals: no HA/multi-region), but worth an explicit note that this is accepted residual risk. |

### 11. Deployment (§11)

| # | Threat | STRIDE | Severity | Notes |
|---|---|---|---|---|
| 11.1 | **Inconsistent secret handling: `db` password uses `POSTGRES_PASSWORD_FILE` (a Docker secret), while the JWT signing secret and payment-processor API key are passed via plain `env_file`** (§11.6). Env-var secrets are visible via `docker inspect`, process environment dumps, and are more easily accidentally logged than file-based secrets. | Information Disclosure | Low–Medium | The document already knows the better pattern (it uses it for `db`) — recommend applying the same `_FILE`/secrets approach to the JWT secret and processor API key, which arguably matter more (JWT secret compromise = 4.1-style total auth bypass). |
| 11.2 | **Network segmentation into `frontend`/`backend` is offered as an optional alternative** ("a single Docker Compose network (or two...)", §11.2), not a requirement. If a single flat network is chosen, `db` and the Gateway/`web` share a network, weakening the stated invariant that only `api` can reach `db` (§11.2's own bullet) down to "nothing else is configured to," rather than "nothing else is able to." | Tampering / Information Disclosure | Medium | Recommend making the two-network split (or equivalent enforced isolation) a hard requirement, not an "or." |
| 11.3 | **No secret-rotation story for the JWT signing secret or payment-processor API key.** A leaked secret (via 11.1 or otherwise) has no documented remediation path (e.g., dual-secret rotation window, forced re-login of all users). | Repudiation | Low | Worth a sentence in §11.3 on rotation procedure, even if manual at this scale. |
| 11.4 | **No mention of container image / dependency vulnerability scanning** in the build pipeline (§11.5 covers multi-stage builds and non-root users well, but not supply-chain scanning). | Tampering | Low | Likely out of scope for this document's level (infra/CI concern), but flagging since §11 is otherwise fairly deployment-security-conscious. |

---

## Summary — Highest-Priority Design Gaps

1. **[High] `api` blindly trusts the Gateway's identity header (4.1)** — no independent verification means one network misconfiguration is a full auth bypass for every role including admin.
2. **[High] Unauthenticated `/tokenize` + unbound `card_token` on `/api/orders` (6.1)** enables using checkout as a card-testing oracle against the payment processor.
3. **[Medium–High] No cap on cumulative refunds vs. original payment amount (8.1)** — a financial-integrity check the rest of the design applies elsewhere (checkout re-pricing) but misses here.
4. **[Medium–High] No dual-control/self-escalation guard on admin role grants (7.2)**, compounded by no MFA anywhere (1.4) for the two highest-privilege roles.
5. **[Medium] Role changes don't revoke sessions (7.3)**, unlike password changes — an inconsistency within the document's own stated security model.
6. **[Medium] Per-account (not per-IP) lockout is a ready-made DoS against any known email address (1.1).**
7. **[Medium] No stock reservation at checkout (6.3) and no idempotency key on `/charge` (6.2)** — both are classic e-commerce correctness/fraud gaps.

Items 5 and 3 are notable specifically because the document *already demonstrates* the right pattern elsewhere (session revocation on password change; re-pricing at checkout) — the gap is inconsistent application of a principle the design otherwise holds, which is usually cheaper to fix than to discover.
