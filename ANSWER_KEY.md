# Answer Key — Widget Shop Design Review Exercise (Instructor Only)

**Do not distribute to trainees.** Give them [DESIGN.md](DESIGN.md) unmodified — it was never edited to plant these; the four gaps below are omissions that were already there. That's the point of the exercise: the doc reads as confident and thorough everywhere else, so trainees have to notice what it *doesn't* say, not spot an obviously broken sentence.

Each entry: where it hides, why it's easy to miss, the concrete exploit, and the fix. Difficulty is rated for a developer with limited security background.

---

## 1. Stored XSS via unescaped widget content — Difficulty: Easy

**Where:** §5.1 (`WIDGETS.name`, `WIDGETS.description`, `WIDGETS.image_url` — plain `string`/`text` columns, no encoding note), §7.4 (Admin catalog management), §7.7.2 (Browse Catalog sequence diagram — widget rows go straight from DB to API response to "Render catalog" / "Render detail page").

**Why it's easy:** No security background needed beyond "user-controlled data ends up on a page" — this is usually the first vuln class taught. The tell is an absence: the doc has an entire subsection on output security (§3.2's CSP), but CSP is a mitigation for *when other defenses fail*, not a substitute for escaping output in the first place — and nothing in §5.1, §7.4, or §7.7.2 ever says widget fields are escaped/sanitized before being rendered by the SPA.

**Exploit scenario:** An admin account (compromised, or simply a lower-trust "admin" than intended — e.g. a junior staffer with catalog-only access) sets a widget's `name` or `description` to `<script>...</script>` or an `onerror`-bearing `<img>` tag. Every guest and customer who views the catalog or that widget's detail page (§7.7.2) executes the payload — session/token theft, page defacement, or (per §3.2) an attempt to read the in-memory access token before its 15-minute expiry.

**What a good answer looks like:** Naming that widget content is staff-authored but rendered to *all* visitors, and that the doc never states it's treated as untrusted output (encoded/escaped, or rendered as text rather than HTML) despite being exactly the kind of field a real app would eventually open to less-trusted contributors (multiple admins, a future "reviews" feature, etc.).

**Fix:** State explicitly that all widget fields are rendered as text (not `innerHTML`) in the SPA, and/or HTML-escaped server-side before storage or client-side before render; treat the CSP (§3.2) as defense-in-depth on top of that, not instead of it.

---

## 2. Header-spoofing trust boundary — Difficulty: Hard

**Where:** §3.3 ("the verified caller identity ... is forwarded to `api` on an internal, trusted header") and §11.2 ("A single Docker Compose network (**or** two: `frontend` and `backend`)").

**Why it's subtle:** The doc sounds airtight right up to the trust hand-off — TLS termination, rate limiting, JWT signature/expiry validation, `db`/`api`/`web` all "not published to the host." A trainee skimming for missing security controls will find plenty of *present* controls and stop looking. The actual gap is one clause: `api` never re-verifies the JWT — it just reads a header the gateway attached. Nothing in the doc says what stops another container from attaching that same header itself.

**Exploit scenario:** Compromise `web` (e.g. a malicious/compromised npm dependency pulled in at build time, or any RCE) — or simply deploy with the "single network" option §11.2 explicitly allows. From `web`, send a request straight to `api` with `X-User-Id: 1` / `X-Role: admin` (or whatever header name the real implementation picks). `api` has no way to tell this apart from a gateway-forwarded request — full authentication and authorization bypass.

**What a good answer looks like:** "The design never states how `api` knows a request actually came from the gateway rather than from `web` or another container — it trusts a header with no cryptographic binding to the gateway's JWT verification step." Partial credit for flagging the network ambiguity in §11.2 without connecting it to the header-trust issue in §3.3 — the two need to be tied together for full marks, since fixing only one (e.g. picking the two-network option) still leaves `web` able to spoof `api` unless `web` is also excluded from the backend network.

**Fix:** Put `gateway` and `api` on a network `web` is never a member of, *and* have `api` verify a shared secret (or mTLS client cert) on the identity header — don't rely on network topology alone.

---

## 3. CSRF defense with no CORS policy — Difficulty: Medium-Hard

**Where:** §3.2 ("`POST /api/auth/refresh` ... additionally requires a custom header ... that a cross-site form or `<img>`/`<form>` CSRF attempt cannot attach — defense in depth alongside `SameSite=Strict`").

**Why it's subtle:** This sentence is *correct* as far as it goes — a plain HTML form or `<img>` genuinely cannot attach a custom header, and `SameSite=Strict` genuinely blocks the classic cross-site case. Trainees who know "CSRF token/custom header = mitigated" will check this off as solved. The doc never says anything about CORS anywhere, and that absence is the actual hole: a custom header on a `fetch()` (not a `<form>`) triggers a CORS preflight, and the header only actually blocks anything if the preflight gets rejected for the attacker's origin. With no stated CORS policy, there's nothing to reject it with.

**Exploit scenario:** A compromised or takeover-vulnerable sibling subdomain (still "same-site" under `SameSite=Strict`, so the cookie is attached) issues a `fetch()` with the custom header to `/api/auth/refresh`. If the API's CORS config is permissive (wildcard, or reflects `Origin`, or simply has no allow-list and a permissive framework default), the preflight succeeds and the forged request goes through with the cookie and the header both present.

**What a good answer looks like:** Naming that the header defense's own claim ("a cross-site attempt can't attach this header") is only true for simple/no-CORS requests, and that the document has no CORS section to fall back on. Partial credit for just noting "no CORS policy is mentioned" without connecting it to why that specifically undermines the header defense.

**Fix:** Explicit default-deny CORS — fixed origin allow-list, `Access-Control-Allow-Credentials` never combined with a wildcard or reflected origin.

---

## 4. Missing ownership checks / BOLA (IDOR) — Difficulty: Medium

**Where:** §4 ("Role checks are enforced **server-side** on every API endpoint") and the customer-scoped routes in §8 (`GET /api/orders/:id`, `PATCH /api/cart/items/:itemId`, etc.).

**Why it's subtle:** "Role checks enforced server-side on every endpoint" *sounds* like a complete authorization story, and it's stated with enough confidence that it reads as the authoritative word on authorization for the whole doc. Role-based checks (is this a `customer`?) and ownership checks (is this *their* order?) are two different things, and the doc only ever discusses the first.

**Exploit scenario:** Any authenticated customer calls `GET /api/orders/17` (or any other customer-scoped id) with their own valid token. If the endpoint only checks `role == customer`, not `order.user_id == token.user_id`, they can read (or with `/api/cart/items/:itemId`, modify) any other customer's data just by guessing/incrementing an id.

**What a good answer looks like:** Explicitly distinguishing "role-based" from "ownership-based" authorization and pointing at specific routes in §8 where an id parameter is attacker-controlled with no stated ownership check. Weaker answers will say "authorization looks fine, it's server-side" — that's the trap.

**Fix:** Every customer-scoped query must filter by the authenticated user's id, not just check role membership; state this explicitly as its own requirement, distinct from RBAC.

---

## 5. No refund amount cap or refund/exchange separation of duties — Difficulty: Medium

**Where:** §5 (`REFUNDS` table — no constraint tying cumulative `amount_cents` to the original payment), §7.5, §7.6, and §9 item 9 ("Every refund/exchange records who performed it and when (audit trail)").

**Why it's subtle:** The audit-trail line in §9 reads like a control ("we track who did it"), and trainees with limited security background often equate *auditability* with *prevention* — logging who issued a refund is not the same as stopping an over-refund or a self-dealing refund from happening in the first place. The doc's confident "who and when" framing makes it easy to assume the control surface is complete.

**Exploit scenario (financial loss):** A CS agent (compromised account, or malicious insider) issues repeated partial refunds against the same payment with no check that their sum stays under `amount_cents` originally captured — net financial loss beyond what the customer paid. **Exploit scenario (fraud/self-dealing):** Nothing in §4 or §7.5 stops a CS agent from processing a refund on an order that is their own purchase (if their staff account also has order history) — undetectable without cross-referencing `refunds.issued_by` against `orders.user_id`, which the design never mentions doing.

**What a good answer looks like:** Separating "detective control" (the audit trail, which exists) from "preventive control" (amount validation and separation of duties, which don't). Partial credit for spotting only one of the two (amount cap vs. self-dealing).

**Fix:** Enforce `SUM(refunds.amount_cents) <= payments.amount_cents` per payment at the database or application layer; block or flag any refund/exchange where `issued_by == order.user_id`.

---

## Debrief talking point

All four gaps share a pattern worth calling out explicitly after the exercise: **each one sits directly adjacent to a real, correctly-implemented control**, and the confidence of the nearby correct text is what hides the gap. This is deliberately more realistic than a doc with an obvious missing feature — most real-world security review misses happen exactly this way, not because nothing was done, but because something adjacent was done well enough to stop the reader from looking further.

## Not included in this exercise (present in the doc, but out of scope by design)

The broader review ([THREAT_MODEL.md](THREAT_MODEL.md)) also found a stock-oversell race condition (no reservation between order creation and charge, §7.3) and missing idempotency keys on `/charge`/`/refund` (§6). These were left in `DESIGN.md` too but weren't selected as graded findings for this exercise — usable as stretch/bonus findings if a group finishes early.
