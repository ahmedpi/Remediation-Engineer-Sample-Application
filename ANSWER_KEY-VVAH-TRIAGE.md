# Answer Key — VVAH Scan Triage Exercise (Instructor Only)

**Do not distribute to trainees.** Give them the VVAH report
(`security-scan/Sample_Application_20260917T154119Z_report.md`) plus the source tree, and ask:
*"This scan reported 24 findings and dropped 41. Which of the 24 are real? Which of the 41 were wrongly dropped?"*

Every verdict below was established by reading the cited source lines, not by trusting either the scan or a
second tool. Where an independent threat model (tm-assess, run against the same commit on 2026-09-17) reached
the same or a different conclusion, that is noted as corroboration — never as the basis for the verdict.

**The scan's own arithmetic:** 65 raw S4 findings → 41 dropped (20 DUP, 5 EXCLUDED, 1 UNCONFIRMED, 15 FP) →
24 reported. The assignment therefore has 65 gradeable items, and the dropped 41 are where the real
discrimination happens.

---

## Scoreboard — what the correct answer looks like

| Bucket | Count | Verdict |
|---|---|---|
| Reported findings that are solid true positives | 14 | Accept |
| Reported findings that are true-but-scope-dependent (training-disclaimer class) | 6 | Accept with the scope caveat stated |
| Reported findings that are over-rated (mechanism real, claimed impact not realizable) | 3 | Accept only with the impact corrected |
| **Reported findings that are outright false positives** | **1** | **Must be rejected — finding #16** |
| Dropped findings correctly dropped | 39 | Uphold |
| **Dropped findings wrongly dropped (real, and lost for a non-security reason)** | **2** | **Must be recovered — the two EXCLUDED items** |
| Real issues in **neither** list (never generated a candidate) | ≥2 | Bonus credit |

A trainee who accepts all 24 and upholds all 41 has failed. A trainee who finds only that "the scan found
real bugs" has failed. The pass mark is: **reject #16, recover the two excluded rate-limiter items.**

---

## VVAH's own scope rules (trainees need these to grade the tool fairly)

The FP rationales cite these by name; several verdicts turn on whether the rule was applied *consistently*.

- **Rule B** — a credential fallback confined to a documented dev/training profile is exempt.
- **Rule D** — volumetric / infrastructure DoS is out of scope (owned by edge and SCA tooling).
- **Rule E** — a best-practice gap with no in-repo exploitable path is not reportable.

Watch for Rule B being applied to one committed secret and refused for another. That inconsistency is the
highest-value thing in this exercise (see Discriminator 2).

---

## Part A — The 24 reported findings

### A.1 Solid true positives (14) — accept

Each was verified at the cited lines; the mechanism is exactly as claimed.

| # | Finding | Verified how |
|---|---|---|
| 5 | Refresh-token rotation TOCTOU | `tokens.js:83` SELECT → `:87` test → `:103` UPDATE, no transaction, no `FOR UPDATE`, no conditional update. Concurrent refresh forks the family and suppresses replay detection. |
| 7 | Unbounded staff order pagination | `cs.js:11-16` — join to `users`, selects `customer_email`, no `.limit()`/`.offset()`; `?email=%` matches every row. |
| 8 | Rate-limit key spoofable via `X-Forwarded-For` | `rateLimit.js:4-10` takes the leftmost XFF element unconditionally; no `app.set('trust proxy')` anywhere; `nginx.conf:64,70,93` set **only** `Host`, so a client-supplied XFF reaches the app untouched. |
| 9 | Missing security response headers | `nginx.conf:28-109` — no `add_header` for HSTS/CSP/XFO/XCTO/Referrer-Policy; `app.js:14-37` mounts no helmet. *(Two supporting claims in this finding are false — see A.4.)* |
| 10 | Raw PAN/CVV crosses merchant origin | `client.js:10` sets `FAUXPAY_BASE_URL='/fauxpay'` (same origin); `:152-156` POSTs `card_number`/`cvv` there; `nginx.conf:90` proxies it. `fauxpay/src/server.js:63-67` admits it in-code. |
| 11 | Stock decremented pre-charge, never restored | `orders.js:47-66` commits the decrement, `:70` charges **after** commit, `:71-74` catch sets `status:'cancelled'` and never re-increments. |
| 12 | No email verification | `auth.js:31-55` — inserts and calls `issueSession` at `:53` with no confirmation token, no unverified state, no reset route. |
| 13 | Registration enumeration | `auth.js:40-43` — 409 "An account with that email already exists" vs 201. |
| 14 | Login timing oracle | `auth.js:64` `if (!user || !(await bcrypt.compare(...)))` short-circuits, so the unknown-user branch pays no bcrypt cost (cost 10 at `:45`). |
| 15 | No `Idempotency-Key` on charge/refund | `fauxpayClient.js:7-10` sends only Content-Type + Authorization. Supporting claim verified too: `20260101000007_create_payments.js:4` gives `order_id` an FK but **no** `.unique()`. |
| 20 | Stock TOCTOU → negative stock | `orders.js:30-39` reads outside the transaction; `:62` decrements unconditionally with no `where('stock_quantity','>=',…)` and no `forUpdate()`. Schema confirms it lands: `20260101000004_create_widgets.js:9` is a plain signed `integer` with **no CHECK ≥ 0**. |
| 21 | Order re-price races admin price mutation | `orders.js:30` re-prices outside the transaction opened at `:47`; `unit_price_cents` written from that stale snapshot at `:43/:59`. |
| 22 | No audit log for admin mutations | `admin.js:10,33,52,58,70,80` — not one handler logs or writes an audit row; role change at `:70-78` is completely silent. No `audit_log` table in migrations. |
| 23 | No logging of auth events | `auth.js:64-66` (failure) and `:68-72` (success) both return with no logger call. Load-bearing claim verified: the only logging call in the API is `console.error(err)` at `app.js:33`, which an intentional 401 never reaches. |

Finding **24** (refresh-replay event silently swallowed, `tokens.js:87-93`) is also verified true, with one
caveat worth grading: its file range overlaps finding #5, and its substance is a subset of #22/#23 (no audit
logging). Accept it, but a strong answer notes it is the same root cause counted a third time.

### A.2 True but scope-dependent (6) — accept only with the caveat stated

All six are factually correct about the code **and** all six sit behind an explicit production-exclusion
comment in that same file. Whether they are "findings" depends on a scope decision the tool made silently.

| # | Finding | Disclaimer that governs it |
|---|---|---|
| 1 | Committed default `JWT_SECRET` | `middleware/auth.js:8-17`, `.env:31-38` |
| 2 | Hardcoded seed staff password | `seeds/01_initial_data.js:16-20` (verified: `bcrypt.hash('ChangeMe123!', 10)` shared by the admin and CS accounts) |
| 3 | nginx prefix-proxies all of FauxPay | `nginx.conf:83-89` ("this location block is not deployed") |
| 4 | Card tokens never consumed → replay | `fauxpay/src/server.js:1-7` ("In production this service does not exist"). Mechanism verified: `/charge` at `:89-106` calls `tokens.get()` and never `tokens.delete()`, mints a fresh transaction regardless of prior use, and binds neither amount nor order. |
| 6 | Self-signed TLS minted at container start | `generate-cert.sh:6-8`; asserted values all verified (`-subj "/CN=localhost"`, `rsa:2048`, `-days 365`, `-nodes`) |
| 10 | Raw PAN through our origin | `fauxpay/src/server.js:69-74`, `client.js:147-151` |

**Full credit** requires the trainee to say *both* that the code does what the finding claims *and* that the
verdict depends on whether a "not in production" comment is trusted — and to notice the tool answered that
question inconsistently (Discriminator 2). Accepting them uncritically, or waving them away as "just
training defaults," are both partial credit.

### A.3 Over-rated — mechanism real, claimed impact not realizable (3)

| # | Mechanism (verified true) | Why the stated impact is wrong |
|---|---|---|
| 17 | `orders.js:73` forwards `detail: err.data?.error` verbatim (and `cs.js:48` does the same) | The finding claims this leaks "declined-reason strings, AVS/CVV mismatch codes" and enriches a card-testing oracle. FauxPay has no acquirer and never declines a card: `/charge` returns `status:'captured'` for any known token, and its entire error vocabulary is `Unknown card_token` / `amount_cents must be a positive integer` / `Refund amount exceeds original charge`. **VVAH dropped the card-oracle claim itself as an FP** (`fauxpay/src/server.js:75`) while keeping this finding, whose impact depends on that same oracle. Accept as hygiene; reject the oracle chain. |
| 18 | `reviews.js:9-23` — public route (no `requireAuth`, unlike `:25`) whose `select` at `:14` includes `reviews.user_id` and `users.full_name` | `full_name` on a public review is intended product behavior, and no endpoint anywhere accepts a `user_id` parameter to pivot on (orders/addresses/cart all scope to `req.user.sub`), so there is no IDOR to chain into. Genuine privacy-hygiene item (drop `user_id` from the payload), not Medium. |
| 19 | `fauxpay/src/server.js:46` uses `key !== API_KEY`, a short-circuiting string compare | Timing differential for an early-exit compare of a short string is nanoseconds, buried by TLS, Express routing and event-loop scheduling; no amplification primitive exists, and `nginx.conf:16` caps the route at 20 r/m. The file's own comment at `:37-42` already documents the correct `timingSafeEqual` form. Hygiene, not exploitable. |

Trainees who reject these outright get partial credit — the code defect is real. Trainees who accept them at
the stated severity also get partial credit. Full credit separates mechanism from impact.

### A.4 False positive — must be rejected (1)

**Finding #16 — "Refresh cookie Secure flag conditional on NODE_ENV" (MEDIUM, CVSS 6.8).**

The finding's central factual claim is: *"The api container in the training docker-compose does not set
NODE_ENV=production, so the cookie is created without the Secure attribute."* That is false. `NODE_ENV` was
checked in all three places it could be set:

- `api/Dockerfile:8` → `ENV NODE_ENV=production`
- `docker-compose.yml` → does not mention `NODE_ENV` anywhere (the api service's `environment:` sets only `DB_HOST`)
- `.env` → contains `DB_NAME`, `DB_USER`, `DB_PORT`, `DB_PASSWORD`, `PORT`, `JWT_SECRET`, `FAUXPAY_API_KEY` — no `NODE_ENV`

So in the shipped stack `process.env.NODE_ENV === 'production'` is **true**, and `tokens.js:56` sets
`secure: true`. The exploit scenario as written cannot occur.

The same finding also asserts the refresh token "mints fresh **12-hour** access JWTs." Also false:
`tokens.js:10` sets `ACCESS_TOKEN_TTL = '15m'`, and `nginx.conf:9` independently says "access tokens expire
every 15 minutes." (The 7-day refresh TTL it cites *is* correct: `tokens.js:15`.)

**Why it got through** is the instructive part, and worth walking through in the debrief: the S4 chunk that
produced this finding packed `docker-compose.yml` but not `api/Dockerfile`, so the disproving line was never
in context — and the S6 adversarial verifier, which *does* have repo-wide Read/Glob/Grep, still stamped it
TRUE_POSITIVE at 7/10 without grepping for `NODE_ENV`. A one-line grep refutes it.

**Residual (award credit for spotting this):** tying the flag to an env var rather than setting it
unconditionally is still fragile — one `NODE_ENV=development` in a future compose override silently
un-secures the cookie. That makes the *remediation* advice sound while the *finding* is invalid. The best
answers say exactly that.

---

## Part B — The 41 dropped findings

### B.1 EXCLUDED (5) — the most important item in this exercise

All five were discarded with the reason **"file not in repo inventory."** Look at the paths:

```
[EXCLUDED] api/src/middleware/rateLimit.js:12   other        (chunk-06)
[EXCLUDED] api/src/middleware/rateLimit.js:4    logic-flaw   (chunk-06)
[EXCLUDED] api/src/routes/auth.js:57            info-leak    (chunk-06)
[EXCLUDED] api/src/routes/auth.js:40            info-leak    (chunk-06)
[EXCLUDED] api/src/routes/auth.js:57            logic-flaw   (chunk-06)
```

Every reported finding carries a `Node JS/` prefix (`Node JS/api/src/middleware/rateLimit.js:4`). These five
do not. The scan root is the repository root, the application lives one directory down in `Node JS/`, and
these five candidates were emitted with paths relative to the app rather than the repo — so the inventory
check rejected them. **They were dropped for a path-normalization reason, with no security reasoning
applied and no adversarial verification performed.**

Three are harmless — they duplicate findings that survived with the correct prefix (`rateLimit.js:4`
logic-flaw ≈ #8; `auth.js:40` info-leak ≈ #13; `auth.js:57` info-leak ≈ #14).

**Two have no counterpart anywhere in the reported 24**, and the gaps that exist at exactly those locations
are both real. The report prints no description for EXCLUDED items, so their exact content cannot be
recovered — what follows is an inference from location and finding class, but the underlying
vulnerabilities were verified directly in code:

1. **`rateLimit.js:12` (class "other" — VVAH's class for resource/DoS issues).** Lines 12-13 are the
   `rateLimit()` factory and `const hits = new Map()`. The real gap there: the `hits` map is unbounded, keyed
   on a **client-chosen string** (per #8, the XFF header, which isn't even validated as an IP), and the
   `setInterval` sweep runs only once per `windowMs` and only evicts already-expired windows — so nothing
   caps growth *within* a window. `nginx.conf:58-60` deliberately excludes `/api/auth/refresh` from the tight
   `api_auth` zone, leaving it on `api_general` at 20 r/s, which is the high-rate vector. This is a genuine
   memory-exhaustion path on a single-process service. tm-assess independently reported it as a Medium
   finding (#16). **Nothing in VVAH's reported output covers it.**
2. **`auth.js:57` (class "logic-flaw").** Line 57 is the `POST /login` handler. The real gap there: rate
   limiting has **no per-account dimension at all.** `credentialLimiter` is route middleware, so it runs
   before anything reads `req.body.email`, and `clientIp()` is the entire keying decision — no failed-attempt
   counter, no lockout, no per-identifier throttle anywhere in the codebase. A distributed or XFF-spoofing
   attacker gets unlimited guesses against one victim. tm-assess ranked this its **#1 finding**, and it is
   graded finding #1 in [`ANSWER_KEY-THREAT-MODEL.md`](ANSWER_KEY-THREAT-MODEL.md). **Nothing in VVAH's
   reported output covers it** — #8 covers the *spoofable key*, which is a different defect with a different
   fix.

**Grading:** recovering these two is the pass mark for Part B. A trainee who notices the missing `Node JS/`
prefix and reasons "these were dropped by a tooling bug, so I can't trust the drop" has found the single most
valuable thing in the report. Credit "the per-account throttle is missing and the scan never reported it"
even if the trainee doesn't connect it to the EXCLUDED line — that's the finding; the path bug is the
explanation.

### B.2 UNCONFIRMED (1) — correctly dropped, for the wrong reason

`docker-compose.yml:97 other — s4 confidence 0.40 < gate 0.50`. Line 97 is the fauxpay healthcheck, whose
command (line 101) carries `rejectUnauthorized:false`. **The drop is correct:** it is FauxPay checking its
own self-signed cert over localhost purely to confirm its TLS listener answers, with no MITM surface — the
comment at `:93-96` explains exactly this. But note *how* it was dropped: a numeric confidence gate, not
reasoning. Right answer, no analysis. Worth raising in the debrief as the difference between a control and
a coincidence.

### B.3 DUP (20) — uphold, with two structural caveats

Spot-checked all 20 against their canonical findings; every one does reference the same root cause, and the
collapse is legitimate (e.g. the four separate `.env` / `.env.example` / `docker-compose.yml` / `server.js:3`
hits on `JWT_SECRET` all fold into #1, and one rotation fixes all of them). Two caveats deserve credit:

- **`tokens.js:49` folds into finding #16** — i.e. it is a faithful duplicate of a false positive. Dedup
  propagates errors as happily as it propagates truth.
- **`catalog.js:8` and `api/Dockerfile:3` fold into canonicals that S6 then dropped as FPs.** Those issues
  were therefore dismissed without ever being independently verified on their own merits. Both dismissals
  happen to be correct here, but the chain — S5 collapses B into A, S6 kills A, B dies silently — is a
  structural weakness, not a one-off.

### B.4 FP (15) — 13 correct, 1 with a false rationale, 1 inconsistent

**Correctly dropped, rationale verified (13):**

| Location | VVAH's reason | Verification |
|---|---|---|
| `tokens.js:21` | 15-min token + rotating revocable refresh is the standard pattern; scanner misread the TTL | **Correct.** `ACCESS_TOKEN_TTL='15m'` (`tokens.js:10`); refresh is opaque, hashed, single-use, revocable. Also disproves the "12h" claim in #16/#9. |
| `auth.js:25` | jsonwebtoken v9 rejects `alg=none` and blocks HS/RS confusion | **Correct.** `package.json` declares `^9.0.2`; installed is **9.0.3**. Pinning `algorithms:['HS256']` remains good hygiene but closes no reachable path. |
| `fauxpay/src/server.js:75` (logic-flaw) | No real acquirer, so no live-vs-dead PAN oracle | **Correct.** `/charge` returns `captured` for any known token; `/tokenize` accepts any 13-19 digits with no Luhn check. There is no signal to distinguish cards. *(Then hold this against finding #17.)* |
| `fauxpay/src/server.js:75` (other) | Bounded per-request growth behind a per-IP limiter = volumetric DoS (Rule D); `transactions.set` additionally gated by `requireApiKey` | **Correct for this component.** `nginx.conf:16` caps the route at 20 r/m and `/charge` is behind `requireApiKey` (`:89`). *(Contrast with the API-side map in B.1 — same smell, opposite verdict, because the rate ceiling in front of it is real. Good teaching pair.)* |
| `admin.js:33` | `price_cents` **is** validated at `:39-43` and `updated_by` **is** set at `:44`; the snippet stopped one line short | **Correct, verbatim.** The textbook self-corrected S4 false positive — five more lines of context refute it. |
| `cart.js:39` | Checkout's stock check short-circuits before the transaction, so the overflow/noisy-order impact never materializes | **Correct.** `orders.js:36-38` returns 400 before the transaction at `:47`. Residual: no cart quantity cap (hygiene). |
| `cs.js:14` | Privileged role required; Postgres ILIKE is linear; data impact already covered elsewhere | **Correct.** `cs.js:9` gates on `requireRole('customer_service')`, and the match-everything impact *is* finding #7. |
| `catalog.js:8` | Knex parameterises the value, so not SQLi; LIKE DoS is volumetric (Rule D) | **Correct.** `catalog.js:12` builds the *pattern* in a template literal, which Knex binds as a parameter; no `knex.raw`, no concatenated SQL, no dynamic ORDER BY anywhere in `api/src`. |
| `app.js:16` | Bare `cors()` sets ACAO `*` without ACAC; auth is a Bearer header, not ambient | **Correct.** `app.js:16` is `app.use(cors())`; the only cookie is httpOnly + SameSite=lax + path-scoped to `/api/auth`. No cross-origin privilege is gained. Residual: pin the origin (hardening). |
| `app.js:31` | Log forging is unreportable with no downstream parser (Rule E) | **Correct, and internally consistent** — no logger/shipper exists, so there is no parser to poison, and the *absence* of logging is separately reported as #22/#23. Same line, two findings, correctly split. |
| `api/Dockerfile:1` | Lockfiles exist in-repo and `npm install` honors them | **Correct.** All three `package-lock.json` files exist at `lockfileVersion: 3` (integrity hashes), and each Dockerfile copies one via `COPY package.json package-lock.json* ./`. Residual `npm install` vs `npm ci` is real but SCA/hardening territory. |
| `web/Dockerfile:3` | Same lockfile reasoning | **Correct.** Same verification. |
| `fauxpay/Dockerfile:3` | Dockerfile hygiene, owned by SCA (Rules D/E) | **Correct.** Same verification. |

**Verdict defensible, rationale factually wrong (1):**

- **`docker-compose.yml:82` (FauxPay key).** The rationale states *"the real processor secret has no
  code-level fallback anywhere in the repo."* That is false: `fauxpay/src/server.js:20` is
  `process.env.FAUXPAY_API_KEY || 'fauxpay_test_key'` — a working fallback that silently accepts a publicly
  known key. (The *consuming* side is clean — `fauxpayClient.js:2` has no fallback — which is probably what
  was meant, but it isn't what was written, and the fallback that matters is on the side that enforces the
  gate.) Award full credit for catching this: it is a checkable claim in the tool's own justification, and it
  is wrong.

**Inconsistent with the tool's own reported findings (1) — Discriminator 2:**

- **`docker-compose.yml:59` (DB password).** Facts are right (`:64` is
  `POSTGRES_PASSWORD: ${DB_PASSWORD:-widgetshop}`, documented at `:52-58`, and the db is `expose`d not
  `ports`-published). But the verdict rests entirely on **Rule B** — trusting a production-exclusion
  comment — which is the *exact* reasoning VVAH refused to apply to `JWT_SECRET` (#1, Critical) and the seed
  password (#2, Critical). Worse, the asymmetry runs backwards: `JWT_SECRET` has **no** fallback and fails
  closed at `server.js:3-6`, while the DB password has **two** working fallbacks (`knexfile.js:26` and the
  compose default). By the tool's own severity logic the DB password should have scored at least as high as
  the secret it dropped it in favor of.

---

## Part C — The three discriminators (what separates an A from a C)

1. **Reject #16 on evidence.** Not "this feels weak" — a `grep -rn NODE_ENV` that finds `api/Dockerfile:8`
   and nothing overriding it. Also catching the 15m-vs-12h error doubles the credit.
2. **Name the Rule B inconsistency.** `docker-compose.yml:59` dropped for trusting a training disclaimer
   while #1 and #2 scored Critical for ignoring one. The trainee doesn't have to say which verdict is right
   — a defensible answer can go either way — but they must notice the tool went both ways on identical
   evidence, and ideally that the dropped one has the weaker failure mode.
3. **Distrust the EXCLUDED bucket.** Spotting that five candidates died to a missing `Node JS/` path prefix
   rather than to analysis, and recovering the two real gaps hiding there (no per-account throttle;
   unbounded attacker-keyed limiter map).

A strong answer also notices the **internal contradiction between finding #17 and the
`fauxpay/src/server.js:75` FP**: the tool dropped the card-testing-oracle claim as physically unrealizable,
then kept a finding whose impact narrative depends on that same oracle.

---

## Part D — Real issues in neither list (bonus credit)

These never appeared as a reported finding *or* a dropped candidate — the scan produced no claim about them
at all. They are the ceiling of the exercise, and the honest answer to "is the scan complete?" is no.

- **Exchange workflow has no membership check, no state machine, and no settlement.** Verified:
  `cs.js:71-91` inserts `returned_widget_id`, `returned_quantity`, `replacement_widget_id`,
  `replacement_quantity` straight from `req.body` with **no** check that the returned item belongs to the
  order, no quantity cap against what was purchased, and no price-difference settlement;
  `cs.js:93-114` then lets `status` jump directly to `completed` with no allowed-transition table. A
  customer_service session can dispatch arbitrary high-value goods against any order. VVAH's *threat model*
  raised this as T20 but it was never promoted into an S4 finding. tm-assess reported it as its #9.
- **`GET /api/admin/orders` is unbounded too.** `admin.js:66` is `db('orders').orderBy('created_at','desc')`
  with no limit — the same defect as finding #7, at a second location neither report flagged as its own
  finding.
- **No session revocation path at all.** `tokens.js:110` keys `revokeSession` off the token the *caller*
  presents, so it is self-logout only; there is no password-change/reset route and no admin disable, so a
  demoted admin keeps a valid access token for up to 15 minutes and a compromised session cannot be ended by
  anyone but its holder. Also absent from VVAH entirely (tm-assess #4 and #5).
- **`cs.js:38-42` refund cap is a non-atomic SUM-then-INSERT**, upheld today only because FauxPay enforces
  its own cumulative cap atomically at `fauxpay/src/server.js:115-119`. An application invariant defended
  solely by a downstream dependency. Neither report treats it as a finding; worth full bonus credit.

---

## Rubric

Per item, full credit requires all three of:

1. a verdict (legitimate / false positive / correctly dropped / wrongly dropped),
2. the **file:line that settles it**, and
3. why the tool's stated reasoning was right or wrong.

A correct verdict with no supporting check is half credit — that is guessing, and on a 65-item list guessing
scores near 60% by base rate alone. Grade the *checks*, not the verdicts.

Suggested weighting:

| Component | Weight |
|---|---|
| Rejecting #16 with evidence | 20% |
| Recovering the two wrongly-excluded rate-limiter findings | 25% |
| Correcting the three over-rated findings (#17, #18, #19) without rejecting the underlying defect | 15% |
| Naming the Rule B inconsistency (`compose:59` vs #1/#2) | 15% |
| Upholding the 13 correct FPs with at least a spot-check on three of them | 15% |
| Part D bonus (any real issue absent from both lists) | 10% |

Hard fails: accepting all 24 uncritically; upholding all 41 drops; rejecting the six disclaimer-class
findings (#1–#4, #6, #10) without engaging with the scope question; or citing tm-assess (or any second tool)
as the *reason* for a verdict rather than as corroboration.

---

## Verification commands

Each refutes or confirms one claim in seconds. Run from `Node JS/`.

```bash
grep -rn "NODE_ENV" api/Dockerfile docker-compose.yml .env
```
Settles finding #16: the only hit is `api/Dockerfile:8 ENV NODE_ENV=production`, so the cookie is Secure.

```bash
grep -n "ACCESS_TOKEN_TTL\|REFRESH_TOKEN_TTL_MS" api/src/services/tokens.js
```
15m access / 7-day refresh — refutes the "12-hour access JWT" claim in #16 and #9.

```bash
sed -n '33,50p' api/src/routes/admin.js
```
Confirms the `admin.js:33` FP: `price_cents` validated at 39-43, `updated_by` set at 44.

```bash
grep -n "FAUXPAY_API_KEY" fauxpay/src/server.js api/src/services/fauxpayClient.js docker-compose.yml
```
Refutes the `docker-compose.yml:82` FP rationale: `fauxpay/src/server.js:20` does carry `|| 'fauxpay_test_key'`.

```bash
grep -n "stock_quantity" api/src/db/migrations/20260101000004_create_widgets.js
```
No `CHECK (stock_quantity >= 0)` — confirms finding #20 lands in the schema, not just in theory.

```bash
grep -rn "x-forwarded-for\|trust proxy" api/src && grep -n "proxy_set_header" web/nginx.conf
```
Confirms #8: the app trusts the header, Express is never told to, and nginx sets only `Host`.

```bash
grep -rn "req.body.email\|failed_login\|locked_until" api/src
```
Returns nothing relevant — confirms the per-account throttle recovered in B.1 does not exist anywhere.

```bash
ls api/package-lock.json web/package-lock.json fauxpay/package-lock.json && grep -n "COPY package" */Dockerfile
```
Confirms the three lockfile FPs: all present, all copied into the image.

---

## Cross-reference to the independent threat model

tm-assess ran against the same commit and is useful as corroboration only — never as a trainee's
justification. Where it agrees: VVAH #5/#7/#8/#9/#11/#12/#13/#14/#15/#20/#22/#23 and the FPs at `auth.js:25`,
`catalog.js:8`, `app.js:16`, `cs.js:14`. Where it disagrees with VVAH's *reported* set: it treats #1, #2, #3,
#4, #6, #10 as open questions rather than findings (the disclaimer split), rejects #17/#18/#19 on impact, and
independently reports the two findings VVAH lost to the EXCLUDED path bug. Its own misses are instructive
too: it did not reach finding #21 (the price-mutation race), which VVAH found. Full mapping in the
side-by-side comparison artifact produced alongside this key.
