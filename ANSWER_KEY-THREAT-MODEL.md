# Answer Key — Threat Model Exercise (Instructor Only)

**Do not distribute to trainees.** Give them the running application (or the `Node JS/` source tree) and ask them to threat-model it — no hints, no pre-supplied finding count. This key grades two specific findings. Both are real, currently-present gaps in the shipped code, not planted bugs: they were independently rediscovered by two different automated pipelines run against this exact codebase (VVAH's agentic SAST scan and the tm-assess data-flow threat model, both dated 2026-09-17), which is good corroborating evidence they're the two most reliably-findable gaps in the current build rather than an artifact of one tool's blind spots.

Each entry: where it hides, why it's easy to miss, the concrete exploit, and the fix. Difficulty is rated for a developer with limited security background.

---

## Suggested framing

Hand trainees the app running under `docker compose up` (or the source tree) and ask: *"Threat-model the authentication and observability posture. What's missing, and how would you exploit it?"* Do not tell them how many findings there are or what class to look for.

A trainee who says "there's a rate limiter and it returns 429" or "there's a `console.error` in the error handler, so there's logging" has failed the exercise on the respective finding — both responses mistake the presence of *something* for the presence of the *control that matters*. A trainee who identifies the specific missing dimension (per-account throttling; structured security-event logging) has passed.

---

## 1. Rate limiting has no per-account dimension — Difficulty: Medium

**Where:** `Node JS/api/src/middleware/rateLimit.js` — `clientIp(req)` is the entire keying decision, and `Node JS/api/src/routes/auth.js` mounts `credentialLimiter` as route middleware, so it never inspects `req.body.email`. Reinforced by `Node JS/web/nginx.conf`'s `limit_req_zone` blocks, which are also keyed on address (`$binary_remote_addr` for the anchored zone), not on the identifier being authenticated.

**Why it's easy to miss:** The control is real and demonstrably works against the naive attack — it has `Retry-After` and `RateLimit-*` headers, a sweep that clears expired windows, and a separate, looser bucket for `/refresh`. A trainee who tests "can I brute-force login from one machine" watches it return 429 on the 11th attempt and checks the box. Two layers of rate limiting (nginx *and* the app) compounds the false confidence — it looks like defense in depth, but both layers key on the same dimension (caller address), so neither one closes the gap the other leaves.

**Exploit scenario:** An attacker with a handful of source addresses — a cheap proxy pool, a few cloud regions, or (per finding 2 in the retired `ANSWER_KEY-RATE-LIMITING.md` code-review exercise) a spoofed `X-Forwarded-For` header the app trusts with no trusted-proxy check — targets one victim account. Every address (real or forged) gets its own 10-attempts-per-15-minutes budget, so the *account* absorbs an effectively unbounded number of guesses while the per-address throttle never once fires. Nothing anywhere in the system counts failures against the account being attacked, so there is no ceiling on exposure and no signal that one account is under sustained attack — both tm-assess and VVAH independently flagged this as their top or near-top risk (tm-assess ranked it its #1 finding by severity).

**What a good answer looks like:** Distinguishing "limit the caller" from "limit the exposure of one victim" and naming that these defend against different things — a per-IP/per-socket limit bounds how fast *one attacker* can go, a per-account limit bounds how much *one victim* can absorb regardless of how the traffic is spread across addresses or forged headers. Bonus for noting there is no failed-login counter, lockout, or alert anywhere in the codebase, so a distributed low-and-slow campaign is not just unthrottled but invisible (this connects directly to finding 2).

**Fix:** Add a second counter keyed on the submitted identifier (normalized email), independent of the IP-keyed limiter, with its own threshold and a progressive delay rather than a hard lock (a hard per-account lock is itself a denial-of-service lever against any known email address — worth raising as a design trade-off, not just implementing blindly). Persist it outside in-process memory so it survives restarts and works across replicas. Emit a security event on threshold breach — see finding 2, since a limiter no one can see tripping is only half a control.

---

## 2. No application or security-event logging exists anywhere — Difficulty: Easy-Medium

**Where:** Absence, not a bad line — searched `Node JS/api/src/**`, `Node JS/fauxpay/src/**`, and `Node JS/web/nginx.conf` for any logging framework or structured log call. The only output in the entire stack is `console.error(err)` in the terminal error handler (`Node JS/api/src/app.js`), one `console.error` at boot if `JWT_SECRET` is unset, and one `console.log` boot banner (`Node JS/api/src/server.js`) — no `winston`, `pino`, `bunyan`, or `morgan` dependency anywhere in any of the three `package.json` files, no request-logging middleware, and no SIEM/Splunk/log-shipping integration of any kind.

**Why it's easy to miss:** `console.error(err)` in the global error handler *feels* like "we log errors," and a trainee scanning for "is there a try/catch with logging" will find one and move on. The absence only becomes visible when you ask a narrower question: not "does anything get printed," but "if this specific account gets brute-forced, refunded fraudulently, or promoted to admin right now, does any operator ever find out without the victim complaining first?" The answer is no for every security-relevant event in the system — failed logins, successful logins, role changes, refunds, bulk customer-data reads, and even the code's own strongest compromise signal (a refresh-token replay, which `Node JS/api/src/services/tokens.js` explicitly detects and revokes the whole token family for) produce zero log line, metric, or alert.

**Exploit scenario:** Combine with finding 1 — an attacker runs a distributed, low-and-slow credential-stuffing campaign against one account (or, per the retired rate-limiting code-review key, forges `X-Forwarded-For` to defeat the IP keying entirely from a single host). Every failed attempt returns a normal 401 with no trace left anywhere an operator could see. If the attacker eventually succeeds, the successful login is equally silent. If they trip the refresh-token reuse-detection path — the system's built-in "this token was probably stolen" signal — that gets acted on (the token family is revoked) but never reported, so an actual confirmed compromise indicator is manufactured and then thrown away. An incident responder investigating a customer complaint weeks later has nothing to reconstruct the timeline from beyond `console.error` output that likely never left the container's ephemeral stdout.

**What a good answer looks like:** Naming that "an error handler exists" and "security events are logged" are different claims, and that the second is false for every security-relevant action in the system, not just login. Full marks for listing concrete unlogged events beyond login — `authz.role.changed` (`PATCH /api/admin/users/:id/role`), `refund.issued`, `data.bulk_export` (unpaginated staff order reads), and `auth.refresh.reuse_detected` (the token-theft heuristic in `tokens.js` that currently fires and does nothing observable). Partial credit for "there's no logging" without connecting it to the specific consequence that detection, incident response, and even basic post-incident forensics are all impossible today.

**Fix:** Introduce a structured logger (e.g. `pino`) and a minimum security-event set with actor, action, target, and outcome on at least: `auth.login.success` / `auth.login.failure` (keyed on the attempted account, to make finding 1's remediation observable), `auth.refresh.reuse_detected`, `authz.role.changed`, `authz.denied` (every 401/403), `refund.issued`, and `data.bulk_export`. Ship it somewhere that survives the container (a log driver, forwarder, or SIEM/Splunk HEC integration — none exists today) rather than relying on captured stdout. Redact PII/secrets at the point of logging, not as an afterthought, since the current terminal handler already prints full error objects (including bound SQL parameters on a DB failure) with no redaction.

---

## Debrief talking point

Both findings share the same shape: **a real, working control sits directly next to the actual gap**, and the working part is what stops most reviewers from looking further. The rate limiter genuinely rate-limits; the error handler genuinely handles errors. Neither one does the specific job that matters — bounding exposure to *one victim account*, or producing a record an operator can act on — and both jobs require asking a narrower question than "is there a control here" ("is there a control here that does *this specific thing*"). This is deliberately the more realistic failure mode: most real-world reviews miss things not because nothing was built, but because something adjacent was built well enough to stop the reader from asking what it doesn't cover.

## Corroborating evidence (not for trainees)

Both findings were independently reproduced by two automated pipelines run against this codebase on 2026-09-17:

- **VVAH** (agentic SAST): finding 8 ("Rate-limit key spoofable via unvalidated X-Forwarded-For") and findings 22/23 ("No audit log for admin mutations / role changes", "No logging of failed logins or successful auth events") — `security-scan/Sample_Application_20260917T154119Z_report.md`
- **tm-assess** (data-flow threat model): finding 1 ("No account lockout or per-account throttle on login" — ranked as its top risk) and finding 7 ("No security audit logging anywhere in the system") — `out/reports/remediation-training-sample-app.md` (external to this repo; see the comparison artifact from this session for the full cross-reference)

Neither pipeline was told about the other's output or about this exercise in advance, which is reasonable evidence these two gaps are the most robustly findable in the current build — good candidates to keep grading on as the code evolves, as opposed to a finding that only one methodology happens to surface.
