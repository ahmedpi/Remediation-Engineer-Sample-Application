# Answer Key — API Rate Limiting Code Review (Instructor Only)

**Do not distribute to trainees.** Give them the code as-is. Unlike the [DESIGN.md exercise](ANSWER_KEY.md), where the gaps were pre-existing omissions in a document, these four were deliberately written into `Node JS/api/src/middleware/rateLimit.js` and `Node JS/api/src/routes/auth.js`. The code was written to read as a finished control: it has the trappings of a mature implementation (`Retry-After`, `RateLimit-*` headers, a sweep to clear expired windows, a separate looser bucket for `/refresh`), and it demonstrably works against the obvious attack. A trainee who tests "can I brute-force login?" from one machine will watch it return 429 on the 11th attempt and tick the control off as done.

That is the trap. The control is real; its **key** is wrong.

**On the comments:** they state plainly that this is rate limiting and nothing more — no rationale, no discussion of proxies, trust, memory growth, or what the control does not cover. Nothing in `rateLimit.js`, `auth.js` or `nginx.conf` hints at any of the findings below, and the trainee gets no prose to react to. Every finding has to come from reading the logic. Keep it that way if you edit these files: an explanatory comment about *why* the client IP is read from a header would hand over finding 2 outright.

Each entry: where it hides, why it's easy to miss, the concrete exploit, and the fix. Difficulty is rated for a developer with limited security background.

---

## Suggested framing

Hand trainees the two files plus `Node JS/web/nginx.conf`, and ask: *"We added login brute-force protection. Sign it off, or tell us what you'd send back."* Do not tell them how many issues there are. Findings 1 and 2 are the intended catch; 3 and 4 distinguish a strong answer.

A trainee who only says "looks good, it returns 429" has failed the exercise. A trainee who says "in-memory won't work across replicas" has found a real limitation but not a security finding — give partial credit and push them on *what the counter is keyed on*.

---

## 1. Throttling is keyed on IP alone — no per-account counter — Difficulty: Medium

**Where:** `rateLimit.js` — `const key = clientIp(req);` is the entire keying decision. `auth.js` — `credentialLimiter` is mounted on the route, so it never sees `req.body.email`.

**Why it's easy to miss:** "Rate limit the login endpoint" is the standard advice, and this does exactly that, with sensible-looking numbers (10 per 15 minutes). The limiter is mounted as route middleware, which is idiomatic Express and looks tidy — but it also means the throttle runs *before* anyone has looked at which account is being attacked. The missing control is invisible because nothing in the file is wrong; something is simply absent, and its absence is structurally hidden by good-looking code organisation.

**Exploit scenario:** An attacker with 30 source addresses — a cheap proxy pool, a small botnet, or a handful of cloud regions — targets one account. Each address gets its own 10-attempt budget, so the account absorbs 300 guesses per 15-minute window with the throttle never firing once. Nothing in the system counts failures *against the account*, so there is no ceiling on how long this runs and no signal that one account is under sustained attack. Verified: 30 guesses against one account from 30 distinct addresses, 0 throttled.

**What a good answer looks like:** Distinguishing "limit per caller" from "limit per account under attack", and naming that these defend against different things — per-IP limits the *rate of a single attacker*, per-account limits the *total exposure of one victim* regardless of how the traffic is spread. Bonus for noting there is no failed-login counter or alerting anywhere, so a distributed attack is not just unblocked but unobserved.

**Fix:** Keep the per-IP limit and add a second counter keyed on the submitted identifier (normalised email), with its own threshold and a progressive delay or temporary lock. Persist it outside process memory (see finding 3) so it survives restarts and works across instances. Emit a log or metric on threshold breach — a per-account limit no one watches is half a control. Beware the lockout DoS this can introduce (an attacker locking a victim out on purpose); prefer progressive delay plus step-up verification over a hard lock.

---

## 2. `X-Forwarded-For` is trusted without a trusted-proxy check — Difficulty: Medium-Hard

**Where:** `rateLimit.js` — `clientIp()`:

```js
const forwarded = req.headers['x-forwarded-for'];
if (forwarded) {
  return String(forwarded).split(',')[0].trim();
}
```

**Why it's subtle:** This is the single most-copied client-IP snippet in Node, and it encodes a premise that is genuinely true here — behind nginx, `req.socket.remoteAddress` really is the proxy's address, so reading the header really is necessary. The function is named `clientIp`, it falls back to the socket address, and it handles the comma-separated chain format, so it reads as the work of someone who knew about the proxy problem and handled it. Trainees who recognise the pattern tend to register it as the fix rather than the bug. The flaw is not that the header is read; it is that it is read from *any* caller, with no check that the request actually came from the proxy, and the leftmost value — the one wholly under client control — is the one taken.

**Exploit scenario:** The attacker sends `X-Forwarded-For: 10.0.0.<n>`, incrementing `n` each request. Every request lands in a fresh bucket, so the limiter counts to 1 forever. Verified: 40 consecutive login attempts with a rotating header, 0 throttled, ending in a successful `200` login on the victim's real password. No proxy pool needed — one host, one command.

**Interaction with the edge limiter (read this before running the exercise):** `web/nginx.conf` limits `login`/`register` to 10r/m keyed on `$binary_remote_addr`, the *real socket address*, which a forged header cannot influence. So an attacker arriving through the published port is still capped by nginx, and this bypass does not visibly pay off from the front door. It pays off when the attacker reaches the `api` container directly on the Docker network — which they can, since `api` and `web` share one compose network. That is the same trust-boundary theme as finding 2 in the design key, so the two exercises reinforce each other. If you want trainees to demonstrate the bypass end-to-end from the published port, loosen or remove the `api_auth` zone in `nginx.conf` first.

Note also that `nginx.conf` never sets `proxy_set_header X-Forwarded-For`, so a client-supplied header passes through the proxy untouched to the API.

**What a good answer looks like:** "The API derives identity for a security decision from a header the client controls, with nothing establishing that the request came from our proxy." Full marks for noting the fix has *two* halves — the proxy must overwrite the header and the app must be told which hops to trust — and that doing only one leaves the hole open. Partial credit for "we should use `req.ip`" without mentioning `trust proxy`, since `req.ip` is the socket address until Express is configured, which would key every request to the proxy's address and throttle the entire user base into a single bucket.

**Fix:** Both ends.

- nginx: `proxy_set_header X-Forwarded-For $remote_addr;` — overwrite, not append. `$proxy_add_x_forwarded_for` *appends* to whatever the client sent, which leaves a forged value sitting in the leftmost position and does not fix this.
- API: `app.set('trust proxy', 1)` (or the proxy's CIDR) and use `req.ip`, letting Express walk the chain from the right past exactly the hops you trust. Hand-rolled parsing must take the **rightmost** untrusted entry, never the leftmost.

---

## 3. Counter table is keyed on attacker-controlled input with no bound — Difficulty: Hard

**Where:** `rateLimit.js` — `const hits = new Map();`, and the sweep:

```js
const sweep = setInterval(() => { ... }, windowMs);
```

**Why it's subtle:** The sweep is the thing that makes this hard to spot. It genuinely does delete expired windows and is even `unref`'d so it will not hold the process open, so the file looks like it has already considered and solved the problem. Trainees who notice the unbounded `Map` usually find the sweep a few lines later and move on satisfied. The gap is timing and capacity, not absence: the sweep runs once per `windowMs` — every 15 minutes — and only removes entries whose window has already rolled over. Nothing caps how many entries accumulate *within* a window, and per finding 2 the key is a string the client chooses.

**Exploit scenario:** The attacker sends login requests with a unique `X-Forwarded-For` each time — random values, not even valid IPs, since nothing validates the format. Each allocates a new `Map` entry holding a key string and a small object, none eligible for sweeping until its 15-minute window expires. Sustained throughput against a single-process Node service turns into steady heap growth for a full window before any reclamation happens, so the limiter meant to protect the service becomes the cheapest way to exhaust it. The service is single-process (`server.js` does no clustering), so the crash takes the whole API with it.

**What a good answer looks like:** Connecting finding 2 to memory: "the key is attacker-controlled, so the store is attacker-sized." Recognising that the sweep bounds the table *across* windows but not *within* one. Strong answers will also note that fixing finding 2 substantially mitigates this — once the key can only be a real observed peer address, the keyspace is bounded by actual clients — which is a good illustration of one root cause behind two findings.

**Fix:** Primarily, fix finding 2 so the key is trustworthy. Then bound the store regardless: an LRU with a hard entry cap, or move counters to Redis with per-key TTLs, which also gives correctness across restarts and multiple instances (see finding 1). A production service should use a maintained implementation such as `express-rate-limit` with a shared store, rather than a hand-rolled `Map`.

---

## 4. Legitimate users on a shared address are locked out — Difficulty: Easy-Medium

**Where:** Consequence of the same keying decision in `rateLimit.js`; visible in that `credentialLimiter` runs before the handler and so blocks *all* attempts from an address, including ones that would have succeeded.

**Why it's easy to miss:** It is not an attack on the system, so trainees hunting for "how do I break in" walk straight past it. It also only shows up if you test the *success* path after tripping the limit, and most people confirm the limit fires and stop there.

**Exploit scenario:** Any address shared by many users — a corporate NAT, a university, a mobile carrier CGNAT, an office VPN egress — accumulates the 10 failures of its noisiest user within a 15-minute window, and everyone behind it is locked out of login, correct password and all. Verified: after tripping the limit, the victim's genuine password returns 429 rather than 200. An attacker can also weaponise this deliberately — 10 junk attempts from a known corporate egress denies login to that whole office. Note the limiter counts *every* attempt, not just failures, so successful logins consume budget too and a busy shared address burns through it faster than the numbers suggest.

**What a good answer looks like:** Framing rate limiting as a trade-off with availability rather than a pure win, and identifying shared-egress addresses as the failure case. Strong answers will spot that counting successes as well as failures is gratuitous — a successful login is evidence the caller is *not* an attacker.

**Fix:** Count only failed attempts (reset or skip on success). Prefer progressive delay over a hard block for the per-IP tier, reserving hard blocks for the per-account tier. Widen the IP-tier threshold and rely on the per-account counter from finding 1 for precision, since that is the control that actually targets the attack rather than the address.

---

## Reproduction

From a single host. Substitute the API's address; reach the `api` container directly on the compose network rather than through the published port if the nginx `api_auth` zone is still in place — see the note in finding 2.

```bash
for i in $(seq 1 14); do curl -s -o /dev/null -w '%{http_code} ' -X POST http://localhost:3000/api/auth/login -H 'Content-Type: application/json' -d "{\"email\":\"victim@example.com\",\"password\":\"guess$i\"}"; done; echo
```

The control works: 401 ten times, then 429.

```bash
for i in $(seq 1 40); do curl -s -o /dev/null -w '%{http_code} ' -X POST http://localhost:3000/api/auth/login -H 'Content-Type: application/json' -H "X-Forwarded-For: 10.0.0.$i" -d "{\"email\":\"victim@example.com\",\"password\":\"guess$i\"}"; done; echo
```

Finding 2: rotating the header, the throttle never fires.

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3000/api/auth/login -H 'Content-Type: application/json' -d '{"email":"victim@example.com","password":"the-real-password"}'
```

Finding 4: run this after tripping the limit — the correct password returns 429.

All figures quoted in this key were observed against the real route handlers with a stubbed database, not estimated.
