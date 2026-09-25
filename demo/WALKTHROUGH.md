# S7 Abuse & Scraping Classifier — demo walkthrough

## The story

A customer self-service **Orders API** lets a signed-in customer read **their own**
orders: `GET /orders/{id}`. Nothing about a single request is abusive — the abuse
is in the **shape of a sequence of requests**. An attacker who wants to know which
order ids exist, or to harvest every order they can reach, walks the id space:
`GET /orders/1001`, `/orders/1002`, `/orders/1003`, … as fast as they can. Because
they only own one order, almost all of those come back **403** — a classic
enumeration fingerprint that no single-request rule sees.

S7 watches the **sequence per client**. It keeps a small rolling window (method,
templated path `/orders/{id}`, the raw id, status, timestamp) and computes — in
Rust, never in the model — the request rate, whether the ids are **sequential**,
the **4xx share**, and how many **distinct endpoints** are touched. Only when that
already looks unusual does it ask a typed Jev judge one question: *given this is a
customer self-service orders API, what is this client doing?* The judge returns one
choice — `normal_use | enumeration | bulk_scraping | auth_probing |
vulnerability_probing` — and a confidence. The policy turns that into an upstream
header `x-jev-abuse: <verdict>` that a Rate Limiting policy can tier on, and
(optionally) rejects listed verdicts with **429 Retry-After**.

## The two clients (what the demo runs)

**Normal client** (`x-api-key: cust-1001-normal`) reads its own order `/orders/1001`
and `/profile` a few times, slowly:

```
[ normal] GET /orders/1001    -> 200
[ normal] GET /profile        -> 200
...
=> all 200, NO x-jev-abuse header. Rate stays low, 4xx share is 0, so the
   trigger never fires and the judge is never called. Zero added latency.
```

**Scraper client** (`x-api-key: scraper-9f`) walks `/orders/1001..1030` as fast as
it can. It owns only 1001, so the rest are 403:

```
[scraper] GET /orders/1001    -> 200
[scraper] GET /orders/1002    -> 403
[scraper] GET /orders/1003    -> 403
...                                     (sequential ids + rising 4xx + high rate)
[scraper] GET /orders/1012    -> 403    x-jev-abuse: enumeration
[scraper] GET /orders/1013    -> 429    x-jev-abuse: enumeration  Retry-After: 30
...
=> once the window trips the trigger, the judge classifies `enumeration`;
   the gateway stamps x-jev-abuse and (enumeration in blockVerdicts) returns 429.
```

The exact request at which the verdict appears depends on how fast the window
fills — the trigger is `rate >= medium OR 4xx share >= high`, and with the demo's
lowered `rateBuckets: [10,20,40]` and a burst of 403s it trips within the first
dozen requests. After the first judge call the verdict is **cached for
`reevaluateSeconds`** (30s here), so the judge is called at most once per client
per period no matter how many requests the scraper fires.

## Why this is safe and cheap

- **The judge never counts.** All counting (rate, sequential-id ratio, 4xx share,
  distinct paths) is deterministic Rust. The judge only interprets a word-bucketed
  summary, so it can't be fooled into miscounting and it can't leak the raw ids.
- **The judge is rarely called.** Normal traffic never triggers it; abusive
  traffic triggers it at most `1 / reevaluateSeconds` per client.
- **Fail open.** A judge timeout/error leaves the client `normal_use` — the
  classifier tiers and annotates, it is never a hard dependency in the request path.
- **Shadow first.** Deploy in `shadow` to watch verdicts in the logs with zero
  request impact, then flip to `enforce` (header + optional 429).

## Toggles to show live

- `mode: shadow` → the same scraper run logs `verdict=enumeration` but returns 200s
  throughout and sets no header — proves the classification without enforcing.
- `blockVerdicts: []` → header is set (`x-jev-abuse: enumeration`) but no 429; hand
  off to a downstream Rate Limiting policy keyed on the header instead.
- `clientKeyExpression: ip` → key clients by source IP instead of api-key.
