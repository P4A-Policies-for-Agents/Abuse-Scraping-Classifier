# Abuse & Scraping Classifier — MuleSoft Omni/Flex Gateway Policy

An **inbound (request-leg) classifier** for the MuleSoft Omni/Flex Gateway that
reads the **shape of a client's recent requests** — not any single request — and
decides whether the client is using the API normally or **enumerating ids, bulk
scraping, probing auth, or probing for vulnerabilities**. It emits an upstream
header `x-jev-abuse: <verdict>` that a Rate Limiting policy can tier on, and can
optionally reject configured verdicts with **HTTP 429 Retry-After**.

A single `GET /orders/1002` is not abusive. The abuse lives in the *sequence*:
`GET /orders/1001`, `/orders/1002`, `/orders/1003`, … walked fast, mostly returning
403. This policy keeps a small **per-client rolling window** and classifies the
pattern — the thing per-request rules and static rate limits miss.

It is one of the **TypeSafe-Jev** gateway policy family: a typed **"System 1"
judge** returns a *choice + confidence*, never generated text — so there is **no
model in the data path** and all counting/decision logic stays in Rust.

Built with the PDK, Rust → `wasm32-wasip1`, split-model. Applies to **REST** and
**HTTP** (`assetTypes: rest,http`).

---

## How it classifies — track → compute → trigger → judge → act

On the **request leg**, per client (`clientKeyExpression`: an id claim surfaced as a
header, an api-key header, or the source IP):

1. **Track** a rolling window (`windowSize`, default 30; 10-minute TTL) of recent
   requests: method, normalised path template (`/orders/{id}` — numeric/UUID
   segments collapsed, raw id kept), status code, timestamp. Held in the PDK cache
   with **LRU eviction at `maxTrackedClients`** (default 10,000) — memory is bounded
   to `windowSize × maxTrackedClients`.
2. **Compute — in Rust, never the model:**
   - `rate_bucket` (`low | medium | high | very high`) from requests/minute vs
     `rateBuckets`.
   - `sequential_ids` — true if ≥ 70% of consecutive ids differ by 1.
   - `error_ratio_bucket` from the 4xx share.
   - `distinct_paths_bucket`.
3. **Trigger** the judge only when it already looks unusual: `rate ≥ medium` **or**
   `4xx share ≥ high` — and **at most once per `reevaluateSeconds`** per client (the
   verdict is cached for that period).
4. **Judge** — send the code-computed summary (`api_purpose`, `recent_requests[]`,
   `request_rate`, `sequential_ids`, `error_rate`, `distinct_endpoints`) to a typed
   Jev judge that answers one `behaviour` **choice** question. Never generated text.
5. **Resolve** — if the choice ≠ `normal_use` and confidence ≥ `minConfidence`, the
   verdict is that choice; otherwise `normal_use`.
6. **Act** — in `enforce`, set upstream `x-jev-abuse: <verdict>`; if the verdict is
   in `blockVerdicts`, reject with **429** + `Retry-After: reevaluateSeconds`.

On the **response leg** the policy appends this request's outcome (now the status
is known) to the client's window. It is the only writer; it buffers no body.

`mode` is **`enforce`** (set header / apply `blockVerdicts`) / **`shadow`** (compute
+ log, never mutate — the safe first deployment) / **`off`**. `failMode` is
effectively **open** here: a judge error/timeout leaves the client `normal_use` —
this classifier annotates and tiers, it is never a hard dependency in the path.

## Judge providers

`jevProvider` selects the judge and the request format sent:
`typesafe`/`cloudflare` use the TypeSafe Jev decisions envelope (`{model, state,
questions}`); `openai`/`openrouter`/`litellm`/`custom` drive an OpenAI-compatible
chat endpoint as a JSON classifier returning `{behaviour, confidence}`; `mock` is a
deterministic in-policy classifier for tests and offline demos (needs
`allowMock: true`). `~typesafe/jev-latest` is a **decisions** model → serve it with
`jevProvider: typesafe` (even through OpenRouter). See the sibling S1 README for the
full provider matrix — the transport shell is shared verbatim.

## Configuration (highlights)

| Property | Default | Purpose |
|---|---|---|
| `mode` | `shadow` | `enforce` / `shadow` / `off` |
| `failMode` | `open` | never fails closed (annotator) |
| `jevProvider` | `typesafe` | judge provider (`mock` for offline) |
| `jevService` | — (required) | judge base URL (`format: service`) |
| `clientKeyExpression` | `header:x-api-key` | `ip` / `header:<name>` / `claim:<name>` |
| `apiPurpose` | `""` | one-line API description given to the judge |
| `windowSize` | `30` | recent requests kept per client |
| `rateBuckets` | `[20, 40, 80]` | rpm thresholds `[medium, high, very_high]` |
| `reevaluateSeconds` | `60` | min seconds between judge calls per client; Retry-After |
| `minConfidence` | `0.6` | a non-normal choice below this → `normal_use` |
| `blockVerdicts` | `[]` | verdicts that get 429 in enforce (else annotate only) |
| `maxTrackedClients` | `10000` | LRU cap on distinct clients tracked |

Full schema: [`abuse-scraping-classifier-definition/gcl.yaml`](abuse-scraping-classifier-definition/gcl.yaml).

## Layout & build (split-model)

```
abuse-scraping-classifier-definition/   # gcl.yaml + exchange.json — the applyable policy asset
abuse-scraping-classifier-flex/          # Rust/wasm implementation
  src/ common.rs   # Mode/FailMode/Decision/Bands, glob, fnv1a (shared jev-policy-common)
      screen.rs    # RequestRecord/ClientWindow, path templating, buckets, trigger, verdict (pure)
      jev.rs       # Provider / JevSettings / evaluate + behaviour-choice signal parsing
      lib.rs       # per-client window in the PDK cache, request/response threading, entrypoint
demo/                                    # live A2D + Flex Gateway demo (see demo/PROVISION.md)
```

```bash
# Publish the DEFINITION FIRST — `make release` on the flex impl runs config-gen against it.
make -C abuse-scraping-classifier-definition release   # pdk policy-definition publish
make -C abuse-scraping-classifier-flex       release   # build-asset-files + build + policy-wasm publish
```
Requires PDK 1.10 (feature `enable_stop_iteration`, MIN_FLEX_VERSION 1.9.3),
cargo-anypoint, anypoint-cli-v4. **23 unit tests** (`cargo test --lib`) cover path
templating, bucket computation, trigger conditions, verdict/confidence resolution,
window bounding, and the judge parsers (typesafe choice + probability fallback,
OpenAI-compat, mock).

## Live demo

A customer self-service **Orders API** (A2D mock) behind a Flex Gateway route on
**omni-gw-small**, S7 in `enforce` with the deterministic `mock` judge. A normal
client reading its own order passes cleanly (no header, no judge call); a scraper
walking `GET /orders/{id}` over sequential ids is classified **`enumeration`** and
gets `x-jev-abuse: enumeration` then **429 Retry-After**. See
[`demo/PROVISION.md`](demo/PROVISION.md) to stand it up and
[`demo/WALKTHROUGH.md`](demo/WALKTHROUGH.md) for the story.

```bash
cp demo/config.json.example demo/config.json      # mock judge — no creds
cp demo/env.local.sh.example demo/env.local.sh     # set S7_GW_URL (+ optional S7_RAW_URL)
source demo/env.local.sh && ./demo/demo.sh
```
