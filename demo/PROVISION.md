# S7 Abuse & Scraping Classifier — live provisioning runbook

> Tenant ids, gateway hosts, and asset ids below are **placeholders** — fill them
> in from your Anypoint tenant. Real ids/keys live only in `demo/config.json` and
> `demo/env.local.sh` (both gitignored). This is the Phase-B outward runbook; the
> policy itself is built and unit-tested in Phase A (see the repo README).

## 0. Prerequisites
- `anypoint-cli-v4` authenticated (Sandbox env), org `<org-id>`.
- Live gateway **omni-gw-small** (has a public host): target `<gw-target-id>`,
  gateway version `<gw-version>`, public host `<omni-gw-small-public-host>`.
- Policy published to Exchange (definition + implementation) at 1.0.0 — see the
  repo README "Layout & build".

## 1. Publish the policy (split-model, definition first)
```bash
make -C abuse-scraping-classifier-definition release   # pdk policy-definition publish
make -C abuse-scraping-classifier-flex       release   # config-gen + build + policy-wasm publish
```

## 2. Create the mock Orders API (A2D)
Use the A2D MCP tools to stand up a REST mock from `demo/orders-api.openapi.json`:
- `design_rest_api` / `ai_generate_full_rest_api` with the provider org + a public
  URL; import `demo/orders-api.openapi.json`.
- Add **mock scenarios** so routing is:
  - `GET /orders/1001` → **200** with the sample order body.
  - `GET /orders/{anything-else}` → **403** `{"error":"forbidden"}`.
  - `GET /profile` → **200** with the sample profile.
- `publish_to_exchange_rest_api` → note the Exchange asset + the raw mock base URL
  (`https://www.a2d-ai.com/api/platform/<a2d-mock-api-id>`) for the ungoverned
  contrast run.

## 3. Manage + deploy the API on the gateway
```bash
anypoint-cli-v4 api-mgr:api:manage --isFlex --type http --withProxy \
  --gatewayVersion <gw-version> <orders-api-exchange-gav>
anypoint-cli-v4 api-mgr:api:deploy --target <gw-target-id> --gatewayVersion <gw-version> --overwrite <api-instance-id>
```
Governed base becomes `https://<omni-gw-small-public-host>/orders-demo`
(the route base you configured on the instance).

## 4. Apply S7
```bash
# Apply the classifier (inbound). No --order flag: order = apply sequence.
anypoint-cli-v4 api-mgr:policy:apply --config "$(cat demo/config.json)" \
  <api-instance-id> <s7-def-group>/abuse-scraping-classifier/1.0.0
anypoint-cli-v4 api-mgr:api:redeploy <api-instance-id>
```
`demo/config.json` uses the **mock** judge (`jevProvider: mock`, `allowMock: true`)
so no external key is needed. To demo the real judge, set `jevProvider: typesafe` +
`jevService: https://openrouter.ai` + `jevModel: ~typesafe/jev-latest` + `jevApiKey`
(see the sibling S1 config; the OpenRouter key stays in `demo/config.json` only).

## 5. Run the demo
```bash
cp demo/config.json.example demo/config.json        # mock judge — no creds
cp demo/env.local.sh.example demo/env.local.sh       # set S7_GW_URL (+ optional S7_RAW_URL)
source demo/env.local.sh && ./demo/demo.sh
```

## 6. Verify
- Normal client: all **200**, **no** `x-jev-abuse` header.
- Scraper client: 403s accumulate, then `x-jev-abuse: enumeration` and **429**
  `Retry-After: 30`.
- Flip `mode` to `shadow` in `demo/config.json`, re-apply + redeploy: scraper stays
  **200** throughout but the gateway log shows `verdict=enumeration`.
- (Optional) with `S7_RAW_URL` set, the same scraper against the ungoverned mock is
  never classified/blocked — the gateway is what adds the protection.
