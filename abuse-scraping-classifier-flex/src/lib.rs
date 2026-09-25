// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Abuse & Scraping Classifier — a request-leg Omni/Flex Gateway policy.
//!
//! Keeps a per-client rolling window of recent requests (method, templated path,
//! raw id, status, timestamp) in the PDK cache. On each request it computes — in
//! Rust — the request rate, whether the client is walking sequential ids, the 4xx
//! share, and how many distinct endpoints it touches. Only when that already looks
//! unusual (rate ≥ medium or 4xx ≥ high) does it call a typed "System 1" Jev judge,
//! and at most once per `reevaluateSeconds` per client (the verdict is cached). The
//! judge returns one `behaviour` choice; the policy sets an upstream request header
//! `x-jev-abuse: <verdict>` a downstream Rate Limiting policy can key on, and can
//! optionally reject `blockVerdicts` with HTTP 429.
//!
//! Two legs, both header-only (no body buffering):
//! - REQUEST: strip inbound `x-jev-*`, resolve the client key, read the window,
//!   compute buckets, decide/reuse a verdict, set the header (enforce), optionally
//!   `Flow::Break(429)`.
//! - RESPONSE: append this request's outcome (now the status is known) to the
//!   window and persist it. This is the only writer.
//!
//! `failMode` is always effectively open here — a judge error leaves the client
//! `normal_use` (never fail closed on a classifier that only annotates/tiers).

mod common;
mod generated;
mod jev;
mod screen;

use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use pdk::cache::{Cache, CacheBuilder, EvictionStrategy, LruStrategy};
use pdk::hl::*;
use pdk::logger;
use serde_json::json;

use crate::generated::config::Config;
use crate::jev::{evaluate, JevSettings, Provider};
use crate::screen::{
    compute_buckets, push_bounded, recent_request_lines, should_trigger, template_path,
    verdict_from_signals, ClientWindow, RateThresholds, RequestRecord,
};

const HDR: &str = "x-jev-abuse";
const NORMAL: &str = "normal_use";
// Rolling-window retention (plan: in-memory, 10 min TTL). Cache TTL is uniform.
const WINDOW_TTL_SECS: u64 = 600;

/// Threaded from the request leg to the response leg.
#[derive(Clone, Debug, Default)]
struct Ctx {
    /// Whether this exchange is in scope (mode != off).
    enabled: bool,
    client_key: String,
    method: String,
    path_template: String,
    id: Option<i64>,
    ts_ms: u64,
    /// Whether the judge was called this request (→ refresh the cached verdict).
    judged: bool,
    /// The resolved verdict (for logging + to persist when `judged`).
    verdict: String,
}

// ─── config helpers ─────────────────────────────────────────────────────────

fn jev_settings(cfg: &Config) -> JevSettings {
    JevSettings {
        provider: Provider::parse(cfg.jev_provider.as_deref().unwrap_or("typesafe")),
        model: cfg.jev_model.clone().unwrap_or_else(|| "~typesafe/jev-latest".to_string()),
        path: cfg.jev_path.clone().unwrap_or_default(),
        api_key: cfg.jev_api_key.clone().unwrap_or_default(),
        custom_auth_header: cfg.custom_auth_header.clone().unwrap_or_else(|| "Authorization".to_string()),
        timeout_ms: cfg.jev_timeout_ms.unwrap_or(600).max(1) as u64,
        max_state_tokens: cfg.max_state_tokens.unwrap_or(24000).max(256) as usize,
        cloudflare_account_id: cfg.cloudflare_account_id.clone(),
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn load_window(cache: &dyn Cache, key: &str) -> ClientWindow {
    cache
        .get(key)
        .and_then(|b| serde_json::from_slice::<ClientWindow>(&b).ok())
        .unwrap_or_default()
}

fn save_window(cache: &dyn Cache, key: &str, w: &ClientWindow) {
    if let Ok(bytes) = serde_json::to_vec(w) {
        let _ = cache.save(key, bytes);
    }
}

/// Resolve the client key. `clientKeyExpression` forms: `ip` (first `x-forwarded-for`
/// hop, else `x-real-ip`), `header:<name>` (or a bare header name), and `claim:<name>`
/// (best-effort: reads header `<name>` — a preceding JWT policy is expected to surface
/// the claim as a header). Missing → `anonymous`.
fn resolve_client_key(expr: &str, h: &dyn HeadersHandler) -> String {
    let val = |name: &str| h.header(name).unwrap_or_default();
    let key = if expr == "ip" {
        let xff = val("x-forwarded-for");
        if !xff.is_empty() {
            xff.split(',').next().unwrap_or("").trim().to_string()
        } else {
            val("x-real-ip")
        }
    } else if let Some(name) = expr.strip_prefix("header:").or_else(|| expr.strip_prefix("claim:")) {
        val(name)
    } else if !expr.is_empty() {
        val(expr)
    } else {
        val("x-api-key")
    };
    if key.trim().is_empty() {
        "anonymous".to_string()
    } else {
        key
    }
}

// ─── request leg ─────────────────────────────────────────────────────────────

async fn request_filter(request_state: RequestState, cfg: Rc<Config>, cache: Rc<dyn Cache>, client: Rc<HttpClient>) -> Flow<Ctx> {
    let mode = common::Mode::parse(cfg.mode.as_deref().unwrap_or("shadow"));
    let headers = request_state.into_headers_state().await;

    // Strip inbound x-jev-* so a client cannot spoof the downstream tier.
    if cfg.strip_client_jev_headers.unwrap_or(true) {
        headers.handler().remove_header(HDR);
    }
    if mode == common::Mode::Off {
        return Flow::Continue(Ctx::default());
    }

    let method = headers.method().to_uppercase();
    let raw_path = headers.path();
    let client_key = {
        let expr = cfg.client_key_expression.as_deref().unwrap_or("header:x-api-key");
        resolve_client_key(expr, headers.handler())
    };
    let (path_template, id) = template_path(&raw_path);

    // Read the client's window (records so far — this request is recorded on the
    // response leg) and compute the buckets over it.
    let window = load_window(&*cache, &client_key);
    let rt = RateThresholds::from_slice(cfg.rate_buckets.as_deref().unwrap_or(&[]));
    let ts_ms = now_ms();
    let buckets = compute_buckets(&window.records, ts_ms, &rt);

    let window_size = cfg.window_size.unwrap_or(30).max(1) as usize;
    let reeval_ms = cfg.reevaluate_seconds.unwrap_or(60).max(1) as u64 * 1000;
    let min_conf = cfg.min_confidence.unwrap_or(0.6);
    let settings = jev_settings(&cfg);

    let trigger = should_trigger(&buckets);
    let cached_fresh = window.verdict.is_some() && ts_ms.saturating_sub(window.last_eval_ms) < reeval_ms;

    // Decide the verdict: reuse a fresh cached one; else judge if triggered; else normal.
    let (verdict, judged) = if !trigger {
        (NORMAL.to_string(), false)
    } else if cached_fresh {
        (window.verdict.clone().unwrap_or_else(|| NORMAL.to_string()), false)
    } else if settings.provider == Provider::Mock && !cfg.allow_mock.unwrap_or(false) {
        // Mock disabled and no real judge configured → fail open (normal_use).
        logger::warn!("s7: mock provider disabled (allowMock=false) — failing open");
        (NORMAL.to_string(), false)
    } else {
        let state = json!({
            "api_purpose": cfg.api_purpose.clone().unwrap_or_default(),
            "recent_requests": recent_request_lines(&window.records, window_size),
            "request_rate": buckets.rate.word(),
            "sequential_ids": buckets.sequential_ids,
            "error_rate": buckets.error.word(),
            "distinct_endpoints": buckets.distinct.word(),
        });
        match evaluate(&client, &cfg.jev_service, &settings, &state).await {
            Ok(res) => {
                let v = verdict_from_signals(&res.signals, min_conf);
                logger::debug!(
                    "s7: judged client={client_key} rate={} seq={} err={} distinct={} -> {v} (model={})",
                    buckets.rate.word(), buckets.sequential_ids, buckets.error.word(), buckets.distinct.word(), res.model
                );
                (v, true)
            }
            Err(e) => {
                logger::warn!("s7: judge error {e:?} — failing open (normal_use)");
                (NORMAL.to_string(), false)
            }
        }
    };

    logger::info!(
        "s7: mode={:?} client={client_key} rate={} rpm={} seq={} err={:.2} distinct={} trigger={trigger} verdict={verdict}",
        mode, buckets.rate.word(), buckets.rate_per_min, buckets.sequential_ids, buckets.error_ratio, buckets.distinct_paths
    );

    let ctx = Ctx {
        enabled: true,
        client_key,
        method,
        path_template,
        id,
        ts_ms,
        judged,
        verdict: verdict.clone(),
    };

    // Enforce: set the upstream tier header and optionally reject. Shadow: compute +
    // log + record only (no mutation).
    if mode.mutates() {
        headers.handler().set_header(HDR, &verdict);
        let blocked = verdict != NORMAL
            && cfg.block_verdicts.as_deref().unwrap_or(&[]).iter().any(|v| v == &verdict);
        if blocked {
            let retry = cfg.reevaluate_seconds.unwrap_or(60).max(1);
            let body = json!({
                "error": "abuse_detected",
                "behaviour": verdict,
                "policy": "abuse-scraping-classifier"
            })
            .to_string();
            logger::info!("s7: BLOCK client={} verdict={verdict} retry_after={retry}", ctx.client_key);
            // Record the block synchronously — a Break short-circuits the response leg.
            let mut w = load_window(&*cache, &ctx.client_key);
            push_bounded(
                &mut w.records,
                RequestRecord { method: ctx.method.clone(), path_template: ctx.path_template.clone(), id: ctx.id, status: 429, ts_ms },
                window_size,
            );
            w.last_eval_ms = ts_ms;
            w.verdict = Some(verdict.clone());
            save_window(&*cache, &ctx.client_key, &w);
            return Flow::Break(
                Response::new(429)
                    .with_headers(vec![
                        ("retry-after".to_string(), retry.to_string()),
                        ("content-type".to_string(), "application/json".to_string()),
                        (HDR.to_string(), verdict.clone()),
                    ])
                    .with_body(body.as_str()),
            );
        }
    }

    Flow::Continue(ctx)
}

// ─── response leg ─────────────────────────────────────────────────────────────

async fn response_filter(response_state: ResponseState, request_data: RequestData<Ctx>, cfg: Rc<Config>, cache: Rc<dyn Cache>) {
    let RequestData::Continue(ctx) = request_data else { return };
    if !ctx.enabled {
        return;
    }
    let headers = response_state.into_headers_state().await;
    let status = headers.status_code() as u16;

    let window_size = cfg.window_size.unwrap_or(30).max(1) as usize;
    // Sole writer: re-read (picks up any concurrent update), append this outcome,
    // refresh the cached verdict if we judged this request, and persist.
    let mut w = load_window(&*cache, &ctx.client_key);
    push_bounded(
        &mut w.records,
        RequestRecord { method: ctx.method.clone(), path_template: ctx.path_template.clone(), id: ctx.id, status, ts_ms: ctx.ts_ms },
        window_size,
    );
    if ctx.judged {
        w.last_eval_ms = ctx.ts_ms;
        w.verdict = Some(ctx.verdict.clone());
    }
    save_window(&*cache, &ctx.client_key, &w);
}

// ─── launch ───────────────────────────────────────────────────────────────────

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    cache_builder: CacheBuilder,
    client: HttpClient,
) -> anyhow::Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow::anyhow!("Failed to parse configuration '{}'. Cause: {}", String::from_utf8_lossy(&bytes), err)
    })?;

    // LRU eviction at `maxTrackedClients` bounds memory to window_size × clients;
    // the uniform TTL expires idle clients (plan: 10-minute window retention).
    let max_clients = config.max_tracked_clients.unwrap_or(10_000).max(1) as usize;
    let cache: Rc<dyn Cache> = Rc::new(
        cache_builder
            .new("abuse-scraping-classifier".to_string())
            .eviction_strategy(EvictionStrategy::Lru(LruStrategy::default().with_shards(1)))
            .ttl(std::time::Duration::from_secs(WINDOW_TTL_SECS))
            .max_entries(max_clients)
            .build(),
    );

    let config = Rc::new(config);
    let client = Rc::new(client);

    let cfg_req = config.clone();
    let cache_req = cache.clone();
    let client_req = client.clone();
    let filter = on_request(move |rs| {
        let c = cfg_req.clone();
        let ca = cache_req.clone();
        let cl = client_req.clone();
        async move { request_filter(rs, c, ca, cl).await }
    })
    .on_response(move |rs, rd| {
        let c = config.clone();
        let ca = cache.clone();
        async move { response_filter(rs, rd, c, ca).await }
    });
    launcher.launch(filter).await?;
    Ok(())
}
