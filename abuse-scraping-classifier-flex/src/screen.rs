// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Deterministic behaviour summarisation for the Abuse & Scraping Classifier.
//!
//! Everything here is a **pure function over a `&[RequestRecord]` window** — no
//! gateway types, no clock, no I/O — so the rate/sequential-id/error/distinct
//! buckets, the trigger predicate, and the verdict resolution are all unit-tested
//! in isolation. `lib.rs` owns the cache wiring and passes `now_ms` in.
//!
//! The judge (`jev.rs`) is a typed "System 1" classifier: given a *code-computed*
//! summary of recent requests it returns one `behaviour` choice + confidence. We
//! never ask it to count or compare numbers — the counting is all here, in Rust.

use serde::{Deserialize, Serialize};

/// One completed request in a client's rolling window. Serialised into the PDK
/// cache. `path_template` has numeric/UUID segments collapsed to `{id}`; `id`
/// keeps the first raw numeric id (for sequential-enumeration detection).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RequestRecord {
    pub method: String,
    pub path_template: String,
    pub id: Option<i64>,
    pub status: u16,
    pub ts_ms: u64,
}

/// Per-client rolling window + cached verdict, persisted in the PDK cache under
/// the client key. TTL + LRU eviction (`maxTrackedClients`) are the cache's job.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientWindow {
    #[serde(default)]
    pub records: Vec<RequestRecord>,
    /// Epoch-ms of the last judge call for this client (0 = never).
    #[serde(default)]
    pub last_eval_ms: u64,
    /// Verdict cached from that judge call, reused until `reevaluateSeconds` elapse.
    #[serde(default)]
    pub verdict: Option<String>,
}

/// The judge's typed answer. Kept here (not in `jev.rs`) so the transport shell
/// depends on the policy, mirroring the S1 split.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Signals {
    /// (behaviour choice, confidence 0..1).
    pub behaviour: Option<(String, f64)>,
}

/// Requests-per-minute thresholds: `[medium, high, very_high]`.
#[derive(Clone, Copy, Debug)]
pub struct RateThresholds {
    pub medium: f64,
    pub high: f64,
    pub very_high: f64,
}

impl Default for RateThresholds {
    fn default() -> Self {
        RateThresholds { medium: 20.0, high: 40.0, very_high: 80.0 }
    }
}

impl RateThresholds {
    /// Build from a config array `[medium, high, very_high]`; missing/short → default,
    /// and values are sorted so a misconfiguration can never invert the ladder.
    pub fn from_slice(v: &[f64]) -> RateThresholds {
        if v.len() < 3 {
            return RateThresholds::default();
        }
        let mut xs = [v[0], v[1], v[2]];
        xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        RateThresholds { medium: xs[0], high: xs[1], very_high: xs[2] }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RateBucket {
    Low,
    Medium,
    High,
    VeryHigh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorBucket {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DistinctBucket {
    Few,
    Some,
    Many,
}

impl RateBucket {
    pub fn word(self) -> &'static str {
        match self {
            RateBucket::Low => "low",
            RateBucket::Medium => "medium",
            RateBucket::High => "high",
            RateBucket::VeryHigh => "very high",
        }
    }
}

impl ErrorBucket {
    pub fn word(self) -> &'static str {
        match self {
            ErrorBucket::Low => "low",
            ErrorBucket::Medium => "medium",
            ErrorBucket::High => "high",
        }
    }
}

impl DistinctBucket {
    pub fn word(self) -> &'static str {
        match self {
            DistinctBucket::Few => "few",
            DistinctBucket::Some => "some",
            DistinctBucket::Many => "many",
        }
    }
}

// 4xx share thresholds (fixed — not exposed as config per the plan's knob list).
const ERROR_MEDIUM: f64 = 0.10;
const ERROR_HIGH: f64 = 0.30;
// A trailing-minute window for the rate computation.
const RATE_WINDOW_MS: u64 = 60_000;
// Minimum consecutive-id pairs before `sequential_ids` can be true (avoids a
// spurious "true" from one or two records).
const MIN_SEQ_PAIRS: usize = 3;
const SEQ_RATIO: f64 = 0.70;

/// The code-computed behaviour summary handed to the judge.
#[derive(Clone, Debug, PartialEq)]
pub struct Buckets {
    pub rate_per_min: usize,
    pub rate: RateBucket,
    pub sequential_ids: bool,
    pub error_ratio: f64,
    pub error: ErrorBucket,
    pub distinct_paths: usize,
    pub distinct: DistinctBucket,
}

/// Compute the buckets over a window as of `now_ms`. Pure.
pub fn compute_buckets(records: &[RequestRecord], now_ms: u64, rt: &RateThresholds) -> Buckets {
    // Rate: requests seen in the trailing minute.
    let rate_per_min = records
        .iter()
        .filter(|r| now_ms.saturating_sub(r.ts_ms) < RATE_WINDOW_MS)
        .count();
    let rate = rate_bucket(rate_per_min as f64, rt);

    // Sequential ids: fraction of consecutive id pairs that differ by exactly 1.
    let ids: Vec<i64> = records.iter().filter_map(|r| r.id).collect();
    let mut pairs = 0usize;
    let mut consecutive = 0usize;
    for w in ids.windows(2) {
        pairs += 1;
        if (w[0] - w[1]).abs() == 1 {
            consecutive += 1;
        }
    }
    let sequential_ids = pairs >= MIN_SEQ_PAIRS && (consecutive as f64) / (pairs as f64) >= SEQ_RATIO;

    // Error ratio: share of 4xx responses.
    let total = records.len();
    let errors = records.iter().filter(|r| (400..500).contains(&r.status)).count();
    let error_ratio = if total == 0 { 0.0 } else { errors as f64 / total as f64 };
    let error = if error_ratio >= ERROR_HIGH {
        ErrorBucket::High
    } else if error_ratio >= ERROR_MEDIUM {
        ErrorBucket::Medium
    } else {
        ErrorBucket::Low
    };

    // Distinct templated paths.
    let mut seen: Vec<&str> = Vec::new();
    for r in records {
        if !seen.contains(&r.path_template.as_str()) {
            seen.push(r.path_template.as_str());
        }
    }
    let distinct_paths = seen.len();
    let distinct = if distinct_paths <= 2 {
        DistinctBucket::Few
    } else if distinct_paths <= 5 {
        DistinctBucket::Some
    } else {
        DistinctBucket::Many
    };

    Buckets { rate_per_min, rate, sequential_ids, error_ratio, error, distinct_paths, distinct }
}

fn rate_bucket(rpm: f64, rt: &RateThresholds) -> RateBucket {
    if rpm >= rt.very_high {
        RateBucket::VeryHigh
    } else if rpm >= rt.high {
        RateBucket::High
    } else if rpm >= rt.medium {
        RateBucket::Medium
    } else {
        RateBucket::Low
    }
}

/// Trigger the judge only when the traffic already looks unusual: rate ≥ medium
/// OR 4xx share ≥ high. This bounds judge calls to interesting clients.
pub fn should_trigger(b: &Buckets) -> bool {
    b.rate >= RateBucket::Medium || b.error >= ErrorBucket::High
}

/// Normalise a request path into a template + first raw numeric id.
/// Numeric segments and UUID-shaped segments collapse to `{id}`; the first
/// numeric segment's value is returned for sequential-enumeration detection.
pub fn template_path(path: &str) -> (String, Option<i64>) {
    // Drop any query string first.
    let raw = path.split('?').next().unwrap_or("");
    let mut first_id: Option<i64> = None;
    let mut out = String::with_capacity(raw.len());
    let mut first = true;
    for seg in raw.split('/') {
        if !first {
            out.push('/');
        }
        first = false;
        if seg.is_empty() {
            continue;
        }
        if is_numeric(seg) {
            if first_id.is_none() {
                first_id = seg.parse::<i64>().ok();
            }
            out.push_str("{id}");
        } else if is_uuid(seg) {
            out.push_str("{id}");
        } else {
            out.push_str(seg);
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    (out, first_id)
}

fn is_numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// UUID shape: 8-4-4-4-12 hex with dashes.
fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        let is_dash = i == 8 || i == 13 || i == 18 || i == 23;
        if is_dash {
            if c != b'-' {
                return false;
            }
        } else if !c.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Render the window as the `recent_requests` state lines the judge reads, e.g.
/// `"GET /orders/{id} (id=1002) 403"`. Most-recent last, capped at `limit`.
pub fn recent_request_lines(records: &[RequestRecord], limit: usize) -> Vec<String> {
    let start = records.len().saturating_sub(limit);
    records[start..]
        .iter()
        .map(|r| match r.id {
            Some(id) => format!("{} {} (id={}) {}", r.method, r.path_template, id, r.status),
            None => format!("{} {} {}", r.method, r.path_template, r.status),
        })
        .collect()
}

/// Resolve the judge's answer into a verdict string, honouring `min_confidence`.
/// A non-`normal_use` choice only stands if confidence ≥ threshold; otherwise the
/// client is treated as normal.
pub fn verdict_from_signals(sig: &Signals, min_confidence: f64) -> String {
    match &sig.behaviour {
        Some((choice, conf)) if choice != "normal_use" && *conf >= min_confidence => choice.clone(),
        _ => "normal_use".to_string(),
    }
}

/// Push a record into the window and truncate to the newest `window_size`.
pub fn push_bounded(records: &mut Vec<RequestRecord>, rec: RequestRecord, window_size: usize) {
    records.push(rec);
    let ws = window_size.max(1);
    if records.len() > ws {
        let drop = records.len() - ws;
        records.drain(0..drop);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(method: &str, path: &str, id: Option<i64>, status: u16, ts_ms: u64) -> RequestRecord {
        RequestRecord { method: method.into(), path_template: path.into(), id, status, ts_ms }
    }

    #[test]
    fn templates_numeric_and_uuid_segments() {
        let (t, id) = template_path("/orders/1002");
        assert_eq!(t, "/orders/{id}");
        assert_eq!(id, Some(1002));

        let (t2, id2) = template_path("/v1/customers/9f8e7d6c-1234-4abc-8def-0123456789ab/orders");
        assert_eq!(t2, "/v1/customers/{id}/orders");
        assert_eq!(id2, None); // no numeric segment

        let (t3, _) = template_path("/orders/1002?expand=items");
        assert_eq!(t3, "/orders/{id}"); // query stripped
    }

    #[test]
    fn template_keeps_non_id_paths() {
        let (t, id) = template_path("/health");
        assert_eq!(t, "/health");
        assert_eq!(id, None);
    }

    #[test]
    fn rate_bucket_ladder() {
        let rt = RateThresholds::default(); // 20/40/80
        assert_eq!(rate_bucket(5.0, &rt), RateBucket::Low);
        assert_eq!(rate_bucket(20.0, &rt), RateBucket::Medium);
        assert_eq!(rate_bucket(41.0, &rt), RateBucket::High);
        assert_eq!(rate_bucket(200.0, &rt), RateBucket::VeryHigh);
    }

    #[test]
    fn rate_thresholds_from_slice_sorts() {
        let rt = RateThresholds::from_slice(&[80.0, 20.0, 40.0]);
        assert_eq!(rt.medium, 20.0);
        assert_eq!(rt.high, 40.0);
        assert_eq!(rt.very_high, 80.0);
        // short slice falls back to default
        let d = RateThresholds::from_slice(&[10.0]);
        assert_eq!(d.medium, 20.0);
    }

    #[test]
    fn detects_sequential_enumeration() {
        // 10 sequential GET /orders/{id} at 403 within the same minute.
        let recs: Vec<RequestRecord> = (0..10)
            .map(|i| rec("GET", "orders/{id}", Some(1000 + i), 403, 1_000 + i as u64 * 50))
            .collect();
        let b = compute_buckets(&recs, 1_600, &RateThresholds::from_slice(&[3.0, 6.0, 9.0]));
        assert!(b.sequential_ids);
        assert_eq!(b.distinct, DistinctBucket::Few);
        assert!(b.error_ratio > 0.9);
        assert_eq!(b.error, ErrorBucket::High);
        assert!(b.rate >= RateBucket::VeryHigh);
        assert!(should_trigger(&b));
    }

    #[test]
    fn normal_low_traffic_does_not_trigger() {
        let recs = vec![
            rec("GET", "orders/{id}", Some(1001), 200, 1_000),
            rec("GET", "orders/{id}", Some(1001), 200, 20_000),
            rec("GET", "profile", None, 200, 40_000),
        ];
        let b = compute_buckets(&recs, 41_000, &RateThresholds::default());
        assert!(!b.sequential_ids);
        assert_eq!(b.error, ErrorBucket::Low);
        assert!(b.rate < RateBucket::Medium);
        assert!(!should_trigger(&b));
    }

    #[test]
    fn error_ratio_alone_triggers() {
        // Low rate but a high 4xx share (auth probing) must trigger.
        let recs = vec![
            rec("GET", "admin", None, 403, 0),
            rec("GET", "admin", None, 403, 10_000),
            rec("GET", "admin", None, 200, 20_000),
            rec("GET", "admin", None, 403, 30_000),
        ];
        let b = compute_buckets(&recs, 200_000, &RateThresholds::default()); // rate window empty → Low
        assert_eq!(b.rate, RateBucket::Low);
        assert!(b.error >= ErrorBucket::High);
        assert!(should_trigger(&b));
    }

    #[test]
    fn rate_only_counts_trailing_minute() {
        let mut recs: Vec<RequestRecord> = Vec::new();
        // 5 old (outside the minute) + 25 recent
        for i in 0..5 {
            recs.push(rec("GET", "orders/{id}", Some(i), 200, i as u64 * 10));
        }
        for i in 0..25 {
            recs.push(rec("GET", "orders/{id}", Some(100 + i), 200, 100_000 + i as u64 * 100));
        }
        let b = compute_buckets(&recs, 105_000, &RateThresholds::default());
        assert_eq!(b.rate_per_min, 25); // old ones excluded
    }

    #[test]
    fn recent_lines_format_and_cap() {
        let recs = vec![
            rec("GET", "orders/{id}", Some(1001), 200, 0),
            rec("GET", "orders/{id}", Some(1002), 403, 1),
            rec("GET", "profile", None, 200, 2),
        ];
        let lines = recent_request_lines(&recs, 2);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "GET orders/{id} (id=1002) 403");
        assert_eq!(lines[1], "GET profile 200");
    }

    #[test]
    fn verdict_honours_min_confidence() {
        let sig = Signals { behaviour: Some(("enumeration".into(), 0.9)) };
        assert_eq!(verdict_from_signals(&sig, 0.6), "enumeration");
        // below threshold → treated as normal
        let weak = Signals { behaviour: Some(("enumeration".into(), 0.4)) };
        assert_eq!(verdict_from_signals(&weak, 0.6), "normal_use");
        // explicit normal_use choice
        let norm = Signals { behaviour: Some(("normal_use".into(), 0.95)) };
        assert_eq!(verdict_from_signals(&norm, 0.6), "normal_use");
        // no signal → normal
        assert_eq!(verdict_from_signals(&Signals::default(), 0.6), "normal_use");
    }

    #[test]
    fn push_bounded_keeps_newest() {
        let mut recs: Vec<RequestRecord> = Vec::new();
        for i in 0..5 {
            push_bounded(&mut recs, rec("GET", "orders/{id}", Some(i), 200, i as u64), 3);
        }
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].id, Some(2)); // oldest two dropped
        assert_eq!(recs[2].id, Some(4));
    }
}
