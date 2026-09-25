// Copyright 2026 Salesforce, Inc. All rights reserved.
//! `jev-client` subset (inlined; lift into the shared crate later): a single
//! abstraction for calling a System-One judge. The judge is a *classifier* — it
//! returns a typed `behaviour` choice + confidence, never generated prose — so a
//! numeric threshold is meaningful. Providers: TypeSafe Jev (noul/choice API), any
//! OpenAI-compatible chat endpoint driven as a JSON classifier, and a deterministic
//! in-policy Mock for tests and offline demos. All mutation stays in the Rust policy.
//!
//! The transport shell (Provider / JevSettings / evaluate / auth / path / status
//! handling / budget) is shared verbatim across the TypeSafe-Jev policy family; only
//! the question layer (`build_*_body`, `parse_*_signals`, `mock_signals`) is S7's.

use std::time::Duration;

use pdk::hl::*;
use serde_json::Value;

use crate::screen::Signals;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    Mock,
    TypeSafe,
    OpenAi,
    OpenRouter,
    LiteLlm,
    Cloudflare,
    Custom,
}

impl Provider {
    pub fn parse(s: &str) -> Provider {
        match s {
            "mock" => Provider::Mock,
            "openai" => Provider::OpenAi,
            "openrouter" => Provider::OpenRouter,
            "litellm" => Provider::LiteLlm,
            "cloudflare" => Provider::Cloudflare,
            "custom" => Provider::Custom,
            _ => Provider::TypeSafe,
        }
    }
    /// Whether this provider speaks the OpenAI chat-completions contract.
    fn is_openai_compat(self) -> bool {
        matches!(self, Provider::OpenAi | Provider::OpenRouter | Provider::LiteLlm | Provider::Custom)
    }
    fn default_path(self) -> &'static str {
        match self {
            Provider::OpenAi => "/v1/chat/completions",
            Provider::OpenRouter => "/api/v1/chat/completions",
            Provider::LiteLlm | Provider::Custom => "/v1/chat/completions",
            Provider::TypeSafe => "/api/alpha/decisions",
            Provider::Cloudflare => "/client/v4/accounts",
            Provider::Mock => "",
        }
    }
}

#[derive(Clone, Debug)]
pub struct JevSettings {
    pub provider: Provider,
    pub model: String,
    pub path: String,
    pub api_key: String,
    pub custom_auth_header: String,
    pub timeout_ms: u64,
    pub max_state_tokens: usize,
    pub cloudflare_account_id: Option<String>,
}

impl JevSettings {
    pub fn resolved_path(&self) -> String {
        if !self.path.is_empty() {
            self.path.clone()
        } else if self.provider == Provider::Cloudflare {
            format!(
                "/client/v4/accounts/{}/ai/run/{}",
                self.cloudflare_account_id.as_deref().unwrap_or(""),
                self.model
            )
        } else {
            self.provider.default_path().to_string()
        }
    }
}

#[derive(Clone, Debug)]
pub enum JevError {
    Timeout,
    RateLimited,
    Overloaded,
    Auth,
    Upstream(u16),
    Decode(String),
    Disabled,
}

pub struct JevResult {
    pub signals: Signals,
    pub model: String,
}

/// Approximate token budget on a state string (chars/4, conservative). Keeps the
/// head (70%) and tail (30%) with a gateway marker so an over-long summary cannot
/// push the payload past the judge. Returns (text, truncated).
pub fn budget_state(text: &str, max_tokens: usize) -> (String, bool) {
    let max_chars = max_tokens.saturating_mul(4);
    if text.chars().count() <= max_chars || max_chars == 0 {
        return (text.to_string(), false);
    }
    let head_chars = (max_chars * 7) / 10;
    let tail_chars = max_chars - head_chars;
    let chars: Vec<char> = text.chars().collect();
    let head: String = chars[..head_chars].iter().collect();
    let tail: String = chars[chars.len() - tail_chars..].iter().collect();
    (format!("{head}\n[… truncated by gateway …]\n{tail}"), true)
}

// ─── S7 question set + signal parsing ────────────────────────────────────────

const CLASSIFIER_SYSTEM: &str = "You are a traffic-abuse classifier for an API gateway. \
You are given a code-computed summary of one client's recent requests to an API, plus the API's purpose. \
The counts, rates, and flags in the summary are already computed for you — do not recount them; classify the intent. \
Reply with ONLY a JSON object, no prose, with keys: \
\"behaviour\": one of \"normal_use\",\"enumeration\",\"bulk_scraping\",\"auth_probing\",\"vulnerability_probing\" \
(normal_use = an ordinary user or integration using the API as intended; \
enumeration = walking through many identifiers to discover which records exist or are accessible; \
bulk_scraping = systematically downloading large amounts of data; \
auth_probing = repeatedly trying credentials, tokens, or access to forbidden resources; \
vulnerability_probing = sending unusual paths or parameters that look like attack attempts), \
\"confidence\": number 0..1.";

/// OpenAI-compatible chat request that drives the model as a JSON classifier over
/// the same `state` object the decisions format sends.
pub fn build_chat_body(model: &str, state: &Value) -> Value {
    let user = format!("Client request summary (JSON):\n{}", state);
    serde_json::json!({
        "model": model,
        "temperature": 0,
        "response_format": { "type": "json_object" },
        "messages": [
            { "role": "system", "content": CLASSIFIER_SYSTEM },
            { "role": "user", "content": user }
        ]
    })
}

/// Parse an OpenAI-compatible chat completion whose message content is the
/// classifier JSON `{behaviour, confidence}`.
pub fn parse_chat_signals(body: &[u8]) -> Result<Signals, JevError> {
    let v: Value = serde_json::from_slice(body).map_err(|e| JevError::Decode(e.to_string()))?;
    let content = v
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .ok_or_else(|| JevError::Decode("no choices[0].message.content".into()))?;
    let parsed: Value =
        serde_json::from_str(content).map_err(|e| JevError::Decode(format!("content not JSON: {e}")))?;
    let behaviour = parsed.get("behaviour").and_then(Value::as_str).map(|c| {
        let conf = parsed.get("confidence").and_then(Value::as_f64).unwrap_or(0.0).clamp(0.0, 1.0);
        (c.to_string(), conf)
    });
    Ok(Signals { behaviour })
}

/// TypeSafe Jev decisions request (single `behaviour` choice question). The `state`
/// is the code-computed summary from `screen.rs`; the envelope matches the shape
/// verified live against the OpenRouter Decisions API for the S1 policy.
pub fn build_typesafe_body(model: &str, state: &Value) -> Value {
    serde_json::json!({
        "model": model,
        "state": state,
        "questions": {
            "behaviour": {
                "type": "choice",
                "instructions": "Which option best describes the client's behaviour in `recent_requests`, given `api_purpose`? The rate, sequential-id, error-rate, and distinct-endpoint fields are already computed — use them; do not recount.",
                "criteria": {
                    "normal_use": "Looks like an ordinary user or integration using the API as intended.",
                    "enumeration": "Walks through many identifiers to discover which records exist or are accessible.",
                    "bulk_scraping": "Systematically downloads large amounts of data.",
                    "auth_probing": "Repeatedly tries credentials, tokens, or access to forbidden resources.",
                    "vulnerability_probing": "Sends unusual paths or parameters that look like attack attempts."
                }
            }
        }
    })
}

/// Parse a TypeSafe decisions response into our signals. Reads the `choice` +
/// `confidence` for the `behaviour` question (accepts a top-level or `answers`-nested
/// envelope).
pub fn parse_typesafe_signals(body: &[u8]) -> Result<Signals, JevError> {
    let v: Value = serde_json::from_slice(body).map_err(|e| JevError::Decode(e.to_string()))?;
    let answers = v.get("answers").unwrap_or(&v);
    let behaviour = answers.pointer("/behaviour/choice").and_then(Value::as_str).map(|c| {
        // Prefer explicit confidence; else fall back to the winning choice's
        // probability mass if the host reports `probabilities` instead.
        let conf = answers
            .pointer("/behaviour/confidence")
            .and_then(Value::as_f64)
            .or_else(|| answers.pointer(&format!("/behaviour/probabilities/{c}")).and_then(Value::as_f64))
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);
        (c.to_string(), conf)
    });
    Ok(Signals { behaviour })
}

/// Deterministic in-policy judge for tests and offline demos. It mirrors what a
/// real classifier would conclude from the code-computed flags in `state`, so a
/// demo run without any external key still shows classify-vs-normal behaviour.
/// Never enabled unless `allowMock: true`.
pub fn mock_signals(state: &Value) -> Signals {
    let seq = state.get("sequential_ids").and_then(Value::as_bool).unwrap_or(false);
    let error_rate = state.get("error_rate").and_then(Value::as_str).unwrap_or("low");
    let request_rate = state.get("request_rate").and_then(Value::as_str).unwrap_or("low");
    let distinct = state.get("distinct_endpoints").and_then(Value::as_str).unwrap_or("few");
    let high_rate = matches!(request_rate, "high" | "very high");
    let high_err = matches!(error_rate, "high");

    let behaviour = if seq && (high_err || high_rate) {
        // Walking sequential ids with rising 403s / high rate → enumeration.
        ("enumeration", 0.9)
    } else if high_err {
        // Repeated forbidden/failed access without a scan pattern → auth probing.
        ("auth_probing", 0.85)
    } else if high_rate && matches!(distinct, "many" | "some") {
        // High volume across many endpoints → bulk scraping.
        ("bulk_scraping", 0.8)
    } else {
        ("normal_use", 0.95)
    };
    Signals { behaviour: Some((behaviour.0.to_string(), behaviour.1)) }
}

/// Call the judge. `state` is the already-computed request summary.
pub async fn evaluate(
    client: &HttpClient,
    service: &Service,
    s: &JevSettings,
    state: &Value,
) -> Result<JevResult, JevError> {
    if s.provider == Provider::Mock {
        return Ok(JevResult { signals: mock_signals(state), model: "mock".to_string() });
    }
    if s.api_key.trim().is_empty() {
        return Err(JevError::Auth);
    }

    let (body, is_openai) = if s.provider.is_openai_compat() {
        (build_chat_body(&s.model, state), true)
    } else {
        (build_typesafe_body(&s.model, state), false)
    };
    let payload = serde_json::to_vec(&body).map_err(|e| JevError::Decode(e.to_string()))?;

    let auth_header = if s.provider == Provider::Custom { s.custom_auth_header.as_str() } else { "Authorization" };
    let auth_value = if auth_header.eq_ignore_ascii_case("authorization") {
        format!("Bearer {}", s.api_key)
    } else {
        s.api_key.clone()
    };

    let resp = client
        .request(service)
        .path(&s.resolved_path())
        .headers(vec![(auth_header, auth_value.as_str()), ("Content-Type", "application/json")])
        .body(&payload)
        .timeout(Duration::from_millis(s.timeout_ms))
        .post()
        .await
        .map_err(|_| JevError::Timeout)?;

    let status = resp.status_code() as u16;
    match status {
        200..=299 => {}
        401 | 403 => return Err(JevError::Auth),
        429 => return Err(JevError::RateLimited),
        529 => return Err(JevError::Overloaded),
        other => return Err(JevError::Upstream(other)),
    }

    let signals = if is_openai { parse_chat_signals(resp.body())? } else { parse_typesafe_signals(resp.body())? };
    Ok(JevResult { signals, model: s.model.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn enum_state() -> Value {
        json!({
            "api_purpose": "Customer self-service API for viewing own orders.",
            "recent_requests": ["GET orders/{id} (id=1001) 200", "GET orders/{id} (id=1002) 403"],
            "request_rate": "very high",
            "sequential_ids": true,
            "error_rate": "high",
            "distinct_endpoints": "few"
        })
    }

    #[test]
    fn budget_truncates_and_leaves_short() {
        let text = "a".repeat(1000);
        let (out, truncated) = budget_state(&text, 100);
        assert!(truncated);
        assert!(out.contains("[… truncated by gateway …]"));
        let (short, t2) = budget_state("short", 100);
        assert!(!t2);
        assert_eq!(short, "short");
    }

    #[test]
    fn parses_openai_classifier_content() {
        let body = br#"{"choices":[{"message":{"content":"{\"behaviour\":\"enumeration\",\"confidence\":0.88}"}}]}"#;
        let sig = parse_chat_signals(body).unwrap();
        let (b, c) = sig.behaviour.unwrap();
        assert_eq!(b, "enumeration");
        assert!((c - 0.88).abs() < 1e-9);
    }

    #[test]
    fn parses_typesafe_choice_confidence() {
        let body = br#"{"answers":{"behaviour":{"type":"choice","choice":"auth_probing","confidence":0.74}}}"#;
        let sig = parse_typesafe_signals(body).unwrap();
        let (b, c) = sig.behaviour.unwrap();
        assert_eq!(b, "auth_probing");
        assert!((c - 0.74).abs() < 1e-9);
    }

    #[test]
    fn parses_typesafe_choice_probabilities_fallback() {
        // Some hosts omit `confidence` and report per-choice probability mass; the
        // parser must fall back to the winning choice's probability (S1 noul-first
        // lesson: never let the confidence read silently 0).
        let body = br#"{"answers":{"behaviour":{"type":"choice","choice":"enumeration","probabilities":{"normal_use":0.1,"enumeration":0.82}}}}"#;
        let sig = parse_typesafe_signals(body).unwrap();
        let (b, c) = sig.behaviour.unwrap();
        assert_eq!(b, "enumeration");
        assert!((c - 0.82).abs() < 1e-9);
    }

    #[test]
    fn mock_classifies_enumeration_and_normal() {
        let bad = mock_signals(&enum_state());
        assert_eq!(bad.behaviour.as_ref().unwrap().0, "enumeration");
        let good = mock_signals(&json!({
            "request_rate": "low", "sequential_ids": false, "error_rate": "low", "distinct_endpoints": "few"
        }));
        assert_eq!(good.behaviour.as_ref().unwrap().0, "normal_use");
    }

    #[test]
    fn mock_classifies_auth_probing_and_scraping() {
        let probe = mock_signals(&json!({
            "request_rate": "low", "sequential_ids": false, "error_rate": "high", "distinct_endpoints": "few"
        }));
        assert_eq!(probe.behaviour.as_ref().unwrap().0, "auth_probing");
        let scrape = mock_signals(&json!({
            "request_rate": "very high", "sequential_ids": false, "error_rate": "low", "distinct_endpoints": "many"
        }));
        assert_eq!(scrape.behaviour.as_ref().unwrap().0, "bulk_scraping");
    }

    #[test]
    fn cloudflare_path_includes_account_and_model() {
        let s = JevSettings {
            provider: Provider::Cloudflare,
            model: "@cf/m".into(),
            path: String::new(),
            api_key: "k".into(),
            custom_auth_header: "Authorization".into(),
            timeout_ms: 600,
            max_state_tokens: 24000,
            cloudflare_account_id: Some("acc123".into()),
        };
        assert_eq!(s.resolved_path(), "/client/v4/accounts/acc123/ai/run/@cf/m");
    }

    #[test]
    fn typesafe_body_carries_state_and_single_question() {
        let body = build_typesafe_body("~typesafe/jev-latest", &enum_state());
        assert_eq!(body["state"]["sequential_ids"], json!(true));
        assert!(body["questions"]["behaviour"]["criteria"]["enumeration"].is_string());
        // exactly one question
        assert_eq!(body["questions"].as_object().unwrap().len(), 1);
    }
}
