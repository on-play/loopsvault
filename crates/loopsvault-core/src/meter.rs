//! Per-project usage and cost attribution.
//!
//! The founder's strongest idea, and the reason the proxy architecture pays for
//! itself twice. The proxy is the only component on the machine that sees the
//! project identity *and* the response body at the same time, which is what
//! makes one key per provider viable: the provider sees one key, the vault sees
//! ten projects.
//!
//! Two honest limits, carried forward from the handoff and both encoded here:
//!
//! - **Streaming needs a flag.** With SSE the usage arrives in the final chunk,
//!   and OpenAI only sends it when the request asked for it. See
//!   [`ensure_stream_usage`], which the transport calls on the way out.
//! - **Exact for LLM APIs, approximate for GPU APIs.** OpenRouter, OpenAI and
//!   Anthropic report tokens in the response body. fal.ai and Replicate bill on
//!   compute time and generally do not. The founder runs significant fal.ai
//!   traffic, so [`Attribution`] distinguishes a measured record from a counted
//!   one rather than quietly reporting zero dollars as if it were a fact.

use serde::{Deserialize, Serialize};

/// Tokens moved by one request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl Usage {
    pub fn total(&self) -> u64 {
        self.input_tokens + self.output_tokens
    }
}

/// What the meter could establish about one request.
///
/// The distinction is the point. Reporting `Counted` as zero dollars would make
/// a GPU provider look free, and the founder's fal.ai spend is real.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Attribution {
    /// The provider reported tokens. Dollars are exact if the model is priced.
    Measured {
        model: Option<String>,
        usage: Usage,
        micro_usd: Option<u64>,
    },
    /// The provider bills on something the response does not carry (compute
    /// time, image count). We know the call happened and which project made it,
    /// and we do not know the dollars.
    Counted { reason: &'static str },
}

/// Pull usage out of a JSON response body.
///
/// Handles both shapes the handoff names: `prompt_tokens`/`completion_tokens`
/// from OpenAI and OpenRouter, and `input_tokens`/`output_tokens` from
/// Anthropic. Returns `None` rather than zero when the body carries no usage,
/// so a caller cannot mistake "not reported" for "nothing used".
pub fn parse_usage(body: &[u8]) -> Option<Usage> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    usage_from_value(&v)
}

fn usage_from_value(v: &serde_json::Value) -> Option<Usage> {
    let u = v.get("usage")?;

    let input = u
        .get("prompt_tokens")
        .or_else(|| u.get("input_tokens"))
        .and_then(|x| x.as_u64());
    let output = u
        .get("completion_tokens")
        .or_else(|| u.get("output_tokens"))
        .and_then(|x| x.as_u64());

    match (input, output) {
        (None, None) => None,
        _ => Some(Usage {
            input_tokens: input.unwrap_or(0),
            output_tokens: output.unwrap_or(0),
        }),
    }
}

/// Pull usage out of a server-sent-events stream.
///
/// Usage arrives in the last chunk that carries it, so this scans every `data:`
/// line and keeps the last one that parses. Anthropic splits the count across
/// `message_start` (input) and `message_delta` (output), so the two halves are
/// merged rather than the later one overwriting the earlier.
pub fn parse_usage_sse(body: &str) -> Option<Usage> {
    let mut acc: Option<Usage> = None;

    for line in body.lines() {
        let Some(payload) = line.strip_prefix("data:") else {
            continue;
        };
        let payload = payload.trim();
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) else {
            continue;
        };

        // Anthropic nests the input count one level down on message_start.
        let found = usage_from_value(&v).or_else(|| v.get("message").and_then(usage_from_value));

        if let Some(u) = found {
            let cur = acc.get_or_insert(Usage::default());
            // Merge rather than replace: an SSE stream reports the halves in
            // different frames, and taking the last frame alone loses the
            // input count entirely.
            cur.input_tokens = cur.input_tokens.max(u.input_tokens);
            cur.output_tokens = cur.output_tokens.max(u.output_tokens);
        }
    }

    acc
}

/// Make an outbound streaming request report its usage.
///
/// OpenAI and OpenRouter only send a usage frame when the request asked for
/// one. The daemon rewrites the outbound body anyway, so it adds the flag
/// itself rather than asking every project to remember. Returns true if the
/// body was changed.
///
/// Only touches a request that is actually streaming: adding the option to a
/// non-streaming request is rejected by some providers.
pub fn ensure_stream_usage(body: &mut serde_json::Value) -> bool {
    let streaming = body.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    if !streaming {
        return false;
    }
    let Some(obj) = body.as_object_mut() else {
        return false;
    };

    let opts = obj
        .entry("stream_options")
        .or_insert_with(|| serde_json::json!({}));
    let Some(opts) = opts.as_object_mut() else {
        return false;
    };
    if opts.get("include_usage").and_then(|v| v.as_bool()) == Some(true) {
        return false;
    }
    opts.insert("include_usage".into(), serde_json::Value::Bool(true));
    true
}

/// Price per million tokens, in micro-dollars, so the arithmetic stays integral.
///
/// Deliberately a table rather than a set of environment variables: prices are
/// decided values, not deployment inputs, and the founder's own rule says a
/// value is not an environment variable until it has to be. OpenRouter
/// publishes model pricing via its API, so this table is a fallback and a unit,
/// not the source of truth.
#[derive(Clone, Debug, Default)]
pub struct PriceTable {
    entries: Vec<(String, ModelPrice)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelPrice {
    pub input_micro_usd_per_mtok: u64,
    pub output_micro_usd_per_mtok: u64,
}

impl PriceTable {
    pub fn new() -> Self {
        PriceTable::default()
    }

    pub fn set(&mut self, model: impl Into<String>, price: ModelPrice) {
        let model = model.into();
        match self.entries.iter_mut().find(|(m, _)| *m == model) {
            Some(slot) => slot.1 = price,
            None => self.entries.push((model, price)),
        }
    }

    /// Exact model id only.
    ///
    /// No prefix matching, for the same reason hosts are matched exactly: a
    /// prefix rule that quietly prices `gpt-4o-mini` as `gpt-4o` produces a
    /// number that looks authoritative and is wrong by an order of magnitude.
    /// An unpriced model reports `None`, which the report shows as unpriced.
    pub fn get(&self, model: &str) -> Option<ModelPrice> {
        self.entries
            .iter()
            .find(|(m, _)| m == model)
            .map(|(_, p)| *p)
    }

    pub fn cost_micro_usd(&self, model: &str, usage: &Usage) -> Option<u64> {
        let p = self.get(model)?;
        let input = usage.input_tokens.saturating_mul(p.input_micro_usd_per_mtok) / 1_000_000;
        let output = usage.output_tokens.saturating_mul(p.output_micro_usd_per_mtok) / 1_000_000;
        Some(input + output)
    }
}

/// Build the attribution record for one completed request.
pub fn attribute(
    body: &[u8],
    content_type: Option<&str>,
    prices: &PriceTable,
) -> Attribution {
    let is_sse = content_type
        .map(|c| c.starts_with("text/event-stream"))
        .unwrap_or(false);

    let usage = if is_sse {
        std::str::from_utf8(body).ok().and_then(parse_usage_sse)
    } else {
        parse_usage(body)
    };

    let Some(usage) = usage else {
        return Attribution::Counted {
            reason: "provider did not report token usage in the response",
        };
    };

    let model = if is_sse {
        model_from_sse(std::str::from_utf8(body).unwrap_or(""))
    } else {
        serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("model").and_then(|m| m.as_str()).map(String::from))
    };

    let micro_usd = model
        .as_deref()
        .and_then(|m| prices.cost_micro_usd(m, &usage));

    Attribution::Measured {
        model,
        usage,
        micro_usd,
    }
}

fn model_from_sse(body: &str) -> Option<String> {
    for line in body.lines() {
        let Some(payload) = line.strip_prefix("data:") else {
            continue;
        };
        let payload = payload.trim();
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) {
            if let Some(m) = v.get("model").and_then(|m| m.as_str()) {
                return Some(m.to_string());
            }
            if let Some(m) = v
                .get("message")
                .and_then(|m| m.get("model"))
                .and_then(|m| m.as_str())
            {
                return Some(m.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openai_and_openrouter_shape() {
        let body = br#"{"model":"gpt-4o","usage":{"prompt_tokens":100,"completion_tokens":50}}"#;
        assert_eq!(
            parse_usage(body),
            Some(Usage {
                input_tokens: 100,
                output_tokens: 50
            })
        );
    }

    #[test]
    fn parses_anthropic_shape() {
        let body = br#"{"model":"claude-opus-5","usage":{"input_tokens":200,"output_tokens":75}}"#;
        assert_eq!(
            parse_usage(body),
            Some(Usage {
                input_tokens: 200,
                output_tokens: 75
            })
        );
    }

    /// "Not reported" and "zero" are different facts, and conflating them makes
    /// a GPU provider look free.
    #[test]
    fn missing_usage_is_none_not_zero() {
        assert_eq!(parse_usage(br#"{"model":"x"}"#), None);
        assert_eq!(parse_usage(br#"{"usage":{}}"#), None);
        assert_eq!(parse_usage(b"not json"), None);
    }

    /// Anthropic splits the count across two frames. Taking the last frame
    /// alone loses the input tokens entirely.
    #[test]
    fn sse_merges_halves_across_frames() {
        let sse = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-5\",\"usage\":{\"input_tokens\":1200,\"output_tokens\":0}}}\n",
            "\n",
            "data: {\"type\":\"content_block_delta\"}\n",
            "\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":340}}\n",
            "\n",
            "data: [DONE]\n"
        );
        assert_eq!(
            parse_usage_sse(sse),
            Some(Usage {
                input_tokens: 1200,
                output_tokens: 340
            })
        );
        assert_eq!(model_from_sse(sse).as_deref(), Some("claude-opus-5"));
    }

    #[test]
    fn sse_openai_final_chunk() {
        let sse = concat!(
            "data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n",
            "\n",
            "data: {\"model\":\"gpt-4o\",\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\n",
            "\n",
            "data: [DONE]\n"
        );
        assert_eq!(
            parse_usage_sse(sse),
            Some(Usage {
                input_tokens: 10,
                output_tokens: 5
            })
        );
    }

    #[test]
    fn injects_stream_usage_flag_only_when_streaming() {
        let mut streaming = serde_json::json!({"model":"gpt-4o","stream":true});
        assert!(ensure_stream_usage(&mut streaming));
        assert_eq!(streaming["stream_options"]["include_usage"], true);

        // Already asked for it: nothing to do.
        assert!(!ensure_stream_usage(&mut streaming));

        // Adding the option to a non-streaming request is rejected by some
        // providers, so it must be left alone.
        let mut plain = serde_json::json!({"model":"gpt-4o"});
        assert!(!ensure_stream_usage(&mut plain));
        assert!(plain.get("stream_options").is_none());
    }

    #[test]
    fn prices_are_exact_model_ids_only() {
        let mut t = PriceTable::new();
        t.set(
            "gpt-4o",
            ModelPrice {
                input_micro_usd_per_mtok: 2_500_000,
                output_micro_usd_per_mtok: 10_000_000,
            },
        );

        let usage = Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
        };
        assert_eq!(t.cost_micro_usd("gpt-4o", &usage), Some(12_500_000));

        // A prefix rule here would price this as gpt-4o and be wrong by an
        // order of magnitude while looking authoritative.
        assert_eq!(t.cost_micro_usd("gpt-4o-mini", &usage), None);
    }

    #[test]
    fn gpu_providers_are_counted_not_measured() {
        // fal.ai bills on compute time and reports no tokens.
        let body = br#"{"images":[{"url":"https://example.test/a.png"}]}"#;
        let a = attribute(body, Some("application/json"), &PriceTable::new());
        assert!(matches!(a, Attribution::Counted { .. }), "{a:?}");
    }

    #[test]
    fn measured_without_a_price_reports_tokens_and_no_dollars() {
        let body = br#"{"model":"some-new-model","usage":{"prompt_tokens":10,"completion_tokens":5}}"#;
        match attribute(body, Some("application/json"), &PriceTable::new()) {
            Attribution::Measured {
                model,
                usage,
                micro_usd,
            } => {
                assert_eq!(model.as_deref(), Some("some-new-model"));
                assert_eq!(usage.total(), 15);
                assert_eq!(micro_usd, None, "an unpriced model must not report $0");
            }
            other => panic!("expected Measured, got {other:?}"),
        }
    }
}
