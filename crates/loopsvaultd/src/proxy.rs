//! The v1 transport: explicit local endpoint.
//!
//! A project calls `http://127.0.0.1:14322/openrouter/v1/chat/completions`.
//! This module resolves the provider, asks
//! [`loopsvault_core::inject::decide`] whether the credential may go to that
//! host, writes it in, forwards, and meters the response.
//!
//! **This module makes no security decision of its own.** Every "may this go
//! there" question is answered by the core. When the opt-in MITM transport
//! lands it will be a sibling of this file calling the same `decide`, which is
//! constraint 1 from the founder's decisions. If you find yourself adding a
//! host comparison here, that is the constraint breaking.

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use loopsvault_core::{decide, Denial, InjectionRequest, Placement, ProjectToken};

use crate::config::upstream_host;
use crate::state::{now_unix, AppState, AuditRecord, Outcome};

/// The header a caller uses to prove which project it is.
///
/// A dedicated header rather than `Authorization`, because the caller's
/// `Authorization` slot is where the placeholder credential sits and where the
/// real one is about to be written.
pub const PROJECT_TOKEN_HEADER: &str = "x-loopsvault-project-token";

/// Headers that must never be forwarded upstream.
///
/// The project token is ours and means nothing to the provider. Hop-by-hop
/// headers belong to the connection we are terminating, not to the request.
const STRIPPED: &[&str] = &[
    PROJECT_TOKEN_HEADER,
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
];

pub async fn handle(
    State(state): State<AppState>,
    Path((provider, rest)): Path<(String, String)>,
    req: Request,
) -> Response {
    match proxy(state, provider, rest, req).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

struct ProxyError {
    status: StatusCode,
    message: String,
    /// What the caller should do instead. A refusal that names no next step is
    /// what makes an agent write workaround scripts, which is the behaviour
    /// this whole project exists to end.
    next_step: String,
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": {
                "type": "loopsvault_denied",
                "message": self.message,
                "next_step": self.next_step,
            }
        });
        (self.status, axum::Json(body)).into_response()
    }
}

fn deny(status: StatusCode, message: impl Into<String>, next_step: impl Into<String>) -> ProxyError {
    ProxyError {
        status,
        message: message.into(),
        next_step: next_step.into(),
    }
}

async fn proxy(
    state: AppState,
    provider: String,
    rest: String,
    req: Request,
) -> Result<Response, ProxyError> {
    let handler_started = std::time::Instant::now();
    // 1. Who is asking? Established by the token, never by a name the caller
    //    supplied. This is the property per-project attribution and spend caps
    //    depend on.
    let raw_token = req
        .headers()
        .get(PROJECT_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            deny(
                StatusCode::UNAUTHORIZED,
                format!("missing {PROJECT_TOKEN_HEADER}"),
                "Run `loopsvault project token <project>` and send the result in that header.",
            )
        })?;

    let token = ProjectToken::parse(raw_token).map_err(|_| {
        deny(
            StatusCode::UNAUTHORIZED,
            "project token is malformed",
            "Run `loopsvault project token <project>` to get a valid one.",
        )
    })?;

    let project = state.projects.resolve(&token).ok_or_else(|| {
        deny(
            StatusCode::UNAUTHORIZED,
            "project token is not registered",
            "Run `loopsvault project add <project>` to register this project.",
        )
    })?;

    // 2. Which upstream, and which credential?
    let pcfg = state.config.providers.get(&provider).ok_or_else(|| {
        deny(
            StatusCode::NOT_FOUND,
            format!("no provider named {provider}"),
            format!(
                "Known providers: {}. Run `loopsvault ls` to see the catalog.",
                state
                    .config
                    .providers
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    })?;

    // Startup already validated this, so a failure here means the config
    // changed under a running daemon.
    let target = upstream_host(&pcfg.upstream).map_err(|e| {
        deny(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("provider {provider} has an unusable upstream: {e}"),
            "Fix the upstream in the daemon config and restart.",
        )
    })?;

    // 3. May this credential go to that host, for this project? The core
    //    decides. Nothing below re-checks it, and nothing above pre-empts it.
    let verdict = decide(
        &state.catalog,
        &InjectionRequest {
            project: project.as_str(),
            target: &target,
            credential: &pcfg.credential,
        },
    );

    let injection = match verdict {
        Ok(i) => i,
        Err(d) => {
            let alarm = d.is_alarm();
            state.audit.lock().unwrap().push(AuditRecord {
                at_unix: now_unix(),
                project: project.to_string(),
                credential: pcfg.credential.clone(),
                target: target.to_string(),
                outcome: Outcome::Denied,
                alarm,
                attribution: None,
                upstream_ms: None,
                total_ms: Some(handler_started.elapsed().as_millis() as u64),
                upstream_status: None,
            });
            return Err(denial_to_error(&d));
        }
    };

    // 4. Build the upstream request.
    let method = req.method().clone();
    let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
    let url = format!("{}/{}{}", pcfg.upstream.trim_end_matches('/'), rest, query);

    let mut headers = HeaderMap::new();
    for (name, value) in req.headers() {
        if STRIPPED.contains(&name.as_str()) {
            continue;
        }
        // The caller's placeholder credential is dropped rather than
        // forwarded. Whatever it typed there is not a credential, and passing
        // it on would leak whatever it happened to be.
        if placement_targets_header(injection.placement, name.as_str()) {
            continue;
        }
        headers.insert(name.clone(), value.clone());
    }

    let body_bytes = axum::body::to_bytes(req.into_body(), 32 * 1024 * 1024)
        .await
        .map_err(|e| {
            deny(
                StatusCode::BAD_REQUEST,
                format!("could not read request body: {e}"),
                "Send a smaller body, or stream it in chunks under 32MB.",
            )
        })?;

    // Make a streaming request report its usage, so the meter is not blind on
    // the requests that cost the most.
    let body_bytes = match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
        Ok(mut v) => {
            if loopsvault_core::meter::ensure_stream_usage(&mut v) {
                headers.remove("content-length");
                serde_json::to_vec(&v)
                    .map(axum::body::Bytes::from)
                    .unwrap_or(body_bytes)
            } else {
                body_bytes
            }
        }
        Err(_) => body_bytes,
    };

    let mut url_with_key = url;

    // 5. Write the real credential in. This is the only place a value is read,
    //    and it is read at the moment it goes on the wire.
    {
        let mut store = state.store.lock().unwrap();
        store.reload_if_changed();
        let value = store.get(&injection.entry.name).ok_or_else(|| {
            deny(
                StatusCode::FAILED_DEPENDENCY,
                format!(
                    "{} is in the catalog but has no value in the store",
                    injection.entry.name
                ),
                format!(
                    "Run `loopsvault set {}` to store it. The catalog describes what exists; the store holds the value.",
                    injection.entry.name
                ),
            )
        })?;

        match injection.placement {
            Placement::Header { header, scheme } => {
                let rendered = match scheme {
                    Some(s) => format!("{s} {}", value.expose()),
                    None => value.expose().to_string(),
                };
                let name = HeaderName::try_from(header.as_str()).map_err(|_| {
                    deny(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("{header} is not a valid header name"),
                        "Fix the placement in the catalog entry.",
                    )
                })?;
                let mut hv = HeaderValue::from_str(&rendered).map_err(|_| {
                    deny(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "stored credential is not valid in a header",
                        "Re-store the value; it may have a stray newline.",
                    )
                })?;
                // Marks the header so it is redacted if anything ever formats
                // this map.
                hv.set_sensitive(true);
                headers.insert(name, hv);
            }
            Placement::QueryParam { name } => {
                let sep = if url_with_key.contains('?') { '&' } else { '?' };
                url_with_key =
                    format!("{url_with_key}{sep}{name}={}", urlencode(value.expose()));
            }
        }
    }

    // 6. Forward. Timed on its own so the provider's latency can be subtracted
    //    from the total, giving this daemon's overhead directly.
    let upstream_started = std::time::Instant::now();
    let upstream_resp = state
        .http
        .request(method, &url_with_key)
        .headers(headers)
        .body(body_bytes.to_vec())
        .send()
        .await;

    let upstream_resp = match upstream_resp {
        Ok(r) => r,
        Err(e) => {
            state.audit.lock().unwrap().push(AuditRecord {
                at_unix: now_unix(),
                project: project.to_string(),
                credential: injection.entry.name.clone(),
                target: target.to_string(),
                outcome: Outcome::UpstreamError,
                alarm: false,
                attribution: None,
                upstream_ms: Some(upstream_started.elapsed().as_millis() as u64),
                total_ms: Some(handler_started.elapsed().as_millis() as u64),
                upstream_status: None,
            });
            return Err(deny(
                StatusCode::BAD_GATEWAY,
                format!("upstream request failed: {e}"),
                "Check network access to the provider, then retry.",
            ));
        }
    };

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let content_type = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let resp_body = upstream_resp.bytes().await.map_err(|e| {
        deny(
            StatusCode::BAD_GATEWAY,
            format!("could not read upstream response: {e}"),
            "Retry the request.",
        )
    })?;

    // The upstream leg ends once its body is fully read, since the daemon
    // buffers rather than relays and the caller waits for all of it either way.
    let upstream_ms = upstream_started.elapsed().as_millis() as u64;

    // 7. Meter it. The proxy is the only component that sees the project
    //    identity and the response body at the same time, which is what makes
    //    one key per provider viable.
    let attribution =
        loopsvault_core::attribute(&resp_body, content_type.as_deref(), &state.prices);

    state.audit.lock().unwrap().push(AuditRecord {
        at_unix: now_unix(),
        project: project.to_string(),
        credential: injection.entry.name.clone(),
        target: target.to_string(),
        outcome: Outcome::Injected,
        alarm: false,
        attribution: Some(attribution),
        upstream_ms: Some(upstream_ms),
        total_ms: Some(handler_started.elapsed().as_millis() as u64),
        upstream_status: Some(status.as_u16()),
    });

    let mut out = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        if STRIPPED.contains(&name.as_str()) {
            continue;
        }
        out = out.header(name, value);
    }
    Ok(out
        .body(Body::from(resp_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
}

fn placement_targets_header(placement: &Placement, name: &str) -> bool {
    match placement {
        Placement::Header { header, .. } => header.eq_ignore_ascii_case(name),
        Placement::QueryParam { .. } => false,
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Turn a core denial into an HTTP refusal that names the next step.
fn denial_to_error(d: &Denial) -> ProxyError {
    match d {
        Denial::Honeytoken { name, .. } => deny(
            StatusCode::FORBIDDEN,
            format!("{name} is a honeytoken and has been reported"),
            "Nothing legitimate references this credential. If you reached it from a real \
             config, tell the founder immediately rather than retrying.",
        ),
        Denial::HostNotPermitted { name, target } => deny(
            StatusCode::FORBIDDEN,
            format!("{name} may not be sent to {target}"),
            format!("Run `loopsvault describe {name}` to see the hosts it is allowed to reach."),
        ),
        Denial::ProjectNotPermitted { project, name } => deny(
            StatusCode::FORBIDDEN,
            format!("project {project} is not permitted to use {name}"),
            format!("Run `loopsvault grant {name} {project}` if this project should have it."),
        ),
        Denial::NoSuchEntry { name } => deny(
            StatusCode::NOT_FOUND,
            format!("no catalog entry named {name}"),
            "Run `loopsvault ls` to see what exists.",
        ),
        Denial::NotACredential { name, classification } => deny(
            StatusCode::BAD_REQUEST,
            format!("{name} is classified {classification:?}, not a credential"),
            "A constant belongs in source, and a public value is already in your browser \
             bundle. Neither is brokered here.",
        ),
        other => deny(
            StatusCode::FORBIDDEN,
            other.to_string(),
            "Run `loopsvault describe <name>` and fix the catalog entry.",
        ),
    }
}
