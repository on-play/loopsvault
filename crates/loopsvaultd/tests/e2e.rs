//! End-to-end proof of the one claim this project is built on:
//!
//! **the agent gets what it needs, and the credential is never on the agent's
//! side of the boundary.**
//!
//! Everything else is detail. So this test runs the real router, the real
//! encrypted store, and a real upstream server, and checks both halves: that
//! the upstream received the genuine credential, and that the caller never sent
//! it, never received it, and cannot obtain it from any route the daemon
//! serves.
//!
//! Both servers are started and shut down inside the test process. Nothing is
//! left running.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::State as AxState;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::Router;
use loopsvault_core::catalog::{CatalogEntry, Classification, Placement};
use loopsvault_core::secret::SecretValue;
use loopsvault_core::unwrap::FileUnwrapper;
use loopsvault_core::{Catalog, ProjectId, ProjectRegistry};
use loopsvaultd::config::{Config, ProviderConfig};
use loopsvaultd::state::AppState;
use loopsvaultd::store::CredentialStore;

/// The value that must reach the upstream and must never reach the caller.
const REAL_CREDENTIAL: &str = "FAKE-sk-or-v1-thisisthesecretvalue00000";

/// What the caller puts in the slot. It is not a credential and must be dropped
/// rather than forwarded.
const CALLER_PLACEHOLDER: &str = "Bearer LOOPSVAULT_PLACEHOLDER";

#[derive(Default)]
struct Seen {
    authorization: Option<String>,
    body: Option<String>,
}

/// A stand-in for openrouter.ai. Records what it was sent.
async fn fake_upstream(
    AxState(seen): AxState<Arc<Mutex<Seen>>>,
    headers: HeaderMap,
    body: String,
) -> axum::Json<serde_json::Value> {
    {
        let mut s = seen.lock().unwrap();
        s.authorization = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        s.body = Some(body);
    }
    axum::Json(serde_json::json!({
        "model": "test-model",
        "choices": [{"message": {"content": "hello"}}],
        "usage": {"prompt_tokens": 120, "completion_tokens": 34}
    }))
}

struct Harness {
    dir: std::path::PathBuf,
}

impl Harness {
    fn new(label: &str) -> Harness {
        let dir = std::env::temp_dir().join(format!("lv-e2e-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Harness { dir }
    }

    fn master_key(&self) -> std::path::PathBuf {
        let p = self.dir.join("master.key");
        std::fs::write(&p, b"FAKE-master-key-for-e2e").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        p
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn entry_for(upstream_host: &str, projects: Vec<String>) -> CatalogEntry {
    CatalogEntry {
        name: "OPENROUTER_API_KEY".into(),
        aliases: vec!["OPENROUTER_KEY".into()],
        provider: "openrouter".into(),
        comment: "routes all LLM traffic".into(),
        expiry: None,
        projects,
        shape: None,
        classification: Classification::Secret,
        hosts: vec![upstream_host.to_string()],
        placement: Some(Placement::Header {
            header: "authorization".into(),
            scheme: Some("Bearer".into()),
        }),
        honeytoken: false,
    }
}

async fn spawn(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

/// Build a daemon whose only provider points at `upstream`.
fn build_state(
    h: &Harness,
    upstream: &str,
    upstream_host: &str,
    projects: Vec<String>,
) -> (AppState, String) {
    let store_path = h.dir.join("vault.store");
    let key_path = h.master_key();

    {
        let mut store = CredentialStore::open(&store_path, &FileUnwrapper::new(&key_path)).unwrap();
        store
            .put("OPENROUTER_API_KEY", SecretValue::new(REAL_CREDENTIAL))
            .unwrap();
    }

    let mut registry = ProjectRegistry::default();
    let token = registry
        .issue(ProjectId::parse("pitchplus_fast").unwrap())
        .unwrap();
    let token_str = token.expose().to_string();

    let mut providers = BTreeMap::new();
    providers.insert(
        "openrouter".to_string(),
        ProviderConfig {
            upstream: upstream.to_string(),
            credential: "OPENROUTER_API_KEY".to_string(),
        },
    );

    let cfg = Config {
        store_path,
        master_key_path: key_path,
        catalog: Catalog {
            entries: vec![entry_for(upstream_host, projects)],
        },
        projects: registry,
        providers,
        prices: BTreeMap::new(),
    };
    cfg.validate().expect("config should validate");

    (AppState::new(cfg).unwrap(), token_str)
}

#[tokio::test]
async fn the_upstream_gets_the_credential_and_the_caller_never_does() {
    let h = Harness::new("happy");

    let seen = Arc::new(Mutex::new(Seen::default()));
    let upstream_addr = spawn(
        Router::new()
            .route("/v1/chat/completions", post(fake_upstream))
            .with_state(seen.clone()),
    )
    .await;

    let (state, token) = build_state(
        &h,
        &format!("http://{upstream_addr}"),
        "127.0.0.1",
        vec!["pitchplus_fast".into()],
    );
    let daemon_addr = spawn(loopsvaultd::routes::router(state)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{daemon_addr}/openrouter/v1/chat/completions"))
        .header("x-loopsvault-project-token", &token)
        // The caller fills the credential slot with a placeholder, exactly as
        // an agent would. It is not a credential and must not be forwarded.
        .header("authorization", CALLER_PLACEHOLDER)
        .json(&serde_json::json!({"model": "test-model", "messages": []}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();

    // The agent got what it needed.
    assert!(text.contains("hello"), "caller should get the real answer: {text}");

    // The credential never came back to the caller.
    assert!(
        !text.contains(REAL_CREDENTIAL),
        "the response body must not contain the credential"
    );

    // The upstream got the real thing, written by the daemon.
    let s = seen.lock().unwrap();
    assert_eq!(
        s.authorization.as_deref(),
        Some(format!("Bearer {REAL_CREDENTIAL}").as_str()),
        "upstream should have received the real credential"
    );
    // And specifically NOT the caller's placeholder.
    assert_ne!(s.authorization.as_deref(), Some(CALLER_PLACEHOLDER));
}

/// The catalog is the piece that stops an agent flailing. It must be genuinely
/// useful and must still carry no value.
#[tokio::test]
async fn the_catalog_describes_everything_except_the_value() {
    let h = Harness::new("catalog");
    let (state, _token) = build_state(
        &h,
        "http://127.0.0.1:9",
        "127.0.0.1",
        vec!["pitchplus_fast".into()],
    );
    let addr = spawn(loopsvaultd::routes::router(state)).await;

    let body = reqwest::get(format!("http://{addr}/catalog"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    // Useful.
    assert!(body.contains("OPENROUTER_API_KEY"));
    assert!(body.contains("routes all LLM traffic"));
    assert!(body.contains("\"stored\":true"), "should say a value exists: {body}");
    assert!(body.contains("\"len\":"), "shape should be reported");

    // Value-free.
    assert!(!body.contains(REAL_CREDENTIAL), "catalog leaked the value");
    assert!(!body.contains("thisisthesecret"), "catalog leaked part of the value");

    // Describe one entry, including by alias.
    let one = reqwest::get(format!("http://{addr}/catalog/OPENROUTER_KEY"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(one.contains("OPENROUTER_API_KEY"), "alias should resolve: {one}");
    assert!(!one.contains(REAL_CREDENTIAL));
}

/// No route serves a value. This is the claim, stated as a test, so that adding
/// a convenience endpoint that returns one fails here.
#[tokio::test]
async fn no_route_will_hand_over_a_value() {
    let h = Harness::new("noleak");
    let (state, token) = build_state(
        &h,
        "http://127.0.0.1:9",
        "127.0.0.1",
        vec!["pitchplus_fast".into()],
    );
    let addr = spawn(loopsvaultd::routes::router(state)).await;

    let client = reqwest::Client::new();
    for path in [
        "/catalog",
        "/catalog/OPENROUTER_API_KEY",
        "/usage",
        "/audit",
        "/healthz",
    ] {
        let body = client
            .get(format!("http://{addr}{path}"))
            .header("x-loopsvault-project-token", &token)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            !body.contains(REAL_CREDENTIAL),
            "{path} leaked the credential"
        );
    }
}

#[tokio::test]
async fn a_request_without_a_valid_project_token_is_refused() {
    let h = Harness::new("auth");
    let (state, _token) = build_state(
        &h,
        "http://127.0.0.1:9",
        "127.0.0.1",
        vec!["pitchplus_fast".into()],
    );
    let addr = spawn(loopsvaultd::routes::router(state)).await;
    let client = reqwest::Client::new();

    // No token at all.
    let r = client
        .post(format!("http://{addr}/openrouter/v1/chat/completions"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let body = r.text().await.unwrap();
    // A refusal that names no next step is what makes agents write workaround
    // scripts.
    assert!(body.contains("next_step"), "denial must name a next step: {body}");

    // A well-formed token that was never issued.
    let stranger = loopsvault_core::ProjectToken::generate().unwrap();
    let r = client
        .post(format!("http://{addr}/openrouter/v1/chat/completions"))
        .header("x-loopsvault-project-token", stranger.expose())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // A project name is not a token.
    let r = client
        .post(format!("http://{addr}/openrouter/v1/chat/completions"))
        .header("x-loopsvault-project-token", "pitchplus_fast")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

/// A project outside the entry's scope is refused, and no request reaches the
/// upstream. This is the alarm path, so the upstream must record nothing.
#[tokio::test]
async fn a_project_outside_scope_is_refused_before_the_credential_is_read() {
    let h = Harness::new("scope");

    let seen = Arc::new(Mutex::new(Seen::default()));
    let upstream_addr = spawn(
        Router::new()
            .route("/v1/chat/completions", post(fake_upstream))
            .with_state(seen.clone()),
    )
    .await;

    // The catalog permits a DIFFERENT project than the one holding the token.
    let (state, token) = build_state(
        &h,
        &format!("http://{upstream_addr}"),
        "127.0.0.1",
        vec!["some_other_project".into()],
    );
    let addr = spawn(loopsvaultd::routes::router(state)).await;

    let r = reqwest::Client::new()
        .post(format!("http://{addr}/openrouter/v1/chat/completions"))
        .header("x-loopsvault-project-token", &token)
        .send()
        .await
        .unwrap();

    assert_eq!(r.status(), 403);
    let body = r.text().await.unwrap();
    assert!(body.contains("not permitted"), "{body}");
    assert!(!body.contains(REAL_CREDENTIAL));

    // Nothing was forwarded, so the credential was never read.
    assert!(
        seen.lock().unwrap().authorization.is_none(),
        "no request should have reached the upstream"
    );

    // And the refusal was recorded as an alarm.
    let audit = reqwest::get(format!("http://{addr}/audit"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(audit.contains("\"alarms\":1"), "should be an alarm: {audit}");
}

/// A provider pointing outside its credential's allowlist must not start at
/// all. Catching it here turns a puzzling per-request 403 into a startup error.
#[test]
fn a_provider_pointing_at_the_wrong_host_refuses_to_start() {
    let mut providers = BTreeMap::new();
    providers.insert(
        "openrouter".to_string(),
        ProviderConfig {
            // The classic attack: a host the agent controls, spelled to look
            // like the real one.
            upstream: "https://openrouter.ai.evil.com".to_string(),
            credential: "OPENROUTER_API_KEY".to_string(),
        },
    );

    let cfg = Config {
        store_path: "/tmp/unused.store".into(),
        master_key_path: "/tmp/unused.key".into(),
        catalog: Catalog {
            entries: vec![entry_for("openrouter.ai", vec!["pitchplus_fast".into()])],
        },
        projects: ProjectRegistry::default(),
        providers,
        prices: BTreeMap::new(),
    };

    let err = cfg.validate().unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("openrouter.ai.evil.com"), "{text}");
    assert!(text.contains("Refusing to start"), "{text}");
}

/// Per-project attribution, measured through the real path.
#[tokio::test]
async fn usage_is_attributed_to_the_project_that_spent_it() {
    let h = Harness::new("usage");

    let seen = Arc::new(Mutex::new(Seen::default()));
    let upstream_addr = spawn(
        Router::new()
            .route("/v1/chat/completions", post(fake_upstream))
            .with_state(seen.clone()),
    )
    .await;

    let (state, token) = build_state(
        &h,
        &format!("http://{upstream_addr}"),
        "127.0.0.1",
        vec!["pitchplus_fast".into()],
    );
    let addr = spawn(loopsvaultd::routes::router(state)).await;

    let client = reqwest::Client::new();
    for _ in 0..3 {
        client
            .post(format!("http://{addr}/openrouter/v1/chat/completions"))
            .header("x-loopsvault-project-token", &token)
            .json(&serde_json::json!({"model": "test-model", "messages": []}))
            .send()
            .await
            .unwrap();
    }

    let usage: serde_json::Value = client
        .get(format!("http://{addr}/usage"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let p = &usage["projects"]["pitchplus_fast"];
    assert_eq!(p["calls"], 3);
    assert_eq!(p["input_tokens"], 360, "3 x 120");
    assert_eq!(p["output_tokens"], 102, "3 x 34");
    // No price configured for test-model, so the dollars are honestly unknown
    // rather than reported as zero.
    assert_eq!(p["micro_usd"], 0);
    assert_eq!(p["unpriced_calls"], 3);
}

/// The daemon adds the flag that makes a streaming request report its usage,
/// so the meter is not blind on the requests that cost the most.
#[tokio::test]
async fn streaming_requests_are_rewritten_to_report_usage() {
    let h = Harness::new("stream");

    let seen = Arc::new(Mutex::new(Seen::default()));
    let upstream_addr = spawn(
        Router::new()
            .route("/v1/chat/completions", post(fake_upstream))
            .with_state(seen.clone()),
    )
    .await;

    let (state, token) = build_state(
        &h,
        &format!("http://{upstream_addr}"),
        "127.0.0.1",
        vec!["pitchplus_fast".into()],
    );
    let addr = spawn(loopsvaultd::routes::router(state)).await;

    reqwest::Client::new()
        .post(format!("http://{addr}/openrouter/v1/chat/completions"))
        .header("x-loopsvault-project-token", &token)
        .json(&serde_json::json!({"model": "test-model", "stream": true, "messages": []}))
        .send()
        .await
        .unwrap();

    let body = seen.lock().unwrap().body.clone().unwrap_or_default();
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        parsed["stream_options"]["include_usage"], true,
        "daemon should have added the usage flag: {body}"
    );
}

/// Written in response to a concrete adoption report from 42flows.com, which
/// runs OpenRouter through `ofetch` against a base of `https://openrouter.ai/api/v1`
/// and reads nested usage fields for cached-read cost accounting.
///
/// Three things had to be true for that project and none were covered:
///
/// 1. The proxy is **path-agnostic**. It forwards `{upstream}/{rest}`, so a base
///    of `.../openrouter/api/v1` reaches `/api/v1/chat/completions` AND
///    `/api/v1/models`. That second one matters: their pricing sync calls
///    `GET /models`, and a proxy that only understood chat completions would
///    silently break it.
/// 2. `HTTP-Referer` and `X-Title` survive. OpenRouter uses them for app
///    attribution, so dropping them would silently change their dashboard.
/// 3. The response body is passed through **byte for byte**. They read
///    `prompt_tokens_details.cached_tokens`, which the meter does not know
///    about. Metering must observe, never normalise, or it breaks a downstream
///    ledger it has never heard of.
#[tokio::test]
async fn paths_headers_and_response_bytes_pass_through_untouched() {
    let h = Harness::new("passthrough");

    let seen: Arc<Mutex<(Option<String>, Option<String>, Option<String>)>> =
        Arc::new(Mutex::new((None, None, None)));

    // A response with a nested usage field the meter does not model.
    const UPSTREAM_BODY: &str = r#"{"model":"test-model","usage":{"prompt_tokens":100,"completion_tokens":20,"prompt_tokens_details":{"cached_tokens":64}},"data":[{"id":"m"}]}"#;

    let recorder = seen.clone();
    let upstream = Router::new().route(
        "/api/v1/models",
        axum::routing::get(move |headers: HeaderMap| {
            let recorder = recorder.clone();
            async move {
                let mut s = recorder.lock().unwrap();
                s.0 = Some("/api/v1/models".to_string());
                s.1 = headers.get("http-referer").and_then(|v| v.to_str().ok()).map(String::from);
                s.2 = headers.get("x-title").and_then(|v| v.to_str().ok()).map(String::from);
                axum::response::Response::builder()
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(UPSTREAM_BODY))
                    .unwrap()
            }
        }),
    );
    let upstream_addr = spawn(upstream).await;

    let (state, token) = build_state(
        &h,
        &format!("http://{upstream_addr}"),
        "127.0.0.1",
        vec!["pitchplus_fast".into()],
    );
    let addr = spawn(loopsvaultd::routes::router(state)).await;

    let resp = reqwest::Client::new()
        // The shape a project actually uses: base URL carries /api/v1.
        .get(format!("http://{addr}/openrouter/api/v1/models"))
        .header("x-loopsvault-project-token", &token)
        .header("http-referer", "https://42flows.com")
        .header("x-title", "42flows")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let got = resp.text().await.unwrap();

    let s = seen.lock().unwrap();
    assert_eq!(s.0.as_deref(), Some("/api/v1/models"), "multi-segment path must survive");
    assert_eq!(s.1.as_deref(), Some("https://42flows.com"), "HTTP-Referer must survive");
    assert_eq!(s.2.as_deref(), Some("42flows"), "X-Title must survive");

    assert_eq!(got, UPSTREAM_BODY, "response must be byte-identical, not normalised");
    assert!(
        got.contains("\"cached_tokens\":64"),
        "a nested field the meter does not model must still reach the caller"
    );
}

/// Settles the question 42flows.com asked directly: when a request arrives
/// carrying BOTH a project token AND its own `Authorization` header, what does
/// the upstream actually receive?
///
/// Their three call sites all set `Authorization: Bearer ${config.openrouterApiKey}`
/// themselves. Two failure shapes were plausible from reading the strip list:
/// the caller's header is forwarded and the injected credential never applies,
/// or both are emitted and the provider 401s on a duplicate.
///
/// Neither happens. The header named by the placement is dropped from the
/// inbound request before anything is forwarded, then written fresh. So exactly
/// one arrives and it is always the real credential.
///
/// The `Bearer undefined` case is the same path and matters for adoption: once
/// a project blanks its own key, that is the literal string its client will
/// send, and it must not reach the provider.
#[tokio::test]
async fn a_callers_own_authorization_is_replaced_not_duplicated() {
    for caller_sends in [
        "Bearer sk-or-v1-the-callers-own-stale-key",
        "Bearer undefined",
        "Bearer ",
        "Basic Zm9vOmJhcg==",
    ] {
        let h = Harness::new("dupeauth");

        let count: Arc<Mutex<(usize, Option<String>)>> = Arc::new(Mutex::new((0, None)));
        let rec = count.clone();
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(move |headers: HeaderMap| {
                let rec = rec.clone();
                async move {
                    let mut s = rec.lock().unwrap();
                    // get_all counts every value under the name, so a duplicate
                    // would show up here rather than being silently collapsed.
                    s.0 = headers.get_all("authorization").iter().count();
                    s.1 = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(String::from);
                    axum::Json(serde_json::json!({"model":"m","usage":{"prompt_tokens":1,"completion_tokens":1}}))
                }
            }),
        );
        let upstream_addr = spawn(upstream).await;

        let (state, token) = build_state(
            &h,
            &format!("http://{upstream_addr}"),
            "127.0.0.1",
            vec!["pitchplus_fast".into()],
        );
        let addr = spawn(loopsvaultd::routes::router(state)).await;

        reqwest::Client::new()
            .post(format!("http://{addr}/openrouter/v1/chat/completions"))
            .header("x-loopsvault-project-token", &token)
            .header("authorization", caller_sends)
            .json(&serde_json::json!({"model":"m","messages":[]}))
            .send()
            .await
            .unwrap();

        let s = count.lock().unwrap();
        assert_eq!(
            s.0, 1,
            "exactly one Authorization must reach upstream, caller sent {caller_sends:?}"
        );
        assert_eq!(
            s.1.as_deref(),
            Some(format!("Bearer {REAL_CREDENTIAL}").as_str()),
            "the injected credential must win, caller sent {caller_sends:?}"
        );
        assert!(
            !s.1.as_deref().unwrap_or("").contains("undefined"),
            "a blanked client key must never reach the provider"
        );
    }
}

/// An honest limit, asserted rather than left for someone to discover in
/// production.
///
/// The daemon collects the whole upstream response before returning any of it.
/// For the non-streaming JSON that v1's first adopter sends, that is harmless.
/// For a streaming response it is not: the caller gets every chunk at once, at
/// the end, so token-by-token delivery to a user is destroyed.
///
/// This is worth a test precisely because the code around it implies otherwise.
/// The meter carries `parse_usage_sse` and `ensure_stream_usage`, which together
/// read as "streaming is supported". It is supported in the sense that the
/// request succeeds and the usage is metered correctly. It is not supported in
/// the sense anyone building a chat UI means.
///
/// If this test ever fails, someone has made the proxy relay incrementally,
/// which is the fix. Delete the assertion then, and the README limit with it.
#[tokio::test]
async fn streaming_responses_are_buffered_not_relayed() {
    use futures_util::StreamExt;
    use std::time::{Duration, Instant};

    const GAP_MS: u64 = 400;
    let h = Harness::new("buffering");

    let upstream = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            // Chunk one is ready immediately. Chunk two arrives GAP_MS later.
            // A relaying proxy delivers chunk one straight away; a buffering one
            // delivers nothing until chunk two has landed.
            let s = futures_util::stream::unfold(0usize, |i| async move {
                if i >= 2 {
                    return None;
                }
                if i == 1 {
                    tokio::time::sleep(Duration::from_millis(GAP_MS)).await;
                }
                let frame = if i == 0 {
                    "data: {\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n".to_string()
                } else {
                    "data: {\"model\":\"m\",\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n".to_string()
                };
                Some((
                    Ok::<_, std::io::Error>(axum::body::Bytes::from(frame)),
                    i + 1,
                ))
            });
            axum::response::Response::builder()
                .header("content-type", "text/event-stream")
                .body(axum::body::Body::from_stream(s))
                .unwrap()
        }),
    );
    let upstream_addr = spawn(upstream).await;

    let (state, token) = build_state(
        &h,
        &format!("http://{upstream_addr}"),
        "127.0.0.1",
        vec!["pitchplus_fast".into()],
    );
    let addr = spawn(loopsvaultd::routes::router(state)).await;

    let started = Instant::now();
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/openrouter/v1/chat/completions"))
        .header("x-loopsvault-project-token", &token)
        .json(&serde_json::json!({"model":"m","stream":true,"messages":[]}))
        .send()
        .await
        .unwrap();

    let mut stream = resp.bytes_stream();
    let _first = stream.next().await.expect("a first chunk").unwrap();
    let ttfb = started.elapsed();

    // The documented limit. Time to first byte should be ~0 for a relaying
    // proxy and >= the gap for a buffering one.
    assert!(
        ttfb >= Duration::from_millis(GAP_MS),
        "the proxy appears to relay incrementally now (ttfb {ttfb:?}). That is an \
         improvement, not a failure: delete this assertion and the streaming limit \
         in the README."
    );

    // And the request still SUCCEEDS and is metered. Buffered is not broken.
    let rest: Vec<_> = stream.collect().await;
    let mut whole = String::from_utf8_lossy(&_first).to_string();
    for c in rest {
        whole.push_str(&String::from_utf8_lossy(&c.unwrap()));
    }
    assert!(whole.contains("[DONE]"), "the full stream must still arrive");

    let usage: serde_json::Value = reqwest::get(format!("http://{addr}/usage"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        usage["projects"]["pitchplus_fast"]["input_tokens"], 5,
        "usage must still be parsed out of the SSE frames: {usage}"
    );
}

/// The daemon must notice a credential stored while it is running.
///
/// It used to load the store once at startup and never look again, so
/// `loopsvault set` against a running daemon had no effect and nothing said so.
/// That cost most of an adoption session on 2026-08-19: the CLI reported the
/// credential stored, the daemon went on reporting it missing, and both were
/// telling the truth about different snapshots. The visible symptom pointed at
/// the wrong cause entirely.
#[tokio::test]
async fn a_credential_stored_while_running_is_picked_up_without_a_restart() {
    let h = Harness::new("reload");
    let (state, _token) = build_state(
        &h,
        "http://127.0.0.1:9",
        "127.0.0.1",
        vec!["pitchplus_fast".into()],
    );
    let addr = spawn(loopsvaultd::routes::router(state)).await;

    let stored = |body: &str| -> bool {
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        v["entries"][0]["stored"].as_bool().unwrap_or(false)
    };

    // build_state stores OPENROUTER_API_KEY, so start by removing it to get a
    // daemon whose loaded snapshot genuinely lacks the value.
    {
        let mut s = CredentialStore::open(
            h.dir.join("vault.store"),
            &FileUnwrapper::new(h.dir.join("master.key")),
        )
        .unwrap();
        s.remove("OPENROUTER_API_KEY").unwrap();
    }
    // Filesystem mtime granularity is coarse enough that two writes in the same
    // instant can compare equal, which would make this pass for the wrong
    // reason.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let before = reqwest::get(format!("http://{addr}/catalog"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!stored(&before), "precondition: the value should be absent");

    // Now write it, exactly as the CLI would, with the daemon still running.
    {
        let mut s = CredentialStore::open(
            h.dir.join("vault.store"),
            &FileUnwrapper::new(h.dir.join("master.key")),
        )
        .unwrap();
        s.put("OPENROUTER_API_KEY", SecretValue::new(REAL_CREDENTIAL))
            .unwrap();
    }

    let after = reqwest::get(format!("http://{addr}/catalog"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        stored(&after),
        "the daemon must see a credential stored while it was running: {after}"
    );
    assert!(!after.contains(REAL_CREDENTIAL), "and still never serve it");
}
