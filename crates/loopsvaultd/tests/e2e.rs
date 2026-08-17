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
