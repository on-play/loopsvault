//! HTTP surface.
//!
//! Two kinds of route, and the split matters:
//!
//! - **The catalog routes are open.** Any agent may read them, freely and
//!   without a token, because they carry no value. This is the piece that fixes
//!   the original complaint: an agent that would otherwise flail against a
//!   blocked env file can ask what exists and what it is for.
//! - **The proxy route requires a project token**, because it is the one that
//!   spends money and touches credentials.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{any, get};
use axum::{Json, Router};
use serde::Serialize;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/catalog", get(catalog))
        .route("/catalog/:name", get(describe))
        .route("/usage", get(usage))
        .route("/audit", get(audit))
        // The v1 transport. `/:provider/*rest` so that
        // /openrouter/v1/chat/completions maps to provider=openrouter and
        // rest=v1/chat/completions.
        .route("/:provider/*rest", any(crate::proxy::handle))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

/// The catalog, as an agent sees it.
///
/// Values are absent by construction rather than by filtering: `CatalogEntry`
/// has no field that could hold one. See `loopsvault_core::catalog`.
async fn catalog(State(state): State<AppState>) -> Json<CatalogView> {
    let mut store = state.store.lock().unwrap();
        store.reload_if_changed();
    let entries = state
        .catalog
        .entries
        .iter()
        .filter(|e| !e.honeytoken) // a honeytoken that advertises itself is not a tripwire
        .map(|e| EntryView {
            name: e.name.clone(),
            aliases: e.aliases.clone(),
            provider: e.provider.clone(),
            comment: e.comment.clone(),
            expiry: e.expiry.clone(),
            projects: e.projects.clone(),
            classification: format!("{:?}", e.classification).to_lowercase(),
            hosts: e.hosts.clone(),
            shape: store.shape_of(&e.name),
            stored: store.get(&e.name).is_some(),
        })
        .collect();

    // Stored names that no catalog entry claims. Without this a typo in
    // `loopsvault set` is invisible: the value is stored under a name nothing
    // will ever look up, `set` reports success, and the catalog goes on saying
    // the credential is missing. Silent, and the two halves never meet.
    let orphaned: Vec<String> = store
        .names()
        .into_iter()
        .filter(|n| state.catalog.get(n).is_err())
        .map(String::from)
        .collect();

    Json(CatalogView {
        note: "Names, purposes and shapes only. Values are never served by this API, \
               and there is no endpoint that returns one. To USE a credential, send your \
               request through the proxy and it will be written in on the way out."
            .into(),
        entries,
        orphaned,
    })
}

async fn describe(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<EntryView>, (StatusCode, Json<serde_json::Value>)> {
    let entry = state.catalog.get(&name).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("no catalog entry named {name}"),
                "next_step": "GET /catalog to see everything that exists.",
            })),
        )
    })?;

    if entry.honeytoken {
        // Same answer as a name that does not exist. A tripwire that announces
        // itself is not a tripwire.
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("no catalog entry named {name}"),
                "next_step": "GET /catalog to see everything that exists.",
            })),
        ));
    }

    let mut store = state.store.lock().unwrap();
        store.reload_if_changed();
    Ok(Json(EntryView {
        name: entry.name.clone(),
        aliases: entry.aliases.clone(),
        provider: entry.provider.clone(),
        comment: entry.comment.clone(),
        expiry: entry.expiry.clone(),
        projects: entry.projects.clone(),
        classification: format!("{:?}", entry.classification).to_lowercase(),
        hosts: entry.hosts.clone(),
        shape: store.shape_of(&entry.name),
        stored: store.get(&entry.name).is_some(),
    }))
}

/// Per-project usage, rolled up from the audit log.
async fn usage(State(state): State<AppState>) -> Json<serde_json::Value> {
    use std::collections::BTreeMap;

    let audit = state.audit.lock().unwrap();
    let mut by_project: BTreeMap<String, ProjectUsage> = BTreeMap::new();

    for r in &audit.records {
        let e = by_project.entry(r.project.clone()).or_default();
        e.calls += 1;
        match &r.attribution {
            Some(loopsvault_core::Attribution::Measured {
                usage, micro_usd, ..
            }) => {
                e.input_tokens += usage.input_tokens;
                e.output_tokens += usage.output_tokens;
                match micro_usd {
                    Some(c) => e.micro_usd += c,
                    // An unpriced model is not a free one. Counting it as zero
                    // would make the total quietly wrong in the cheap
                    // direction, which is the worst way for a spend figure to
                    // be wrong.
                    None => e.unpriced_calls += 1,
                }
            }
            Some(loopsvault_core::Attribution::Counted { .. }) => e.unmetered_calls += 1,
            None => {}
        }
        // The daemon's own cost, with the provider's latency subtracted rather
        // than averaged against. Comparing a proxied call to a direct one folds
        // provider jitter into the delta and needs repetition to partly cancel
        // it; subtracting the upstream leg cancels it exactly, per call, and
        // needs nobody to hold a raw key to produce a baseline.
        if let Some(o) = r.overhead_ms() {
            e.overhead_ms_total += o;
            e.overhead_ms_max = e.overhead_ms_max.max(o);
            e.overhead_samples += 1;
        }
    }

    Json(serde_json::json!({
        "note": "Exact for providers that report tokens. fal.ai and Replicate bill on \
                 compute time and report none, so those appear as unmetered_calls with the \
                 dollars honestly unknown rather than reported as zero.",
        "projects": by_project,
    }))
}

async fn audit(State(state): State<AppState>) -> Json<serde_json::Value> {
    let audit = state.audit.lock().unwrap();
    let recent = audit.recent(200);
    let alarms = recent.iter().filter(|r| r.alarm).count();
    Json(serde_json::json!({
        "alarms": alarms,
        "records": recent,
    }))
}

#[derive(Serialize)]
pub struct CatalogView {
    note: String,
    entries: Vec<EntryView>,
    /// Values stored under a name no catalog entry answers to. Always a
    /// mistake, and always worth showing loudly.
    orphaned: Vec<String>,
}

#[derive(Serialize)]
pub struct EntryView {
    name: String,
    aliases: Vec<String>,
    provider: String,
    comment: String,
    expiry: Option<String>,
    projects: Vec<String>,
    classification: String,
    hosts: Vec<String>,
    /// Length and character class. Enough to validate plausibility, never a
    /// character of the value, not even a prefix.
    shape: Option<loopsvault_core::Shape>,
    /// Whether a value exists, which is the question an agent actually needs
    /// answered before it tries to use one.
    stored: bool,
}

#[derive(Serialize, Default)]
struct ProjectUsage {
    calls: u64,
    input_tokens: u64,
    output_tokens: u64,
    micro_usd: u64,
    unpriced_calls: u64,
    unmetered_calls: u64,
    /// Milliseconds this daemon added, summed, excluding the provider's own
    /// latency.
    overhead_ms_total: u64,
    overhead_ms_max: u64,
    overhead_samples: u64,
}
