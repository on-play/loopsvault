//! Shared daemon state, and the audit log.

use std::sync::{Arc, Mutex};

use anyhow::Context;
use loopsvault_core::unwrap::FileUnwrapper;
use loopsvault_core::{Catalog, PriceTable, ProjectRegistry};

use crate::config::Config;
use crate::store::CredentialStore;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    pub config: Config,
    pub catalog: Catalog,
    pub projects: ProjectRegistry,
    pub prices: PriceTable,
    pub store: Mutex<CredentialStore>,
    pub audit: Mutex<AuditLog>,
    pub http: reqwest::Client,
}

impl AppState {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let unwrapper = FileUnwrapper::new(&config.master_key_path);
        let store = CredentialStore::open(&config.store_path, &unwrapper)
            .context("opening the credential store")?;

        let http = reqwest::Client::builder()
            // The upstream is a real provider over TLS. No custom root store,
            // no danger_accept_invalid_certs, ever: this process holds the
            // credentials, so it is the last place that should be relaxed
            // about who it is talking to.
            .build()
            .context("building the upstream HTTP client")?;

        Ok(AppState(Arc::new(Inner {
            catalog: config.catalog.clone(),
            projects: config.projects.clone(),
            prices: config.price_table(),
            config,
            store: Mutex::new(store),
            audit: Mutex::new(AuditLog::default()),
            http,
        })))
    }
}

impl std::ops::Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

/// Every use, every project, every timestamp.
///
/// In-memory for v1, which is honest about what it is: the handoff wants a
/// durable audit log and that lands with the SQLite work. What matters now is
/// that the shape is right, in particular that a record can describe a refusal
/// without quoting the thing it refused.
#[derive(Debug, Default)]
pub struct AuditLog {
    pub records: Vec<AuditRecord>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AuditRecord {
    pub at_unix: u64,
    pub project: String,
    pub credential: String,
    pub target: String,
    pub outcome: Outcome,
    /// True when this record is evidence of a problem rather than a typo. The
    /// alarm list from the handoff: wrong host, wrong project, honeytoken.
    pub alarm: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution: Option<loopsvault_core::Attribution>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Injected,
    Denied,
    UpstreamError,
}

impl AuditLog {
    pub fn push(&mut self, record: AuditRecord) {
        if record.alarm {
            // The handoff keeps revoke manual by default: an automatic revoke
            // on a false positive takes production down at 3am. So an alarm is
            // loud and does not act.
            tracing::error!(
                project = %record.project,
                credential = %record.credential,
                target = %record.target,
                "ALARM: {:?}", record.outcome
            );
        }
        self.records.push(record);
    }

    pub fn recent(&self, n: usize) -> &[AuditRecord] {
        let start = self.records.len().saturating_sub(n);
        &self.records[start..]
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
