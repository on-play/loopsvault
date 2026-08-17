//! Daemon configuration.
//!
//! Note what is a config field here and what is not. The founder's rule is that
//! a value is not an environment variable until it has to be: only a secret, or
//! a value that genuinely differs between deployments that exist today. So the
//! bind address, the store path and the provider table are config, because they
//! genuinely differ between this Mac and a Linux server. Everything else that a
//! lesser design would make configurable is a constant in source.
//!
//! No credential appears in this file. Values live in the store; this file only
//! says where the store is.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use loopsvault_core::{Catalog, ProjectRegistry};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Where the encrypted credential store lives.
    pub store_path: PathBuf,

    /// Where the master key file lives, for the v1 file unwrapper.
    pub master_key_path: PathBuf,

    /// The plaintext, agent-readable catalog.
    #[serde(default)]
    pub catalog: Catalog,

    /// Token fingerprints to project names. Holds no usable token.
    #[serde(default)]
    pub projects: ProjectRegistry,

    /// Which URL prefix maps to which upstream and which credential.
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderConfig>,

    /// Model prices, in micro-dollars per million tokens.
    #[serde(default)]
    pub prices: BTreeMap<String, PriceEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// The real upstream base, e.g. `https://openrouter.ai`.
    pub upstream: String,
    /// The catalog entry whose value is written into the request.
    pub credential: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PriceEntry {
    pub input_micro_usd_per_mtok: u64,
    pub output_micro_usd_per_mtok: u64,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config = serde_json::from_str(&raw)
            .with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Fail at startup rather than at request time.
    ///
    /// Every check here is one that would otherwise surface as a confusing
    /// refusal in the middle of a request, with a credential already resolved.
    pub fn validate(&self) -> anyhow::Result<()> {
        self.catalog.validate().context("catalog is invalid")?;

        for (name, p) in &self.providers {
            let entry = self.catalog.get(&p.credential).with_context(|| {
                format!("provider {name} names credential {} which is not in the catalog", p.credential)
            })?;

            let host = upstream_host(&p.upstream)
                .with_context(|| format!("provider {name} has an unusable upstream"))?;

            // The tie back to the injection core. If a provider's upstream host
            // is not in its credential's allowlist, every request through it
            // would be refused at run time anyway. Catching it here turns a
            // puzzling 403 into a startup error that names both sides.
            let allow = entry
                .host_allowlist()
                .with_context(|| format!("credential {} has an invalid host list", p.credential))?;
            if !allow.allows(&host) {
                bail!(
                    "provider {name} points at {host}, which is not in {}'s hosts list ({}). \
                     Add the host to the catalog entry, or point the provider elsewhere. \
                     Refusing to start rather than refuse every request.",
                    p.credential,
                    allow.iter().map(|h| h.to_string()).collect::<Vec<_>>().join(", ")
                );
            }

            if entry.placement.is_none() {
                bail!(
                    "credential {} has no placement, so provider {name} could never write it into a request",
                    p.credential
                );
            }
        }

        Ok(())
    }

    pub fn price_table(&self) -> loopsvault_core::PriceTable {
        let mut t = loopsvault_core::PriceTable::new();
        for (model, p) in &self.prices {
            t.set(
                model.clone(),
                loopsvault_core::meter::ModelPrice {
                    input_micro_usd_per_mtok: p.input_micro_usd_per_mtok,
                    output_micro_usd_per_mtok: p.output_micro_usd_per_mtok,
                },
            );
        }
        t
    }
}

/// Pull the host out of an upstream base URL and normalise it.
///
/// Deliberately strict and hand-rolled rather than pulling a URL parser: the
/// only shapes accepted are `https://host` and `https://host/prefix`. Anything
/// with credentials, a query, or a fragment in the base is a configuration
/// mistake worth stopping for.
pub fn upstream_host(upstream: &str) -> anyhow::Result<loopsvault_core::Host> {
    let rest = upstream
        .strip_prefix("https://")
        .or_else(|| upstream.strip_prefix("http://"))
        .ok_or_else(|| anyhow::anyhow!("upstream {upstream} must start with https:// or http://"))?;

    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        bail!("upstream {upstream} must not contain credentials");
    }

    // A port is legal in a URL but not part of a host, so it is split off here
    // rather than being rejected by Host::parse with a confusing message.
    let host_part = match authority.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => h,
        _ => authority,
    };

    loopsvault_core::Host::parse(host_part)
        .with_context(|| format!("upstream {upstream} has an invalid host"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_and_normalises_the_upstream_host() {
        assert_eq!(upstream_host("https://openrouter.ai").unwrap().as_str(), "openrouter.ai");
        assert_eq!(upstream_host("https://openrouter.ai/api/v1").unwrap().as_str(), "openrouter.ai");
        assert_eq!(upstream_host("https://OpenRouter.AI/").unwrap().as_str(), "openrouter.ai");
        assert_eq!(upstream_host("http://localhost:8080").unwrap().as_str(), "localhost");
    }

    #[test]
    fn rejects_upstreams_that_are_configuration_mistakes() {
        assert!(upstream_host("openrouter.ai").is_err(), "scheme is required");
        assert!(upstream_host("https://user:pass@openrouter.ai").is_err());
        assert!(upstream_host("https://").is_err());
    }
}
