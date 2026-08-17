//! The catalog: plaintext, agent-readable, value-free.
//!
//! This is the piece no existing tool provides and the one that fixes the
//! original complaint. An agent can read all of this freely and answer "what
//! keys exist, what are they for, which are expiring" without any privileged
//! operation and without a value ever entering its context.
//!
//! Nothing in this module can hold a value. [`CatalogEntry`] has no field of
//! type `SecretValue`, and that is a structural choice: the catalog is
//! serialised to JSON for agents, so a value field here would be one
//! `serde_json::to_string` away from the thing this project exists to prevent.
//! Values live in the store, keyed by [`CatalogEntry::name`].

use serde::{Deserialize, Serialize};

use crate::host::{Host, HostAllowlist, HostError};
use crate::secret::Shape;

/// What a value actually is, which decides whether it belongs in the vault.
///
/// Derived from the founder's own rule: a value is not an environment variable
/// until it has to be. Running the classifier across every project found that
/// of 429 distinct names in real env files, 100 were secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Classification {
    /// A real credential. This is the vault.
    Secret,
    /// A decided value. Belongs in a constants module in source, not here and
    /// not in a deployment dashboard.
    Constant,
    /// Compiled into a browser bundle by the framework (`NEXT_PUBLIC_`,
    /// `VITE_`, `NUXT_PUBLIC_`, ...), so it is served to every visitor.
    /// The vault refuses to store these on principle: storing one would imply a
    /// protection that does not exist.
    Public,
    /// The name does not say. Needs a human call before anything is built on
    /// it. Guessing "constant" here puts a credential in source.
    Review,
}

/// How the credential is written into an outbound request.
///
/// Modelled on the header-token providers the handoff lists via iron-proxy:
/// bearer, `x-api-key`, `api-key`, `x-goog-api-key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Placement {
    /// `Authorization: Bearer <value>`, or any header with an optional scheme
    /// prefix.
    Header {
        header: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
    },
    /// `?key=<value>`. Used by some Google endpoints. Discouraged: a query
    /// string lands in access logs on the far side.
    QueryParam { name: String },
}

/// One catalog entry. Contains no value, by construction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntry {
    /// Canonical name, e.g. `OPENROUTER_API_KEY`.
    pub name: String,

    /// Other names that mean this same credential.
    ///
    /// Not cosmetic. The inventory found the same Anthropic credential living
    /// as `ANTHROPIC_API_KEY` in six projects and `CLAUDE_API_KEY` in four.
    /// Without aliases the vault either stores one secret twice, recreating the
    /// rotation problem it exists to solve, or forces a rename across ten repos
    /// before anything can be adopted.
    #[serde(default)]
    pub aliases: Vec<String>,

    pub provider: String,

    /// What it is for, in plain language. This is the field that stops an agent
    /// guessing, and it is the whole reason the catalog is readable.
    pub comment: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,

    /// Projects permitted to use this credential. Exact names, no globs, for
    /// the same reason hosts are exact.
    #[serde(default)]
    pub projects: Vec<String>,

    /// Length and character class, so an agent can validate plausibility
    /// without seeing a character. Absent until a value is stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<Shape>,

    pub classification: Classification,

    /// Exact hosts this credential may ever be sent to.
    #[serde(default)]
    pub hosts: Vec<String>,

    #[serde(default)]
    pub placement: Option<Placement>,

    /// A honeytoken is a realistic but entirely fake credential that nothing
    /// legitimate references. Any use of one is definitive evidence of a
    /// problem, with zero false positives, which is why the handoff calls it
    /// the first alarm to build.
    #[serde(default)]
    pub honeytoken: bool,
}

impl CatalogEntry {
    /// Does this entry answer to `name`, canonically or by alias?
    ///
    /// Case-sensitive on purpose. Env variable names are conventionally upper
    /// case, and folding here would let `openrouter_api_key` and
    /// `OPENROUTER_API_KEY` be the same entry, which hides a typo rather than
    /// reporting it.
    pub fn answers_to(&self, name: &str) -> bool {
        self.name == name || self.aliases.iter().any(|a| a == name)
    }

    pub fn host_allowlist(&self) -> Result<HostAllowlist, HostError> {
        HostAllowlist::parse(&self.hosts)
    }

    pub fn permits_project(&self, project: &str) -> bool {
        self.projects.iter().any(|p| p == project)
    }
}

/// The whole catalog.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(default)]
    pub entries: Vec<CatalogEntry>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CatalogError {
    #[error("no catalog entry named {0}")]
    NoSuchEntry(String),
    #[error("{0} is claimed by more than one entry")]
    AmbiguousName(String),
    #[error("entry {entry} has an invalid host: {source}")]
    BadHost {
        entry: String,
        #[source]
        source: HostError,
    },
}

impl Catalog {
    pub fn get(&self, name: &str) -> Result<&CatalogEntry, CatalogError> {
        let mut found = self.entries.iter().filter(|e| e.answers_to(name));
        let first = found.next().ok_or_else(|| CatalogError::NoSuchEntry(name.to_string()))?;
        if found.next().is_some() {
            // Two entries claiming one name is a configuration bug that would
            // otherwise resolve to whichever came first in the file, which is
            // exactly the kind of silent choice that loses a credential.
            return Err(CatalogError::AmbiguousName(name.to_string()));
        }
        Ok(first)
    }

    /// Every name, canonical and alias, that resolves to something. This is
    /// what an agent lists.
    pub fn names(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for e in &self.entries {
            out.push(&e.name);
            out.extend(e.aliases.iter().map(|s| s.as_str()));
        }
        out.sort_unstable();
        out
    }

    /// Validate the whole catalog up front, so a typo stops the daemon starting
    /// rather than silently narrowing an allowlist at request time.
    pub fn validate(&self) -> Result<(), CatalogError> {
        let mut seen: Vec<&str> = Vec::new();
        for e in &self.entries {
            e.host_allowlist().map_err(|source| CatalogError::BadHost {
                entry: e.name.clone(),
                source,
            })?;
            for n in std::iter::once(e.name.as_str()).chain(e.aliases.iter().map(|s| s.as_str())) {
                if seen.contains(&n) {
                    return Err(CatalogError::AmbiguousName(n.to_string()));
                }
                seen.push(n);
            }
        }
        Ok(())
    }

    pub fn hosts_of(&self, name: &str) -> Result<HostAllowlist, CatalogError> {
        let e = self.get(name)?;
        e.host_allowlist().map_err(|source| CatalogError::BadHost {
            entry: e.name.clone(),
            source,
        })
    }

    pub fn resolve_host(&self, raw: &str) -> Result<Host, HostError> {
        Host::parse(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str) -> CatalogEntry {
        CatalogEntry {
            name: name.to_string(),
            aliases: vec![],
            provider: "openrouter".into(),
            comment: "routing for all LLM calls".into(),
            expiry: None,
            projects: vec!["pitchplus_fast".into()],
            shape: None,
            classification: Classification::Secret,
            hosts: vec!["openrouter.ai".into()],
            placement: Some(Placement::Header {
                header: "authorization".into(),
                scheme: Some("Bearer".into()),
            }),
            honeytoken: false,
        }
    }

    /// The catalog is handed to agents as JSON. If a value could ever appear in
    /// it, this project has no point.
    #[test]
    fn serialised_catalog_carries_no_value() {
        let c = Catalog {
            entries: vec![entry("OPENROUTER_API_KEY")],
        };
        let json = serde_json::to_string_pretty(&c).unwrap();
        assert!(json.contains("OPENROUTER_API_KEY"));
        assert!(json.contains("routing for all LLM calls"));
        // There is no field that could hold one, so this is a structural fact
        // rather than a lucky one. The assertion documents the intent.
        assert!(!json.to_lowercase().contains("\"value\""));
        assert!(!json.to_lowercase().contains("secretvalue"));
    }

    #[test]
    fn aliases_resolve_to_one_entry() {
        let mut e = entry("ANTHROPIC_API_KEY");
        e.aliases = vec!["CLAUDE_API_KEY".into()];
        let c = Catalog { entries: vec![e] };

        assert_eq!(c.get("ANTHROPIC_API_KEY").unwrap().name, "ANTHROPIC_API_KEY");
        assert_eq!(c.get("CLAUDE_API_KEY").unwrap().name, "ANTHROPIC_API_KEY");
        assert_eq!(
            c.get("NOPE").unwrap_err(),
            CatalogError::NoSuchEntry("NOPE".into())
        );
    }

    #[test]
    fn two_entries_claiming_one_name_is_an_error_not_a_coin_flip() {
        let mut a = entry("OPENROUTER_API_KEY");
        a.aliases = vec!["LLM_KEY".into()];
        let mut b = entry("OPENAI_API_KEY");
        b.aliases = vec!["LLM_KEY".into()];
        let c = Catalog { entries: vec![a, b] };

        assert_eq!(
            c.validate().unwrap_err(),
            CatalogError::AmbiguousName("LLM_KEY".into())
        );
        assert_eq!(
            c.get("LLM_KEY").unwrap_err(),
            CatalogError::AmbiguousName("LLM_KEY".into())
        );
    }

    #[test]
    fn a_bad_host_stops_startup() {
        let mut e = entry("OPENROUTER_API_KEY");
        e.hosts = vec!["openrouter.ai".into(), "not a host".into()];
        let c = Catalog { entries: vec![e] };
        assert!(matches!(
            c.validate().unwrap_err(),
            CatalogError::BadHost { .. }
        ));
    }

    #[test]
    fn name_matching_is_case_sensitive() {
        let c = Catalog {
            entries: vec![entry("OPENROUTER_API_KEY")],
        };
        assert!(c.get("openrouter_api_key").is_err());
    }
}
