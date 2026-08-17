//! The injection core: which credential may go to which host, for which project.
//!
//! **This module is the one Decision 1 constraint made concrete.** The founder
//! chose "both, endpoint first": v1 ships the explicit local endpoint, and an
//! opt-in MITM transport lands later. The constraint recorded with that decision
//! is that the two transports share one implementation of this decision, so that
//! exact host matching is written once. Duplicating it would give the one bug
//! class that actually leaks a key two places to live.
//!
//! So this module knows nothing about HTTP, sockets, TLS, or hyper. It takes a
//! description of an intended request and returns a verdict. A transport's only
//! job is to describe the request honestly and obey the verdict.

use crate::catalog::{Catalog, CatalogEntry, Classification, Placement};
use crate::host::Host;

/// What a transport asks about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InjectionRequest<'a> {
    /// The project this request is attributed to.
    ///
    /// This is established by the per-project token the caller presented, never
    /// by a string the caller supplied. Project identity is cryptographic; if a
    /// transport ever fills this in from request content, the attribution and
    /// the spend caps built on it become advisory.
    pub project: &'a str,
    /// The host the request will actually be sent to, already normalised.
    pub target: &'a Host,
    /// The catalog entry the caller is asking for, by canonical name or alias.
    pub credential: &'a str,
}

/// Where the transport must write the credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Injection<'a> {
    /// The resolved entry, so the transport can log and meter without a second
    /// lookup.
    pub entry: &'a CatalogEntry,
    pub placement: &'a Placement,
}

/// Why a request was refused.
///
/// Every variant is audited. Several of them are also alarms rather than
/// ordinary refusals, which [`Denial::is_alarm`] reports.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Denial {
    #[error("no catalog entry named {name}")]
    NoSuchEntry { name: String },

    #[error("{name} is claimed by more than one catalog entry")]
    AmbiguousName { name: String },

    #[error("project {project} is not permitted to use {name}")]
    ProjectNotPermitted { project: String, name: String },

    #[error("{name} may not be sent to {target}")]
    HostNotPermitted { name: String, target: String },

    #[error("{name} has no host allowlist, so it may not be sent anywhere")]
    NoHostsConfigured { name: String },

    #[error("{name} has no placement configured, so it cannot be written into a request")]
    NoPlacement { name: String },

    #[error("{name} is classified {classification:?} and is not a credential")]
    NotACredential {
        name: String,
        classification: Classification,
    },

    #[error("HONEYTOKEN {name} was requested by project {project} for {target}")]
    Honeytoken {
        name: String,
        project: String,
        target: String,
    },

    #[error("catalog entry {entry} has an invalid host configured: {detail}")]
    BadHostConfig { entry: String, detail: String },
}

impl Denial {
    /// Is this refusal evidence of a problem, rather than ordinary
    /// misconfiguration?
    ///
    /// The handoff's alarm list: a credential requested for a host not in its
    /// allowlist, a credential used by a project not in its list, and any touch
    /// of a honeytoken. Those three are here. A missing entry or a missing
    /// placement is someone typing a name wrong, and paging on it would train
    /// the founder to ignore the alarm, which is worse than not having one.
    pub fn is_alarm(&self) -> bool {
        matches!(
            self,
            Denial::Honeytoken { .. }
                | Denial::HostNotPermitted { .. }
                | Denial::ProjectNotPermitted { .. }
        )
    }
}

/// Decide whether a credential may be written into this request.
///
/// The order of checks is deliberate: honeytoken first, so that a honeytoken
/// fires its alarm even when the request would have been refused for a duller
/// reason afterwards. An attacker probing the vault should trip the tripwire on
/// the first touch, not on the one request that happens to be otherwise valid.
pub fn decide<'a>(
    catalog: &'a Catalog,
    req: &InjectionRequest<'_>,
) -> Result<Injection<'a>, Denial> {
    let entry = catalog.get(req.credential).map_err(|e| match e {
        crate::catalog::CatalogError::NoSuchEntry(name) => Denial::NoSuchEntry { name },
        crate::catalog::CatalogError::AmbiguousName(name) => Denial::AmbiguousName { name },
        crate::catalog::CatalogError::BadHost { entry, source } => Denial::BadHostConfig {
            entry,
            detail: source.to_string(),
        },
    })?;

    // 1. Honeytoken. Nothing legitimate ever references one, so any touch is
    //    definitive. Checked first so the alarm cannot be masked.
    if entry.honeytoken {
        return Err(Denial::Honeytoken {
            name: entry.name.clone(),
            project: req.project.to_string(),
            target: req.target.to_string(),
        });
    }

    // 2. Only a secret can be injected. Refusing to inject a `public` value is
    //    not pedantry: handing one out through the credential path would imply
    //    a protection it does not have, since the framework already ships it to
    //    every browser.
    if entry.classification != Classification::Secret {
        return Err(Denial::NotACredential {
            name: entry.name.clone(),
            classification: entry.classification,
        });
    }

    // 3. Project scope. Exact, never a glob.
    if !entry.permits_project(req.project) {
        return Err(Denial::ProjectNotPermitted {
            project: req.project.to_string(),
            name: entry.name.clone(),
        });
    }

    // 4. Host scope. Exact, never a suffix, never a wildcard. An empty
    //    allowlist permits nothing, rather than permitting everything, which is
    //    the direction that fails safe when a catalog entry is half written.
    let allow = entry
        .host_allowlist()
        .map_err(|source| Denial::BadHostConfig {
            entry: entry.name.clone(),
            detail: source.to_string(),
        })?;
    if allow.is_empty() {
        return Err(Denial::NoHostsConfigured {
            name: entry.name.clone(),
        });
    }
    if !allow.allows(req.target) {
        return Err(Denial::HostNotPermitted {
            name: entry.name.clone(),
            target: req.target.to_string(),
        });
    }

    // 5. Somewhere to put it.
    let placement = entry.placement.as_ref().ok_or_else(|| Denial::NoPlacement {
        name: entry.name.clone(),
    })?;

    Ok(Injection { entry, placement })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::CatalogEntry;

    fn entry() -> CatalogEntry {
        CatalogEntry {
            name: "OPENROUTER_API_KEY".into(),
            aliases: vec![],
            provider: "openrouter".into(),
            comment: "LLM routing".into(),
            expiry: None,
            projects: vec!["pitchplus_fast".into(), "42flows.com".into()],
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

    fn catalog_with(e: CatalogEntry) -> Catalog {
        Catalog { entries: vec![e] }
    }

    fn ask<'a>(c: &'a Catalog, project: &str, target: &str, cred: &str) -> Result<Injection<'a>, Denial> {
        let host = Host::parse(target).expect("test host parses");
        decide(
            c,
            &InjectionRequest {
                project,
                target: &host,
                credential: cred,
            },
        )
    }

    #[test]
    fn the_happy_path_injects() {
        let c = catalog_with(entry());
        let inj = ask(&c, "pitchplus_fast", "openrouter.ai", "OPENROUTER_API_KEY").unwrap();
        assert_eq!(inj.entry.name, "OPENROUTER_API_KEY");
        assert_eq!(
            inj.placement,
            &Placement::Header {
                header: "authorization".into(),
                scheme: Some("Bearer".into())
            }
        );
    }

    /// The attack the whole design is shaped around: an agent routes a request
    /// to a host it controls and hopes the credential comes along.
    #[test]
    fn refuses_a_host_the_credential_does_not_belong_to() {
        let c = catalog_with(entry());
        for evil in [
            "openrouter.ai.evil.com",
            "evil.com",
            "evil-openrouter.ai",
            "api.openrouter.ai",
            "openrouter.ai.co",
        ] {
            let err = ask(&c, "pitchplus_fast", evil, "OPENROUTER_API_KEY").unwrap_err();
            assert!(
                matches!(err, Denial::HostNotPermitted { .. }),
                "{evil} should be refused, got {err:?}"
            );
            assert!(err.is_alarm(), "{evil} should raise an alarm");
        }
    }

    #[test]
    fn refuses_a_project_outside_the_entrys_scope() {
        let c = catalog_with(entry());
        let err = ask(&c, "some_other_project", "openrouter.ai", "OPENROUTER_API_KEY").unwrap_err();
        assert!(matches!(err, Denial::ProjectNotPermitted { .. }));
        assert!(err.is_alarm());
    }

    /// Checked before every other refusal, so probing cannot mask the tripwire.
    #[test]
    fn a_honeytoken_alarms_before_any_other_check() {
        let mut e = entry();
        e.name = "STRIPE_LIVE_SECRET_BACKUP".into();
        e.honeytoken = true;
        // Deliberately also wrong in every other way: no projects, no hosts,
        // no placement. The honeytoken verdict must still win.
        e.projects.clear();
        e.hosts.clear();
        e.placement = None;
        let c = catalog_with(e);

        let err = ask(&c, "anything", "evil.com", "STRIPE_LIVE_SECRET_BACKUP").unwrap_err();
        assert!(
            matches!(err, Denial::Honeytoken { .. }),
            "honeytoken must win over every other denial, got {err:?}"
        );
        assert!(err.is_alarm());
    }

    #[test]
    fn an_empty_host_allowlist_permits_nothing() {
        let mut e = entry();
        e.hosts.clear();
        let c = catalog_with(e);
        let err = ask(&c, "pitchplus_fast", "openrouter.ai", "OPENROUTER_API_KEY").unwrap_err();
        assert!(matches!(err, Denial::NoHostsConfigured { .. }));
    }

    #[test]
    fn refuses_to_inject_anything_that_is_not_a_secret() {
        for class in [
            Classification::Constant,
            Classification::Public,
            Classification::Review,
        ] {
            let mut e = entry();
            e.classification = class;
            let c = catalog_with(e);
            let err = ask(&c, "pitchplus_fast", "openrouter.ai", "OPENROUTER_API_KEY").unwrap_err();
            assert!(
                matches!(err, Denial::NotACredential { .. }),
                "{class:?} should not be injectable"
            );
            // Misconfiguration, not an attack. Paging on it would train the
            // founder to ignore the alarm.
            assert!(!err.is_alarm());
        }
    }

    #[test]
    fn an_alias_reaches_the_same_entry_and_the_same_scope() {
        let mut e = entry();
        e.name = "ANTHROPIC_API_KEY".into();
        e.aliases = vec!["CLAUDE_API_KEY".into()];
        e.hosts = vec!["api.anthropic.com".into()];
        let c = catalog_with(e);

        let a = ask(&c, "pitchplus_fast", "api.anthropic.com", "ANTHROPIC_API_KEY").unwrap();
        let b = ask(&c, "pitchplus_fast", "api.anthropic.com", "CLAUDE_API_KEY").unwrap();
        assert_eq!(a.entry.name, b.entry.name);

        // An alias must not widen anything.
        let err = ask(&c, "pitchplus_fast", "evil.com", "CLAUDE_API_KEY").unwrap_err();
        assert!(matches!(err, Denial::HostNotPermitted { .. }));
    }

    #[test]
    fn unknown_names_are_refused_but_do_not_page_anyone() {
        let c = catalog_with(entry());
        let err = ask(&c, "pitchplus_fast", "openrouter.ai", "NOPE").unwrap_err();
        assert!(matches!(err, Denial::NoSuchEntry { .. }));
        assert!(!err.is_alarm());
    }

    #[test]
    fn a_missing_placement_is_refused_rather_than_guessed() {
        let mut e = entry();
        e.placement = None;
        let c = catalog_with(e);
        let err = ask(&c, "pitchplus_fast", "openrouter.ai", "OPENROUTER_API_KEY").unwrap_err();
        assert!(matches!(err, Denial::NoPlacement { .. }));
    }

    /// A denial is logged and shown. It must describe the refusal without
    /// quoting the thing it protects.
    #[test]
    fn denials_never_contain_a_value() {
        let c = catalog_with(entry());
        let err = ask(&c, "evil_project", "openrouter.ai", "OPENROUTER_API_KEY").unwrap_err();
        let text = format!("{err} {err:?}");
        assert!(text.contains("OPENROUTER_API_KEY"), "should name the entry");
        assert!(!text.contains("FAKE-sk"), "must not carry a value");
    }
}
