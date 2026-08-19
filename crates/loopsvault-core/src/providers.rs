//! What each provider's API expects, so a catalog entry can be generated
//! rather than hand-written.
//!
//! This table is the reason adopting LoopsVault is one command rather than an
//! afternoon of JSON. The founder has 100 real secrets across 28 projects;
//! writing a catalog entry for each by hand is the friction that would kill
//! adoption before the daemon ever handled a real call.
//!
//! ## Confidence is part of the data, on purpose
//!
//! Getting a placement wrong is not dangerous, because the exact-host rule
//! still holds and a bad header just earns a 401 from the provider. But it IS
//! confusing, and a config generator that silently emits a guess teaches you to
//! distrust the whole file. So each profile records how sure this is, and
//! [`Confidence::Likely`] entries are emitted for confirmation rather than as
//! settled fact.
//!
//! When a `Likely` entry is confirmed against a real call, promote it here and
//! say so in the commit. That is how this table gets better.

use crate::catalog::Placement;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confidence {
    /// The shape is well established and stable across this provider's docs.
    Verified,
    /// Believed correct, not confirmed against a live call from this machine.
    /// Emitted for review rather than used silently.
    Likely,
}

#[derive(Clone, Copy, Debug)]
pub struct ProviderProfile {
    /// Short key used in the URL path: `/openrouter/v1/...`.
    pub key: &'static str,
    /// Base the daemon forwards to.
    pub upstream: &'static str,
    /// Exact hosts this credential may be sent to. Never a suffix or wildcard.
    pub hosts: &'static [&'static str],
    /// Header the credential goes in.
    pub header: &'static str,
    /// Scheme prefix, if any. `Bearer` for most, absent for `x-api-key` styles.
    pub scheme: Option<&'static str>,
    /// Variable names that mean this credential. First is canonical.
    pub names: &'static [&'static str],
    /// A path that REQUIRES auth and costs nothing, used to check whether a
    /// stored credential actually works.
    ///
    /// Choosing this badly is how a green light becomes meaningless. On
    /// 2026-08-19 a 200 from OpenRouter's /models was reported as proof that
    /// the vault had brokered a real credential. /models is PUBLIC: it returns
    /// 200 with no auth at all, so it proved routing and proved nothing about
    /// the key. An endpoint belongs here only if it fails without a credential.
    pub verify_path: &'static str,
    pub confidence: Confidence,
    /// Whether the response body carries token counts. False means the meter
    /// can count calls but not dollars, which the report shows honestly rather
    /// than reporting zero.
    pub reports_tokens: bool,
    pub note: &'static str,
}

impl ProviderProfile {
    pub fn placement(&self) -> Placement {
        Placement::Header {
            header: self.header.to_string(),
            scheme: self.scheme.map(String::from),
        }
    }

    pub fn canonical_name(&self) -> &'static str {
        self.names[0]
    }

    pub fn aliases(&self) -> &'static [&'static str] {
        &self.names[1..]
    }
}

/// The table.
///
/// Ordered roughly by how much traffic the founder's inventory showed.
pub const PROFILES: &[ProviderProfile] = &[
    ProviderProfile {
        key: "openrouter",
        upstream: "https://openrouter.ai",
        hosts: &["openrouter.ai"],
        header: "authorization",
        scheme: Some("Bearer"),
        names: &["OPENROUTER_API_KEY"],
        verify_path: "/api/v1/auth/key",
        confidence: Confidence::Verified,
        reports_tokens: true,
        note: "OpenAI-compatible. Present in 7 projects, the widest sharing in the inventory.",
    },
    ProviderProfile {
        key: "openai",
        upstream: "https://api.openai.com",
        hosts: &["api.openai.com"],
        header: "authorization",
        scheme: Some("Bearer"),
        names: &["OPENAI_API_KEY"],
        verify_path: "/v1/models",
        confidence: Confidence::Verified,
        reports_tokens: true,
        note: "Streaming needs stream_options.include_usage, which the daemon adds outbound.",
    },
    ProviderProfile {
        key: "anthropic",
        upstream: "https://api.anthropic.com",
        hosts: &["api.anthropic.com"],
        // Not Bearer. Anthropic takes the key in its own header with no scheme.
        header: "x-api-key",
        scheme: None,
        names: &["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"],
        verify_path: "/v1/models",
        confidence: Confidence::Verified,
        reports_tokens: true,
        note: "One credential, two names in this inventory: ANTHROPIC_API_KEY in 6 projects and \
               CLAUDE_API_KEY in 4. This is the case aliases[] was added for.",
    },
    ProviderProfile {
        key: "gemini",
        upstream: "https://generativelanguage.googleapis.com",
        hosts: &["generativelanguage.googleapis.com"],
        header: "x-goog-api-key",
        scheme: None,
        names: &["GEMINI_API_KEY"],
        verify_path: "/v1beta/models",
        confidence: Confidence::Verified,
        reports_tokens: true,
        note: "Also accepts ?key=, but the header is preferred: a query string lands in the \
               provider's access logs on the far side.",
    },
    ProviderProfile {
        key: "stripe",
        upstream: "https://api.stripe.com",
        hosts: &["api.stripe.com"],
        header: "authorization",
        scheme: Some("Bearer"),
        names: &["STRIPE_SECRET_KEY"],
        verify_path: "/v1/balance",
        confidence: Confidence::Verified,
        reports_tokens: false,
        note: "Not an LLM API, so calls are counted and never priced. Brokering it still buys \
               rotation in one place and the audit trail.",
    },
    ProviderProfile {
        key: "resend",
        upstream: "https://api.resend.com",
        hosts: &["api.resend.com"],
        header: "authorization",
        scheme: Some("Bearer"),
        names: &["RESEND_API_KEY"],
        verify_path: "/domains",
        confidence: Confidence::Verified,
        reports_tokens: false,
        note: "In 5 projects.",
    },
    ProviderProfile {
        key: "replicate",
        upstream: "https://api.replicate.com",
        hosts: &["api.replicate.com"],
        header: "authorization",
        scheme: Some("Bearer"),
        names: &["REPLICATE_API_TOKEN"],
        verify_path: "/v1/account",
        confidence: Confidence::Likely,
        reports_tokens: false,
        note: "Historically used the Token scheme and moved to Bearer. Confirm against a real \
               call before relying on it. Bills on compute time, so calls are counted not priced.",
    },
    ProviderProfile {
        key: "fal",
        upstream: "https://fal.run",
        hosts: &["fal.run", "queue.fal.run"],
        header: "authorization",
        scheme: Some("Key"),
        names: &["FAL_KEY"],
        verify_path: "",
        confidence: Confidence::Likely,
        reports_tokens: false,
        note: "Believed to use the Key scheme rather than Bearer. CONFIRM before relying on it. \
               Bills on compute time and reports no tokens, so this is the provider the handoff \
               calls out as approximate: accurate call counts, no exact dollars.",
    },
    ProviderProfile {
        key: "elevenlabs",
        upstream: "https://api.elevenlabs.io",
        hosts: &["api.elevenlabs.io"],
        header: "xi-api-key",
        scheme: None,
        names: &["ELEVENLABS_API_KEY"],
        verify_path: "/v1/user",
        confidence: Confidence::Likely,
        reports_tokens: false,
        note: "Confirm the header name against a real call.",
    },
    ProviderProfile {
        key: "deepgram",
        upstream: "https://api.deepgram.com",
        hosts: &["api.deepgram.com"],
        header: "authorization",
        scheme: Some("Token"),
        names: &["DEEPGRAM_API_KEY"],
        verify_path: "/v1/projects",
        confidence: Confidence::Likely,
        reports_tokens: false,
        note: "Believed to use the Token scheme rather than Bearer. Confirm before relying on it.",
    },
];

/// Find the profile that owns a variable name, canonical or alias.
pub fn profile_for(name: &str) -> Option<&'static ProviderProfile> {
    PROFILES
        .iter()
        .find(|p| p.names.iter().any(|n| n.eq_ignore_ascii_case(name)))
}

pub fn profile_by_key(key: &str) -> Option<&'static ProviderProfile> {
    PROFILES.iter().find(|p| p.key == key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::Host;

    /// Every host in this table must survive the same parser the injection core
    /// uses. A typo here would otherwise surface as a refusal at request time,
    /// with a credential already resolved.
    #[test]
    fn every_profile_host_parses() {
        for p in PROFILES {
            assert!(!p.hosts.is_empty(), "{} has no hosts", p.key);
            for h in p.hosts {
                Host::parse(h).unwrap_or_else(|e| panic!("{} host {h}: {e}", p.key));
            }
        }
    }

    /// The upstream must be one of the hosts the credential is allowed to reach,
    /// or the daemon refuses to start. Catching that here is cheaper than in a
    /// startup error on the founder's machine.
    #[test]
    fn every_upstream_is_inside_its_own_allowlist() {
        for p in PROFILES {
            let rest = p
                .upstream
                .strip_prefix("https://")
                .unwrap_or_else(|| panic!("{} upstream must be https", p.key));
            let host = rest.split('/').next().unwrap();
            assert!(
                p.hosts.contains(&host),
                "{}: upstream host {host} is not in its own hosts list {:?}",
                p.key,
                p.hosts
            );
        }
    }

    #[test]
    fn names_and_keys_are_unique_across_the_table() {
        let mut names = Vec::new();
        let mut keys = Vec::new();
        for p in PROFILES {
            assert!(!keys.contains(&p.key), "duplicate provider key {}", p.key);
            keys.push(p.key);
            for n in p.names {
                assert!(!names.contains(n), "{n} is claimed by two profiles");
                names.push(n);
            }
        }
    }

    #[test]
    fn lookup_works_by_canonical_name_and_alias() {
        assert_eq!(profile_for("OPENROUTER_API_KEY").unwrap().key, "openrouter");
        // The alias case the inventory forced.
        assert_eq!(profile_for("CLAUDE_API_KEY").unwrap().key, "anthropic");
        assert_eq!(profile_for("ANTHROPIC_API_KEY").unwrap().key, "anthropic");
        assert_eq!(
            profile_for("CLAUDE_API_KEY").unwrap().canonical_name(),
            "ANTHROPIC_API_KEY"
        );
        assert!(profile_for("SOMETHING_UNKNOWN").is_none());
    }

    /// Anthropic does not use Bearer. Getting this wrong is the single most
    /// likely placement mistake, because every other major LLM provider does.
    #[test]
    fn anthropic_uses_its_own_header_not_bearer() {
        let p = profile_by_key("anthropic").unwrap();
        assert_eq!(
            p.placement(),
            Placement::Header {
                header: "x-api-key".into(),
                scheme: None
            }
        );
    }

    /// The providers the founder actually spends on must be settled, not
    /// guesses. fal and Replicate are allowed to be Likely; the LLM routers are
    /// not, because those are the thin slice.
    #[test]
    fn the_high_traffic_providers_are_verified() {
        for key in ["openrouter", "openai", "anthropic", "gemini", "stripe"] {
            assert_eq!(
                profile_by_key(key).unwrap().confidence,
                Confidence::Verified,
                "{key} should be settled before adoption"
            );
        }
    }
}
