//! Exact host matching.
//!
//! This is the smallest module in the project and the one most likely to lose a
//! credential. The proxy design is robust against an agent unsetting the proxy
//! variable, because without the proxy the agent has no credential and its own
//! call simply fails. That is self-denial, not exfiltration. The genuine risk
//! runs the other way: an agent routes a request to a host it controls, and a
//! loose rule attaches the real credential to it.
//!
//! So matching is **string equality after normalisation**. Never suffix, never
//! wildcard, never "ends with". There is deliberately no API in this module that
//! could express `*.example.com`, because the way that rule gets added is
//! someone needing it at 2am and reaching for the nearest thing that works.

use std::fmt;

/// A normalised DNS host name, ready for exact comparison.
///
/// Construct only through [`Host::parse`]. The inner string is private so no
/// caller can build one that skipped normalisation.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Host(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    #[error("host is empty")]
    Empty,
    #[error("host contains whitespace")]
    Whitespace,
    #[error("host contains a non-ASCII byte; use punycode")]
    NonAscii,
    #[error("host contains a character that is not valid in a DNS name: {0:?}")]
    InvalidChar(char),
    #[error("host has an empty label (consecutive dots, or a leading dot)")]
    EmptyLabel,
    #[error("host is longer than 253 characters")]
    TooLong,
    #[error("host label is longer than 63 characters")]
    LabelTooLong,
}

impl Host {
    /// Parse and normalise a host name.
    ///
    /// Normalisation is deliberately minimal and total:
    ///
    /// - a trailing dot is removed, because `openrouter.ai.` and
    ///   `openrouter.ai` resolve to the same place and must not be two
    ///   different entries in an allowlist
    /// - ASCII uppercase is folded to lowercase
    /// - a `:port` suffix is rejected rather than stripped, so a caller cannot
    ///   accidentally pass an authority where a host was expected
    ///
    /// Anything not covered by those rules is an error rather than a guess.
    pub fn parse(raw: &str) -> Result<Self, HostError> {
        if raw.is_empty() {
            return Err(HostError::Empty);
        }
        if raw.chars().any(|c| c.is_whitespace()) {
            return Err(HostError::Whitespace);
        }
        // Reject non-ASCII rather than folding it.
        //
        // Unicode case folding maps distinct code points onto the same output:
        // U+212A KELVIN SIGN lowercases to 'k'. Any normalisation that folds
        // Unicode therefore lets a host that is not `openrouter.ai` compare
        // equal to one that is. Punycode is the wire format anyway, so the
        // caller loses nothing by converting before it gets here.
        if !raw.is_ascii() {
            return Err(HostError::NonAscii);
        }

        let trimmed = raw.strip_suffix('.').unwrap_or(raw);
        if trimmed.is_empty() {
            return Err(HostError::Empty);
        }

        // ASCII-only lowercase, for the reason above.
        let lowered = trimmed.to_ascii_lowercase();

        if lowered.len() > 253 {
            return Err(HostError::TooLong);
        }

        for label in lowered.split('.') {
            if label.is_empty() {
                return Err(HostError::EmptyLabel);
            }
            if label.len() > 63 {
                return Err(HostError::LabelTooLong);
            }
            for c in label.chars() {
                // Letters, digits, hyphen, and underscore. Underscore is not
                // legal in a hostname but is common in service records, and
                // rejecting it here would be a surprise rather than a defence.
                // A colon is rejected on purpose: an authority is not a host.
                if !(c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                    return Err(HostError::InvalidChar(c));
                }
            }
        }

        Ok(Host(lowered))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Host({})", self.0)
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The set of hosts one credential may ever be sent to.
///
/// There is no `matches_suffix`, no `add_wildcard`, and no way to construct one
/// that allows everything. Membership is exact equality and nothing else.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostAllowlist {
    hosts: Vec<Host>,
}

impl HostAllowlist {
    pub fn new(hosts: Vec<Host>) -> Self {
        let mut hosts = hosts;
        hosts.sort();
        hosts.dedup();
        HostAllowlist { hosts }
    }

    /// Parse a list of raw host strings. Fails on the first invalid entry
    /// rather than skipping it: a typo in an allowlist should stop the daemon
    /// starting, not silently narrow what is permitted.
    pub fn parse(raws: &[String]) -> Result<Self, HostError> {
        let mut hosts = Vec::with_capacity(raws.len());
        for raw in raws {
            hosts.push(Host::parse(raw)?);
        }
        Ok(HostAllowlist::new(hosts))
    }

    /// Exact membership. This is the whole security property of this module.
    pub fn allows(&self, host: &Host) -> bool {
        self.hosts.iter().any(|h| h == host)
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Host> {
        self.hosts.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Host {
        Host::parse(s).expect("valid host")
    }

    #[test]
    fn normalises_case_and_trailing_dot() {
        assert_eq!(h("OpenRouter.AI"), h("openrouter.ai"));
        assert_eq!(h("openrouter.ai."), h("openrouter.ai"));
        assert_eq!(h("OPENROUTER.AI."), h("openrouter.ai"));
    }

    /// The bug this whole module exists to prevent. Every one of these is a
    /// host an attacker can register or control, and every one of them would
    /// match under a suffix rule, a `contains` rule, or a naive wildcard.
    #[test]
    fn does_not_match_lookalikes() {
        let allow = HostAllowlist::parse(&["openrouter.ai".to_string()]).unwrap();

        assert!(allow.allows(&h("openrouter.ai")));

        // Attacker-controlled subdomain of an attacker-controlled domain.
        assert!(!allow.allows(&h("openrouter.ai.evil.com")));
        // Prefix and suffix games.
        assert!(!allow.allows(&h("evil-openrouter.ai")));
        assert!(!allow.allows(&h("openrouter.ai.co")));
        assert!(!allow.allows(&h("notopenrouter.ai")));
        assert!(!allow.allows(&h("openrouter.aig")));
        // A subdomain is a DIFFERENT host and is not implied by the parent.
        assert!(!allow.allows(&h("api.openrouter.ai")));
        // Nor is the parent implied by a child.
        let allow_sub = HostAllowlist::parse(&["api.openrouter.ai".to_string()]).unwrap();
        assert!(!allow_sub.allows(&h("openrouter.ai")));
    }

    /// Unicode case folding maps distinct code points together, so a host that
    /// folds equal is not the same host. Punycode is the wire format; convert
    /// before parsing.
    #[test]
    fn rejects_non_ascii_rather_than_folding_it() {
        // Cyrillic small letter o, not ASCII 'o'.
        assert_eq!(Host::parse("\u{43e}penrouter.ai"), Err(HostError::NonAscii));
        // U+212A KELVIN SIGN lowercases to ASCII 'k' under Unicode folding.
        assert_eq!(Host::parse("\u{212a}ey.example.com"), Err(HostError::NonAscii));
    }

    #[test]
    fn rejects_authorities_and_junk() {
        // A port makes this an authority, not a host. Rejected rather than
        // stripped, so a caller cannot pass the wrong thing and get a result.
        assert_eq!(Host::parse("openrouter.ai:443"), Err(HostError::InvalidChar(':')));
        assert_eq!(Host::parse("https://openrouter.ai"), Err(HostError::InvalidChar(':')));
        assert_eq!(Host::parse("openrouter.ai/v1"), Err(HostError::InvalidChar('/')));
        assert_eq!(Host::parse(""), Err(HostError::Empty));
        assert_eq!(Host::parse("."), Err(HostError::Empty));
        assert_eq!(Host::parse(" openrouter.ai"), Err(HostError::Whitespace));
        assert_eq!(Host::parse("openrouter.ai\n"), Err(HostError::Whitespace));
        assert_eq!(Host::parse("openrouter..ai"), Err(HostError::EmptyLabel));
        assert_eq!(Host::parse(".openrouter.ai"), Err(HostError::EmptyLabel));
        assert_eq!(Host::parse("open*router.ai"), Err(HostError::InvalidChar('*')));
    }

    #[test]
    fn empty_allowlist_allows_nothing() {
        let allow = HostAllowlist::default();
        assert!(allow.is_empty());
        assert!(!allow.allows(&h("openrouter.ai")));
        // Specifically: an empty allowlist is not "unrestricted".
        assert!(!allow.allows(&h("anything.example.com")));
    }

    #[test]
    fn allowlist_rejects_a_typo_instead_of_dropping_it() {
        let err = HostAllowlist::parse(&["openrouter.ai".into(), "bad host".into()]);
        assert_eq!(err, Err(HostError::Whitespace));
    }

    #[test]
    fn allowlist_dedupes_across_normalisation() {
        let allow = HostAllowlist::parse(&[
            "openrouter.ai".into(),
            "OPENROUTER.AI".into(),
            "openrouter.ai.".into(),
        ])
        .unwrap();
        assert_eq!(allow.iter().count(), 1);
    }

    #[test]
    fn label_and_total_length_limits() {
        let long_label = "a".repeat(64);
        assert_eq!(
            Host::parse(&format!("{long_label}.example.com")),
            Err(HostError::LabelTooLong)
        );
        let long_host = std::iter::repeat("abcdefgh")
            .take(40)
            .collect::<Vec<_>>()
            .join(".");
        assert_eq!(Host::parse(&long_host), Err(HostError::TooLong));
    }
}
