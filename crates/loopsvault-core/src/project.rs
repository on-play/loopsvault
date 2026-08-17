//! Per-project identity.
//!
//! **Project identity is cryptographic, not a self-declared string.** This is
//! the sentence in the handoff that everything about attribution and spend caps
//! rests on. If a transport ever took the project name from a header the caller
//! filled in, then per-project cost tables and per-project caps become advisory:
//! any agent could bill its spend to another project, or borrow another
//! project's credential scope, by typing a different name.
//!
//! So a caller presents a token, and the daemon decides which project that
//! token means. The caller never names the project.
//!
//! The registry stores a SHA-256 of each token rather than the token itself, so
//! a leaked registry file does not hand over working credentials, and lookup is
//! constant-time so a caller cannot learn a valid token by measuring how long a
//! wrong one takes to reject.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::secret::SecretValue;

/// A project name, as it appears in a catalog entry's `projects[]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProjectId(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProjectError {
    #[error("project name is empty")]
    Empty,
    #[error("project name is longer than 128 characters")]
    TooLong,
    #[error("project name contains a character that is not allowed: {0:?}")]
    InvalidChar(char),
}

impl ProjectId {
    /// Project names come from directory names under `~/Projects`, which in
    /// practice include dots (`42flows.com`, `SoundWaves.fm`) and mixed case
    /// (`PitchPlus`). Case is preserved rather than folded, because
    /// `PitchPlus` and `pitchplus_fast` are two different projects on this
    /// machine and folding invites exactly that confusion.
    pub fn parse(raw: &str) -> Result<Self, ProjectError> {
        if raw.is_empty() {
            return Err(ProjectError::Empty);
        }
        if raw.len() > 128 {
            return Err(ProjectError::TooLong);
        }
        for c in raw.chars() {
            if !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
                return Err(ProjectError::InvalidChar(c));
            }
        }
        Ok(ProjectId(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

const TOKEN_PREFIX: &str = "lvp_";
const TOKEN_BYTES: usize = 32;

/// The bearer token one project presents to the daemon.
///
/// Opaque: it carries no project name. A token that spelled out its project
/// would leak which projects exist to anyone who saw one in a process list.
#[derive(Clone)]
pub struct ProjectToken(SecretValue);

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token does not start with {TOKEN_PREFIX}")]
    BadPrefix,
    #[error("token body is not {} hex characters", TOKEN_BYTES * 2)]
    BadLength,
    #[error("token body is not hexadecimal")]
    NotHex,
    #[error("could not read system randomness: {0}")]
    Randomness(String),
}

impl ProjectToken {
    pub fn generate() -> Result<Self, TokenError> {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom::getrandom(&mut bytes).map_err(|e| TokenError::Randomness(e.to_string()))?;
        let mut s = String::with_capacity(TOKEN_PREFIX.len() + TOKEN_BYTES * 2);
        s.push_str(TOKEN_PREFIX);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        Ok(ProjectToken(SecretValue::new(s)))
    }

    pub fn parse(raw: &str) -> Result<Self, TokenError> {
        let body = raw.strip_prefix(TOKEN_PREFIX).ok_or(TokenError::BadPrefix)?;
        if body.len() != TOKEN_BYTES * 2 {
            return Err(TokenError::BadLength);
        }
        if !body.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(TokenError::NotHex);
        }
        Ok(ProjectToken(SecretValue::new(raw)))
    }

    /// The value, for the one moment it is handed to the project that owns it.
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    pub fn fingerprint(&self) -> TokenFingerprint {
        let mut h = Sha256::new();
        h.update(self.0.expose().as_bytes());
        let out = h.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out);
        TokenFingerprint(bytes)
    }
}

impl std::fmt::Debug for ProjectToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A token is a credential. Same rule as SecretValue.
        f.write_str("ProjectToken(<redacted>)")
    }
}

/// SHA-256 of a token. This is what the registry persists.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFingerprint(#[serde(with = "hex_bytes")] [u8; 32]);

impl std::fmt::Debug for TokenFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Safe to show: it is a hash, and showing the first bytes makes audit
        // records correlatable without being reversible.
        write!(f, "TokenFingerprint({:02x}{:02x}{:02x}{:02x}..)",
            self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(64);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(out, "{b:02x}");
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 64 {
            return Err(serde::de::Error::custom("fingerprint must be 64 hex chars"));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).ok_or_else(|| serde::de::Error::custom("not hex"))?;
            let lo = (chunk[1] as char).to_digit(16).ok_or_else(|| serde::de::Error::custom("not hex"))?;
            out[i] = ((hi << 4) | lo) as u8;
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectRecord {
    pub project: ProjectId,
    pub fingerprint: TokenFingerprint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Token to project. Holds no usable token.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProjectRegistry {
    #[serde(default)]
    pub records: Vec<ProjectRecord>,
}

impl ProjectRegistry {
    pub fn issue(&mut self, project: ProjectId) -> Result<ProjectToken, TokenError> {
        let token = ProjectToken::generate()?;
        let fingerprint = token.fingerprint();
        self.records.retain(|r| r.project != project);
        self.records.push(ProjectRecord {
            project,
            fingerprint,
            note: None,
        });
        Ok(token)
    }

    /// Resolve a presented token to a project.
    ///
    /// Constant-time with respect to which record matches: every record is
    /// compared and the result is accumulated, with no early return. An
    /// early-exit loop leaks, through timing, how many leading records failed,
    /// which over many attempts is enough to walk a valid token out of the
    /// daemon.
    pub fn resolve(&self, token: &ProjectToken) -> Option<&ProjectId> {
        let want = token.fingerprint();
        let mut found: Option<&ProjectId> = None;
        for r in &self.records {
            let hit: bool = r.fingerprint.0.ct_eq(&want.0).into();
            if hit {
                found = Some(&r.project);
            }
        }
        found
    }

    pub fn revoke(&mut self, project: &ProjectId) -> bool {
        let before = self.records.len();
        self.records.retain(|r| &r.project != project);
        self.records.len() != before
    }

    pub fn projects(&self) -> Vec<&ProjectId> {
        self.records.iter().map(|r| &r.project).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_resolves_only_to_its_own_project() {
        let mut reg = ProjectRegistry::default();
        let a = reg.issue(ProjectId::parse("pitchplus_fast").unwrap()).unwrap();
        let b = reg.issue(ProjectId::parse("42flows.com").unwrap()).unwrap();

        assert_eq!(reg.resolve(&a).unwrap().as_str(), "pitchplus_fast");
        assert_eq!(reg.resolve(&b).unwrap().as_str(), "42flows.com");

        let stranger = ProjectToken::generate().unwrap();
        assert!(reg.resolve(&stranger).is_none());
    }

    /// The property the whole attribution story depends on: a caller cannot
    /// claim to be a project, it can only present a token.
    #[test]
    fn a_project_name_alone_grants_nothing() {
        let mut reg = ProjectRegistry::default();
        let _ = reg.issue(ProjectId::parse("pitchplus_fast").unwrap()).unwrap();

        // There is deliberately no API that takes a project name and returns
        // an identity. The only way in is resolve(&ProjectToken), and a token
        // cannot be built from a name.
        let forged = ProjectToken::parse("lvp_pitchplus_fast");
        assert!(forged.is_err(), "a name must not parse as a token");
    }

    #[test]
    fn the_registry_persists_no_usable_token() {
        let mut reg = ProjectRegistry::default();
        let token = reg.issue(ProjectId::parse("pitchplus_fast").unwrap()).unwrap();
        let json = serde_json::to_string(&reg).unwrap();

        assert!(json.contains("pitchplus_fast"));
        assert!(
            !json.contains(token.expose()),
            "registry must not contain the token itself"
        );

        // And it still works after a round trip.
        let back: ProjectRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.resolve(&token).unwrap().as_str(), "pitchplus_fast");
    }

    #[test]
    fn tokens_are_redacted_in_debug() {
        let t = ProjectToken::generate().unwrap();
        let dbg = format!("{t:?}");
        assert!(!dbg.contains(t.expose()), "Debug leaked a token: {dbg}");
    }

    #[test]
    fn token_format_is_validated() {
        assert!(matches!(ProjectToken::parse("nope"), Err(TokenError::BadPrefix)));
        assert!(matches!(ProjectToken::parse("lvp_abc"), Err(TokenError::BadLength)));
        let nonhex = format!("lvp_{}", "z".repeat(64));
        assert!(matches!(ProjectToken::parse(&nonhex), Err(TokenError::NotHex)));

        let good = ProjectToken::generate().unwrap();
        assert!(ProjectToken::parse(good.expose()).is_ok());
    }

    #[test]
    fn generated_tokens_do_not_repeat() {
        let a = ProjectToken::generate().unwrap();
        let b = ProjectToken::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn revoking_a_project_invalidates_its_token() {
        let mut reg = ProjectRegistry::default();
        let id = ProjectId::parse("pitchplus_fast").unwrap();
        let t = reg.issue(id.clone()).unwrap();
        assert!(reg.resolve(&t).is_some());
        assert!(reg.revoke(&id));
        assert!(reg.resolve(&t).is_none());
    }

    /// Re-issuing replaces rather than accumulates, so an old token stops
    /// working the moment a new one is handed out.
    #[test]
    fn reissuing_replaces_the_old_token() {
        let mut reg = ProjectRegistry::default();
        let id = ProjectId::parse("pitchplus_fast").unwrap();
        let old = reg.issue(id.clone()).unwrap();
        let new = reg.issue(id.clone()).unwrap();
        assert!(reg.resolve(&old).is_none(), "old token must stop working");
        assert!(reg.resolve(&new).is_some());
        assert_eq!(reg.records.len(), 1);
    }

    #[test]
    fn project_names_match_this_machines_directories() {
        assert!(ProjectId::parse("42flows.com").is_ok());
        assert!(ProjectId::parse("SoundWaves.fm").is_ok());
        assert!(ProjectId::parse("pitchplus_fast").is_ok());
        assert!(ProjectId::parse("daily.goforce").is_ok());
        assert_eq!(ProjectId::parse(""), Err(ProjectError::Empty));
        assert_eq!(
            ProjectId::parse("has space"),
            Err(ProjectError::InvalidChar(' '))
        );
        assert_eq!(
            ProjectId::parse("../escape"),
            Err(ProjectError::InvalidChar('/'))
        );
    }
}
