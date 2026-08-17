//! The secret value type.
//!
//! This is the concrete reason the handoff chose Rust over a GC'd language, and
//! it is worth being precise about what it buys:
//!
//! - `Debug` and `Display` refuse to print the value, so a secret cannot reach
//!   a log line through the usual accident of `tracing::info!("{req:?}")`.
//!   That is a **compile-time** guarantee about formatting, not a convention
//!   somebody has to remember.
//! - `Drop` zeroes the bytes, so the value does not sit in freed memory waiting
//!   for a collector that has no destructors.
//! - `Serialize` is not implemented at all. A secret cannot be turned into JSON
//!   by accident, which is how it would otherwise reach an audit record.
//!
//! What it does **not** buy: protection from root, from a debugger, or from a
//! caller that deliberately calls `expose()`. The point is to make the leak
//! deliberate and greppable rather than accidental and invisible.

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A credential value. Never printed, never serialised, zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue {
    inner: String,
}

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        SecretValue {
            inner: value.into(),
        }
    }

    /// Read the value.
    ///
    /// Named `expose` rather than `get` or `as_str` so that every place a
    /// secret leaves its wrapper is one grep away. Call this as late as
    /// possible, ideally at the moment the byte goes on the wire.
    pub fn expose(&self) -> &str {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// A non-revealing fingerprint, safe for the catalog and for logs. This is
    /// the same shape the `env-keys.sh --shape` tool reports, deliberately: an
    /// agent can validate a credential's plausibility without seeing a
    /// character of it, and not even a prefix leaks, because a prefix is still
    /// part of the secret.
    pub fn shape(&self) -> Shape {
        Shape {
            len: self.inner.len(),
            class: CharClass::of(&self.inner),
        }
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue(<redacted {} bytes>)", self.inner.len())
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CharClass {
    Empty,
    Digits,
    HexLower,
    HexUpper,
    Token,
    Base64ish,
    Url,
    Mixed,
}

impl CharClass {
    pub fn of(s: &str) -> CharClass {
        if s.is_empty() {
            return CharClass::Empty;
        }
        if s.starts_with("http://")
            || s.starts_with("https://")
            || s.starts_with("postgres://")
            || s.starts_with("postgresql://")
            || s.starts_with("redis://")
            || s.starts_with("mysql://")
            || s.starts_with("mongodb://")
        {
            return CharClass::Url;
        }
        if s.bytes().all(|b| b.is_ascii_digit()) {
            return CharClass::Digits;
        }
        if s.bytes().all(|b| b.is_ascii_hexdigit()) {
            if s.bytes().all(|b| !b.is_ascii_uppercase()) {
                return CharClass::HexLower;
            }
            if s.bytes().all(|b| !b.is_ascii_lowercase()) {
                return CharClass::HexUpper;
            }
        }
        if s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return CharClass::Token;
        }
        if s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        {
            return CharClass::Base64ish;
        }
        CharClass::Mixed
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Shape {
    pub len: usize,
    pub class: CharClass,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// If this test ever fails, a secret is one `{:?}` away from a log file.
    #[test]
    fn debug_and_display_never_reveal() {
        let s = SecretValue::new("FAKE-sk-or-v1-abc123");
        let dbg = format!("{s:?}");
        let disp = format!("{s}");
        assert!(!dbg.contains("FAKE-sk"), "Debug leaked: {dbg}");
        assert!(!disp.contains("FAKE-sk"), "Display leaked: {disp}");
        assert!(dbg.contains("redacted"));
        assert!(disp.contains("redacted"));
    }

    /// Nesting is where this usually goes wrong: the wrapper is careful, and
    /// then someone derives Debug on the struct that holds it.
    #[test]
    fn nested_debug_never_reveals() {
        #[derive(Debug)]
        struct Request {
            host: String,
            credential: SecretValue,
        }
        let r = Request {
            host: "openrouter.ai".into(),
            credential: SecretValue::new("FAKE-sk-or-v1-abc123"),
        };
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("FAKE-sk"), "nested Debug leaked: {dbg}");
        assert!(dbg.contains("openrouter.ai"), "should still be useful: {dbg}");
    }

    #[test]
    fn expose_is_the_only_way_out() {
        let s = SecretValue::new("value");
        assert_eq!(s.expose(), "value");
    }

    #[test]
    fn shape_describes_without_revealing() {
        let s = SecretValue::new("FAKE-sk-or-v1-abc123");
        let shape = s.shape();
        assert_eq!(shape.len, 20);
        assert_eq!(shape.class, CharClass::Token);

        let json = serde_json::to_string(&shape).unwrap();
        assert!(!json.contains("FAKE"), "shape must not carry content: {json}");
    }

    #[test]
    fn char_classes() {
        assert_eq!(CharClass::of(""), CharClass::Empty);
        assert_eq!(CharClass::of("3000"), CharClass::Digits);
        assert_eq!(CharClass::of("deadbeef"), CharClass::HexLower);
        assert_eq!(CharClass::of("DEADBEEF"), CharClass::HexUpper);
        assert_eq!(CharClass::of("sk-or-v1_x"), CharClass::Token);
        assert_eq!(CharClass::of("postgres://u:p@h/db"), CharClass::Url);
        assert_eq!(CharClass::of("a+b/c="), CharClass::Base64ish);
        assert_eq!(CharClass::of("has space"), CharClass::Mixed);
    }
}
