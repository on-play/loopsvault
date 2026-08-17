//! LoopsVault core.
//!
//! Everything here is transport-free on purpose. The daemon's HTTP layer, the
//! CLI, and the opt-in MITM transport that lands after v1 all call into this
//! crate rather than reimplementing any part of it.
//!
//! That is the first of the three constraints recorded with the founder's
//! decisions on 2026-08-17:
//!
//! 1. **One injection core, two transports.** Exact host matching is written
//!    once, in [`host`], and applied once, in [`inject`]. See `HANDOFF.md` 11.
//! 2. **The master key unwrapper is pluggable from the first commit.** v1 uses
//!    a file-based unwrapper because the Secure Enclave is v2 work. See
//!    [`unwrap`].
//! 3. **The break-glass export format is designed in v1.** A store written by
//!    v1 must still be recoverable after the Enclave lands, because
//!    `biometryCurrentSet` permanently locks items when a fingerprint or the
//!    machine password changes.
//!
//! The one rule that outranks the rest: an agent receives a *reference*, never
//! a value, never ciphertext, and never a decryption key.

pub mod catalog;
pub mod host;
pub mod inject;
pub mod meter;
pub mod project;
pub mod secret;
pub mod unwrap;

pub use catalog::{Catalog, CatalogEntry, Classification, Placement};
pub use host::{Host, HostAllowlist, HostError};
pub use inject::{decide, Denial, Injection, InjectionRequest};
pub use meter::{attribute, Attribution, PriceTable, Usage};
pub use project::{ProjectId, ProjectRegistry, ProjectToken};
pub use secret::{CharClass, SecretValue, Shape};
