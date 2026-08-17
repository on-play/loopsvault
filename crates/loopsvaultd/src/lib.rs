//! LoopsVault daemon, as a library.
//!
//! The binary is a thin `main` over this, so integration tests can drive the
//! real router and the real store rather than a mock of them. The end-to-end
//! test in `tests/e2e.rs` is the one that proves the central claim of this
//! project, so it needs the real thing.

pub mod config;
pub mod proxy;
pub mod routes;
pub mod state;
pub mod store;
