//! LoopsVault daemon.
//!
//! v1 transport: the explicit local endpoint. A project calls
//! `http://127.0.0.1:14322/openrouter/v1/chat/completions` instead of
//! `https://openrouter.ai/v1/chat/completions`, and the daemon writes the real
//! credential into the request on its way upstream.
//!
//! No CA certificate is created, installed, or trusted anywhere in v1. That is
//! Decision 1 as the founder settled it: both transports, endpoint first. The
//! opt-in MITM transport lands later and will call the same
//! `loopsvault_core::inject::decide`, never its own copy.

mod config;
mod proxy;
mod routes;
mod state;
mod store;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "loopsvaultd", version, about = "LoopsVault daemon")]
struct Args {
    /// Path to the daemon configuration.
    #[arg(long, default_value = "~/.loopsvault/config.json")]
    config: String,

    /// Address to bind. Loopback only by default, and changing it is how you
    /// turn a local credential broker into an open relay, so it is a flag you
    /// have to type rather than a default you inherit.
    #[arg(long, default_value = "127.0.0.1:14322")]
    bind: SocketAddr,
}

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(p)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let config_path = expand_tilde(&args.config);

    let cfg = config::Config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    // Validate the whole catalog before binding a port. A typo in a host should
    // stop the daemon starting, not silently narrow an allowlist at request
    // time when a credential is already in flight.
    cfg.catalog
        .validate()
        .context("catalog failed validation; refusing to start")?;

    let app_state = state::AppState::new(cfg).context("building daemon state")?;
    let app = routes::router(app_state);

    if !args.bind.ip().is_loopback() {
        tracing::warn!(
            bind = %args.bind,
            "binding to a non-loopback address; this daemon holds real credentials"
        );
    }

    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("binding {}", args.bind))?;

    tracing::info!(bind = %args.bind, "loopsvaultd listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
