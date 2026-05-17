use anyhow::Result;
use tracing_subscriber::EnvFilter;

mod cli;
mod client;
mod decoy;
mod dns;
mod server;
mod tls;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let cfg = cli::Config::from_env_and_args()?;
    tracing::info!(mode = ?cfg.mode, local = %cfg.local, remote = %cfg.remote, "dns-tunnel starting");

    match cfg.mode {
        cli::Mode::Client => client::run(cfg).await,
        cli::Mode::Server => server::run(cfg).await,
    }
}
