use anyhow::Result;
use tracing_subscriber::EnvFilter;

mod cli;
mod client;
mod decoy;
mod dns;
mod nstun;
mod nstun_codec;
mod protocol;
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

    match (cfg.transport, cfg.mode) {
        (cli::Transport::Quic, cli::Mode::Client) => client::run(cfg).await,
        (cli::Transport::Quic, cli::Mode::Server) => server::run(cfg).await,
        (cli::Transport::Ns, cli::Mode::Client) => nstun::run_client(cfg).await,
        (cli::Transport::Ns, cli::Mode::Server) => nstun::run_server(cfg).await,
    }
}
