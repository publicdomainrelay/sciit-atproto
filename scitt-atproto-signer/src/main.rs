//! The `scitt-atproto-signer` server.
//!
//! Reads its configuration from the environment and serves the `sign` XRPC
//! method. It holds no identity of its own: every request mints one. Every
//! setting is listed in `--help`.

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use scitt_atproto_signer::config::{
    Config, DEFAULT_BIND, DEFAULT_NSID, DEFAULT_SIGNATURE_TYPE, DEFAULT_SUBJECT, ENV_BIND,
    ENV_NSID, ENV_PLC_DIRECTORY, ENV_SCRAPI_ENDPOINT, ENV_SIGNATURE_TYPE, ENV_SUBJECT,
};
use scitt_atproto_signer::{AppState, xrpc};
use tracing_subscriber::EnvFilter;

/// An AT Protocol XRPC service that registers SCITT Signed Statements.
#[derive(Parser, Debug)]
#[command(
    name = "scitt-atproto-signer",
    version,
    about = "Sign an XRPC request body into a SCITT Transparent Statement and a badge.blue inline attestation",
    long_about = None,
)]
struct Args {
    /// The SCITT Transparency Service to register statements with.
    #[arg(long, env = ENV_SCRAPI_ENDPOINT)]
    scrapi_endpoint: Option<String>,

    /// The address to listen on.
    #[arg(long, env = ENV_BIND, default_value = DEFAULT_BIND)]
    bind: String,

    /// The XRPC NSID this service answers at.
    #[arg(long, env = ENV_NSID, default_value = DEFAULT_NSID)]
    nsid: String,

    /// Publish each request's `did:plc` to this directory. Omit to leave the
    /// DID resolvable by nobody but the caller holding the response.
    #[arg(long, env = ENV_PLC_DIRECTORY)]
    plc_directory: Option<String>,

    /// The default `sub` claim of a Signed Statement.
    #[arg(long, env = ENV_SUBJECT, default_value = DEFAULT_SUBJECT)]
    subject: String,

    /// The `$type` of the badge.blue inline signature record.
    #[arg(long, env = ENV_SIGNATURE_TYPE, default_value = DEFAULT_SIGNATURE_TYPE)]
    signature_type: String,
}

impl Args {
    /// Fold the parsed arguments into the configuration the library takes.
    fn into_config(self) -> Config {
        Config {
            scrapi_endpoint: self.scrapi_endpoint.unwrap_or_default(),
            bind: self.bind,
            nsid: self.nsid,
            plc_directory: self.plc_directory,
            subject: self.subject,
            signature_type: self.signature_type,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let mut config = Args::parse().into_config();
    if config.scrapi_endpoint.trim().is_empty() {
        // Fall back to the environment so `--help` works without the variable
        // set, and a missing endpoint is reported by the one code path that
        // owns that error.
        config.scrapi_endpoint = std::env::var(ENV_SCRAPI_ENDPOINT).unwrap_or_default();
    }

    match run(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "the service stopped");
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Build the state, bind, and serve until interrupted.
async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(AppState::new(config.clone())?);

    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    let address = listener.local_addr()?;
    tracing::info!(
        address = %address,
        method = config.nsid.as_str(),
        scrapi = config.scrapi_endpoint.as_str(),
        plc_directory = config.plc_directory.as_deref().unwrap_or("<not publishing>"),
        "listening"
    );

    axum::serve(listener, xrpc::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Resolve on SIGINT or SIGTERM, so a container stop is a clean one.
async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::warn!(%error, "SIGTERM cannot be handled; stopping on SIGINT only");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => tracing::info!("interrupted"),
        () = terminate => tracing::info!("terminated"),
    }
}
