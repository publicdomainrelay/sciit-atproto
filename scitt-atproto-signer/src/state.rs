//! The shared state a request handler reads.
//!
//! Built once at start-up: the configuration and a SCRAPI client bound to one
//! Transparency Service. Nothing here is mutated per request, and there is no
//! service identity -- every request mints its own. Handlers hold this behind
//! an `Arc` and generate their own keys.

use crate::config::Config;
use crate::errors::Result;
use crate::scitt::ScrapiClient;

/// Everything a handler needs, assembled once.
pub struct AppState {
    /// The configuration this process was started with.
    pub config: Config,
    /// The Transparency Service client.
    pub scrapi: ScrapiClient,
}

impl AppState {
    /// Build the state from a configuration.
    ///
    /// # Errors
    ///
    /// [`crate::errors::SignerError::Scitt`] if the endpoint is unusable.
    pub fn new(config: Config) -> Result<Self> {
        let scrapi = ScrapiClient::new(&config.scrapi_endpoint)?;
        Ok(Self { config, scrapi })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DEFAULT_NSID, DEFAULT_SUBJECT};

    fn config(endpoint: &str) -> Config {
        Config {
            scrapi_endpoint: endpoint.to_string(),
            bind: "127.0.0.1:0".to_string(),
            nsid: DEFAULT_NSID.to_string(),
            plc_directory: None,
            subject: DEFAULT_SUBJECT.to_string(),
            signature_type: crate::attestation::DEFAULT_SIGNATURE_TYPE.to_string(),
        }
    }

    #[test]
    fn the_endpoint_is_carried_into_the_client() {
        let state = AppState::new(config("http://127.0.0.1:8000/")).expect("builds");
        assert_eq!(state.scrapi.base_url(), "http://127.0.0.1:8000");
        assert_eq!(state.config.subject, DEFAULT_SUBJECT);
    }

    #[test]
    fn an_empty_endpoint_is_refused() {
        let error = match AppState::new(config("")) {
            Ok(_) => panic!("an empty endpoint must be refused"),
            Err(error) => error,
        };
        assert!(format!("{error}").contains("endpoint is empty"), "{error}");
    }
}
