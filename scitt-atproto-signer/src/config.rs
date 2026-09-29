//! Service configuration, read from the environment.
//!
//! Every setting has an environment variable and a default that works on a
//! loopback-only development machine, except the Transparency Service
//! endpoint -- there is no sensible default for where to register statements,
//! and guessing one would send them somewhere unexpected.
//!
//! # Why the reader is a parameter
//!
//! [`Config::from_env`] is the only caller of the process environment. The
//! parsing lives in [`Config::from_lookup`], which takes a function, so the
//! rules are tested against a map rather than by mutating a process-wide
//! environment that other tests in the same binary share.

use std::env;

use crate::errors::{Result, SignerError};

pub use crate::attestation::DEFAULT_SIGNATURE_TYPE;

/// The Transparency Service endpoint's variable.
pub const ENV_SCRAPI_ENDPOINT: &str = "SCITT_SCRAPI_ENDPOINT";
/// The listen address's variable.
pub const ENV_BIND: &str = "SCITT_XRPC_BIND";
/// The XRPC method NSID's variable.
pub const ENV_NSID: &str = "SCITT_XRPC_NSID";
/// The PLC directory's variable.
pub const ENV_PLC_DIRECTORY: &str = "SCITT_PLC_DIRECTORY";
/// The statement subject's variable.
pub const ENV_SUBJECT: &str = "SCITT_SUBJECT";
/// The inline signature `$type`'s variable.
pub const ENV_SIGNATURE_TYPE: &str = "SCITT_SIGNATURE_TYPE";

/// The default XRPC method NSID.
pub const DEFAULT_NSID: &str = "blue.scitt.sign";
/// The default listen address.
pub const DEFAULT_BIND: &str = "127.0.0.1:8787";
/// The default statement subject.
pub const DEFAULT_SUBJECT: &str = "scitt-atproto-signer";

/// Every setting this service has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Where to register Signed Statements.
    pub scrapi_endpoint: String,
    /// What to listen on.
    pub bind: String,
    /// The NSID this service answers at.
    pub nsid: String,
    /// The PLC directory to publish each per-request DID to, if any.
    pub plc_directory: Option<String>,
    /// The default `sub` claim of a Signed Statement.
    pub subject: String,
    /// The `$type` of the badge.blue inline signature record.
    pub signature_type: String,
}

impl Config {
    /// Read the configuration from the process environment.
    ///
    /// # Errors
    ///
    /// [`SignerError::Request`] if `SCITT_SCRAPI_ENDPOINT` is unset or empty,
    /// which is the one setting with no default.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| env::var(name).ok())
    }

    /// Read the configuration from `lookup`.
    ///
    /// # Errors
    ///
    /// As [`Config::from_env`].
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        // A shell export commonly carries a trailing newline, and a variable
        // set to spaces is a variable somebody meant to leave unset. Both are
        // trimmed, and an empty result counts as absent.
        let get = |name: &str| {
            lookup(name)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };

        let scrapi_endpoint = get(ENV_SCRAPI_ENDPOINT).ok_or(SignerError::Request {
            details: format!(
                "{ENV_SCRAPI_ENDPOINT} is not set, and the Transparency Service endpoint has no default"
            ),
        })?;

        Ok(Self {
            scrapi_endpoint,
            bind: get(ENV_BIND).unwrap_or_else(|| DEFAULT_BIND.to_string()),
            nsid: get(ENV_NSID).unwrap_or_else(|| DEFAULT_NSID.to_string()),
            plc_directory: get(ENV_PLC_DIRECTORY),
            subject: get(ENV_SUBJECT).unwrap_or_else(|| DEFAULT_SUBJECT.to_string()),
            signature_type: get(ENV_SIGNATURE_TYPE)
                .unwrap_or_else(|| DEFAULT_SIGNATURE_TYPE.to_string()),
        })
    }

    /// The same configuration, with the endpoint replaced.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.scrapi_endpoint = endpoint.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lookup over a fixed set of pairs, including the `None` case that a
    /// typed map cannot express.
    fn lookup_for<'a>(
        pairs: &'a [(&'a str, Option<&'a str>)],
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .and_then(|(_, value)| value.map(str::to_string))
        }
    }

    #[test]
    fn an_unset_endpoint_is_an_error_naming_the_variable() {
        let error = Config::from_lookup(lookup_for(&[])).expect_err("a missing endpoint must fail");
        assert!(format!("{error}").contains(ENV_SCRAPI_ENDPOINT), "{error}");
    }

    /// A variable exported as spaces, or with a trailing newline and nothing
    /// else, is a variable somebody meant to leave unset.
    #[test]
    fn a_blank_endpoint_counts_as_unset() {
        for blank in ["", "   ", "\n"] {
            let error = Config::from_lookup(lookup_for(&[(ENV_SCRAPI_ENDPOINT, Some(blank))]))
                .expect_err("a blank endpoint must fail");
            assert!(format!("{error}").contains(ENV_SCRAPI_ENDPOINT), "{error}");
        }
    }

    #[test]
    fn the_defaults_are_the_documented_ones() {
        let config = Config::from_lookup(lookup_for(&[(
            ENV_SCRAPI_ENDPOINT,
            Some("http://127.0.0.1:8000"),
        )]))
        .expect("builds");

        assert_eq!(config.bind, DEFAULT_BIND);
        assert_eq!(config.nsid, DEFAULT_NSID);
        assert_eq!(config.subject, DEFAULT_SUBJECT);
        assert_eq!(config.signature_type, DEFAULT_SIGNATURE_TYPE);
        assert_eq!(config.plc_directory, None);
    }

    #[test]
    fn values_are_trimmed() {
        let config = Config::from_lookup(lookup_for(&[
            (ENV_SCRAPI_ENDPOINT, Some(" http://ts.example\n")),
            (ENV_BIND, Some(" 0.0.0.0:9000 ")),
            (ENV_SUBJECT, Some(" a-subject ")),
        ]))
        .expect("builds");

        assert_eq!(config.scrapi_endpoint, "http://ts.example");
        assert_eq!(config.bind, "0.0.0.0:9000");
        assert_eq!(config.subject, "a-subject");
    }

    #[test]
    fn every_setting_is_read_when_it_is_set() {
        let config = Config::from_lookup(lookup_for(&[
            (ENV_SCRAPI_ENDPOINT, Some("http://ts.example")),
            (ENV_BIND, Some("0.0.0.0:1")),
            (ENV_NSID, Some("com.example.sign")),
            (ENV_PLC_DIRECTORY, Some("plc.directory")),
            (ENV_SUBJECT, Some("a-subject")),
            (ENV_SIGNATURE_TYPE, Some("com.example.inlineSignature")),
        ]))
        .expect("builds");

        assert_eq!(config.bind, "0.0.0.0:1");
        assert_eq!(config.nsid, "com.example.sign");
        assert_eq!(config.plc_directory.as_deref(), Some("plc.directory"));
        assert_eq!(config.subject, "a-subject");
        assert_eq!(config.signature_type, "com.example.inlineSignature");
    }

    /// `from_env` must be the thin wrapper it claims to be, reading the real
    /// process environment. Asserted against a variable the test sets through
    /// the lookup it is a wrapper for, so nothing here mutates the process.
    #[test]
    fn from_env_reads_the_process_environment() {
        // The endpoint is unset in this test binary, so `from_env` reports the
        // same error `from_lookup` does for an absent variable.
        if env::var(ENV_SCRAPI_ENDPOINT).is_err() {
            let error = Config::from_env().expect_err("unset in this environment");
            assert!(format!("{error}").contains(ENV_SCRAPI_ENDPOINT), "{error}");
        }
    }
}
