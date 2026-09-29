//! The SCRAPI client: registering Signed Statements and collecting Receipts.
//!
//! [draft-ietf-scitt-scrapi-11] is the SCITT API a Transparency Service
//! speaks. This crate uses three of its resources:
//!
//! * `POST /entries` -- register a Signed Statement, sent as the request body
//!   with `Content-Type: application/cose`. `201` carries the Receipt;
//!   `202` means registration is still running and the `Location` header names
//!   where the Receipt will appear.
//! * `GET /entries/{entry_id}` -- resolve the Receipt: `200`, or `204` while
//!   registration runs, or `404`.
//! * `GET /.well-known/scitt-keys` -- the Receipt verification keys, as a COSE
//!   Key Set.
//!
//! [draft-ietf-scitt-scrapi-11]: https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11

use std::time::Duration;

use reqwest::header::{ACCEPT, CONTENT_TYPE, LOCATION};
use reqwest::{Client, StatusCode};
use tracing::Instrument as _;

use crate::errors::{Result, SignerError};

/// The media type a Signed Statement or Receipt is exchanged as.
pub const COSE_CONTENT_TYPE: &str = "application/cose";

/// The media type of a COSE Key Set.
pub const COSE_KEY_SET_CONTENT_TYPE: &str = "application/cbor";

/// How long to keep polling a Receipt that registration has not produced yet.
const RECEIPT_POLL_TIMEOUT: Duration = Duration::from_secs(30);
/// The pause between Receipt polls.
const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// What a registration produced.
#[derive(Debug, Clone)]
pub struct Registration {
    /// The EntryID, taken from the `Location` header's last path segment.
    pub entry_id: String,
    /// The Receipt resource's absolute URL.
    pub location: String,
    /// The Receipt. Empty only if the service answered `202` and never
    /// produced one within the client's poll window.
    pub receipt: Vec<u8>,
}

/// A SCRAPI client, bound to one Transparency Service.
#[derive(Debug, Clone)]
pub struct ScrapiClient {
    /// The HTTP client, shared across calls.
    http: Client,
    /// The service's base URL, with no trailing slash.
    base_url: String,
}

impl ScrapiClient {
    /// Build a client for the Transparency Service at `base_url`.
    ///
    /// # Errors
    ///
    /// [`SignerError::Scitt`] if `base_url` is not a usable URL or the HTTP
    /// client cannot be built.
    pub fn new(base_url: &str) -> Result<Self> {
        let base_url = base_url.trim_end_matches('/').to_string();
        if base_url.is_empty() {
            return Err(SignerError::Scitt {
                details: "the Transparency Service endpoint is empty".to_string(),
            });
        }
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| SignerError::Scitt {
                details: format!("the HTTP client could not be built: {error}"),
            })?;
        Ok(Self { http, base_url })
    }

    /// The service's base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Register a Signed Statement and return its Receipt.
    ///
    /// # Errors
    ///
    /// [`SignerError::Scitt`] for a transport failure, a status the draft does
    /// not define for this resource, or a `201` with no body.
    pub async fn register(&self, statement: &[u8]) -> Result<Registration> {
        let url = format!("{}/entries", self.base_url);
        let response = self
            .http
            .post(&url)
            .header(CONTENT_TYPE, COSE_CONTENT_TYPE)
            .header(ACCEPT, COSE_CONTENT_TYPE)
            .body(statement.to_vec())
            .send()
            .instrument(tracing::info_span!("scrapi_register"))
            .await
            .map_err(|error| SignerError::Scitt {
                details: format!("POST {url} failed: {error}"),
            })?;

        let status = response.status();
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| SignerError::Scitt {
                details: format!(
                    "POST {url} answered {status} with no Location header, \
                     so the Receipt cannot be resolved"
                ),
            })?;
        let entry_id = entry_id_from_location(&location).ok_or_else(|| SignerError::Scitt {
            details: format!("the Location header `{location}` names no entry"),
        })?;

        match status {
            // Section 2.3.1: the Receipt came back with the registration.
            StatusCode::CREATED => {
                let receipt = response.bytes().await.map_err(|error| SignerError::Scitt {
                    details: format!("the Receipt body of POST {url} could not be read: {error}"),
                })?;
                if receipt.is_empty() {
                    return Err(SignerError::Scitt {
                        details: format!("POST {url} answered 201 with an empty Receipt"),
                    });
                }
                Ok(Registration {
                    entry_id,
                    location,
                    receipt: receipt.to_vec(),
                })
            }
            // Section 2.3.2: accepted, no Receipt yet. The Location header
            // names where it will be, so poll that.
            StatusCode::ACCEPTED => {
                let receipt = self.await_receipt(&entry_id).await?;
                Ok(Registration {
                    entry_id,
                    location,
                    receipt,
                })
            }
            other => Err(SignerError::Scitt {
                details: format!(
                    "POST {url} answered {other}: {}",
                    concise_problem(response).await
                ),
            }),
        }
    }

    /// Fetch the Receipt at `/entries/{entry_id}`.
    ///
    /// # Errors
    ///
    /// [`SignerError::Scitt`] for a transport failure, or an answer that is
    /// neither `200` nor the `204` that means "still registering".
    pub async fn receipt(&self, entry_id: &str) -> Result<Option<Vec<u8>>> {
        let url = format!("{}/entries/{entry_id}", self.base_url);
        let response = self
            .http
            .get(&url)
            .header(ACCEPT, COSE_CONTENT_TYPE)
            .send()
            .instrument(tracing::info_span!("scrapi_receipt"))
            .await
            .map_err(|error| SignerError::Scitt {
                details: format!("GET {url} failed: {error}"),
            })?;

        match response.status() {
            StatusCode::OK => {
                let receipt = response.bytes().await.map_err(|error| SignerError::Scitt {
                    details: format!("the Receipt body of GET {url} could not be read: {error}"),
                })?;
                Ok(Some(receipt.to_vec()))
            }
            // Section 2.4.2: registration is still in progress.
            StatusCode::NO_CONTENT => Ok(None),
            other => Err(SignerError::Scitt {
                details: format!(
                    "GET {url} answered {other}: {}",
                    concise_problem(response).await
                ),
            }),
        }
    }

    /// Fetch the service's Receipt verification keys, as a COSE Key Set.
    ///
    /// # Errors
    ///
    /// [`SignerError::Scitt`] for a transport failure or a non-`200` answer.
    pub async fn receipt_keys(&self) -> Result<Vec<u8>> {
        let url = format!("{}/.well-known/scitt-keys", self.base_url);
        let response = self
            .http
            .get(&url)
            .header(ACCEPT, COSE_KEY_SET_CONTENT_TYPE)
            .send()
            .instrument(tracing::info_span!("scrapi_receipt_keys"))
            .await
            .map_err(|error| SignerError::Scitt {
                details: format!("GET {url} failed: {error}"),
            })?;

        if response.status() != StatusCode::OK {
            let status = response.status();
            return Err(SignerError::Scitt {
                details: format!(
                    "GET {url} answered {status}: {}",
                    concise_problem(response).await
                ),
            });
        }

        let keys = response.bytes().await.map_err(|error| SignerError::Scitt {
            details: format!("the key set body of GET {url} could not be read: {error}"),
        })?;
        Ok(keys.to_vec())
    }

    /// Poll `/entries/{entry_id}` until a Receipt appears or the window closes.
    async fn await_receipt(&self, entry_id: &str) -> Result<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + RECEIPT_POLL_TIMEOUT;
        loop {
            if let Some(receipt) = self.receipt(entry_id).await? {
                return Ok(receipt);
            }
            if tokio::time::Instant::now() >= deadline {
                // Not an error: the registration was accepted, and the caller
                // still has the EntryID to resolve later.
                tracing::warn!(
                    entry_id,
                    "the Transparency Service did not produce a Receipt within the poll window"
                );
                return Ok(Vec::new());
            }
            tokio::time::sleep(RECEIPT_POLL_INTERVAL).await;
        }
    }
}

/// The EntryID inside a Receipt `Location` header.
///
/// Section 2.4 of the draft makes the EntryID the last segment of the Receipt
/// resource's path, `/entries/{entry_id}`, and defines it as unpadded
/// base64url. The segment is taken as written rather than decoded and
/// re-encoded, so the identifier the service issued is the identifier this
/// crate reports back.
///
/// The `/entries/` prefix is required rather than inferred from the last
/// slash: a Location of `https://ts.example/entries` names the collection, and
/// reading `entries` as an identifier would produce a lookup for a receipt
/// that cannot exist.
#[must_use]
pub fn entry_id_from_location(location: &str) -> Option<String> {
    let path = location.split(['?', '#']).next()?;
    let (_, tail) = path.split_once("/entries/")?;
    let segment = tail.trim_end_matches('/');
    if segment.is_empty() || segment.contains('/') {
        None
    } else {
        Some(segment.to_string())
    }
}

/// Render a failed response's problem details for an error message, without
/// letting a large or binary body into a log line.
async fn concise_problem(response: reqwest::Response) -> String {
    let body = match response.text().await {
        Ok(body) => body,
        Err(error) => return format!("<body unreadable: {error}>"),
    };
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return "<no problem details>".to_string();
    }
    // RFC 9290 problem details are CBOR, so what arrives here is usually not
    // text at all. Show a little of it and say so rather than pretend.
    let printable: String = trimmed
        .chars()
        .take(200)
        .map(|c| if c.is_control() { '.' } else { c })
        .collect();
    printable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_id_is_the_last_path_segment() {
        assert_eq!(
            entry_id_from_location("http://127.0.0.1:8000/entries/6jZWRUsucVNM"),
            Some("6jZWRUsucVNM".to_string())
        );
        assert_eq!(
            entry_id_from_location("https://ts.example/entries/abc/"),
            Some("abc".to_string())
        );
        assert_eq!(
            entry_id_from_location("/entries/abc?x=1"),
            Some("abc".to_string())
        );
        assert_eq!(
            entry_id_from_location("http://127.0.0.1:8000/entries/6jZWRUsucVNM"),
            Some("6jZWRUsucVNM".to_string())
        );
        // The collection itself names no entry.
        assert_eq!(entry_id_from_location("https://ts.example/entries"), None);
        assert_eq!(entry_id_from_location("https://ts.example/entries/"), None);
        // A path that continues past the entry is not an EntryID either.
        assert_eq!(
            entry_id_from_location("https://ts.example/entries/abc/statement"),
            None
        );
    }

    #[test]
    fn an_empty_endpoint_is_refused() {
        let error = ScrapiClient::new("").expect_err("an empty endpoint is not usable");
        assert!(format!("{error}").contains("endpoint is empty"), "{error}");
    }

    #[test]
    fn a_trailing_slash_does_not_double_up_in_the_path() {
        let client = ScrapiClient::new("http://127.0.0.1:8000/").expect("builds");
        assert_eq!(client.base_url(), "http://127.0.0.1:8000");
    }
}
