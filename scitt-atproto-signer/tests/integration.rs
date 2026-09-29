//! End-to-end tests against a real SCITT API Emulator.
//!
//! The unit tests in `src/` check that this crate is self-consistent. These
//! check that it is *right*, which is a different claim: the emulator is
//! somebody else's implementation of [SCRAPI], reading the same drafts, and
//! this service has to satisfy it.
//!
//! # What has to be true for these to run
//!
//! A Python environment with the emulator installed, created by
//! `scripts/setup-emulator.sh`. When that environment is absent the tests
//! report that and pass, because it is an external prerequisite that a
//! `cargo test` on a machine without Python cannot satisfy -- the alternative
//! is a red suite that says nothing about the code. Everything *after* the
//! environment is found is a hard assertion.
//!
//! [SCRAPI]: https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::post;
use scitt_atproto_signer::config::{Config, DEFAULT_NSID, DEFAULT_SIGNATURE_TYPE, DEFAULT_SUBJECT};
use scitt_atproto_signer::state::AppState;
use serde_json::Value;

/// How long to wait for a child process to answer before calling it a failure.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// The Python interpreter with the emulator installed, if there is one.
///
/// `SCITT_TEST_PYTHON` overrides the search, for a machine keeping the
/// environment somewhere else.
fn emulator_python() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("SCITT_TEST_PYTHON") {
        let path = PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }
    let candidate = crate_dir().join(".emulator-venv/bin/python");
    candidate.is_file().then_some(candidate)
}

/// The crate's own directory, which is where `cargo` runs a test from.
fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A port nothing is listening on.
///
/// The listener is bound and dropped, so the port is free at the moment it is
/// chosen and could in principle be taken before the child binds it. A fixed
/// port would be worse: it collides with whatever the developer already has
/// running, and the failure then looks like a bug in this crate.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    listener.local_addr().expect("an address").port()
}

/// A SCITT API Emulator, killed when this is dropped.
struct Emulator {
    child: Child,
    base_url: String,
    _workspace: TempDir,
}

impl Emulator {
    /// Start the emulator on a free port with an empty workspace.
    ///
    /// `verify_signature` turns on the registration-time signature check of
    /// RFC 9943 Section6.3, which is off by default in the emulator for
    /// interoperability testing. Turning it on is the point of one test here:
    /// it is the only way to learn whether the statement this service
    /// produces is one a Transparency Service can actually verify.
    async fn start(python: &Path, verify_signature: bool) -> Self {
        let workspace = TempDir::new("emulator-workspace");
        let port = free_port();

        let mut command = Command::new(python);
        command
            .arg(crate_dir().join("scripts/run-emulator.py"))
            .arg(workspace.path())
            .arg(port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if verify_signature {
            command.arg("--verify-signature");
        }
        let child = command.spawn().expect("the emulator starts");

        let base_url = format!("http://127.0.0.1:{port}");
        let emulator = Self {
            child,
            base_url,
            _workspace: workspace,
        };
        emulator.await_ready().await;
        emulator
    }

    /// Poll `/.well-known/scitt-keys` until the emulator answers.
    async fn await_ready(&self) {
        let client = reqwest::Client::new();
        let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
        let url = format!("{}/.well-known/scitt-keys", self.base_url);
        while tokio::time::Instant::now() < deadline {
            if let Ok(response) = client.get(&url).send().await
                && response.status().is_success()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the emulator did not answer at {url} within {STARTUP_TIMEOUT:?}");
    }
}

impl Drop for Emulator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A directory removed when this is dropped.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        // The process id keeps two concurrent test binaries apart; the counter
        // keeps two tests in one binary apart.
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);

        let path = std::env::temp_dir().join(format!(
            "scitt-atproto-signer-{prefix}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temporary directory");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// This service, serving on a free port, stopped when this is dropped.
struct Signer {
    base_url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Signer {
    /// Build the service against `scrapi_endpoint` and serve it.
    async fn start(scrapi_endpoint: &str, extra: impl FnOnce(&mut Config)) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let address = listener.local_addr().expect("an address");

        let mut config = Config {
            scrapi_endpoint: scrapi_endpoint.to_string(),
            bind: address.to_string(),
            nsid: DEFAULT_NSID.to_string(),
            plc_directory: None,
            subject: DEFAULT_SUBJECT.to_string(),
            signature_type: DEFAULT_SIGNATURE_TYPE.to_string(),
        };
        extra(&mut config);

        let state = Arc::new(AppState::new(config).expect("the service starts"));
        let router = scitt_atproto_signer::xrpc::router(state);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        Self {
            base_url: format!("http://{address}"),
            handle,
        }
    }

    /// The method's URL.
    fn sign_url(&self) -> String {
        format!("{}/xrpc/{DEFAULT_NSID}", self.base_url)
    }
}

impl Drop for Signer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// A record to attest to.
fn body() -> &'static str {
    r#"{"$type":"app.bsky.feed.post","text":"hello scitt","createdAt":"2026-09-28T00:00:00.000Z"}"#
}

/// Call `sign` and return the parsed answer.
async fn sign(signer: &Signer, body: &str) -> Value {
    let response = reqwest::Client::new()
        .post(signer.sign_url())
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .expect("the request is sent");
    let status = response.status();
    let text = response.text().await.expect("a body");
    assert!(status.is_success(), "sign returned {status}: {text}");
    serde_json::from_str(&text).expect("the answer is JSON")
}

/// Decode unpadded base64url, as the response encodes binary artefacts.
fn decode(value: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in value.bytes() {
        let digit = ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .unwrap_or_else(|| panic!("{byte:?} is not base64url")) as u32;
        buffer = (buffer << 6) | digit;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

/// The message a skipped test prints, so a green run is not mistaken for a run
/// that checked anything.
fn skip(reason: &str) {
    eprintln!("SKIPPED: {reason}");
}

#[tokio::test]
async fn the_sign_method_returns_an_inline_signature_and_a_transparent_statement() {
    let Some(python) = emulator_python() else {
        return skip("no emulator environment; run scripts/setup-emulator.sh");
    };
    let emulator = Emulator::start(&python, false).await;
    let signer = Signer::start(&emulator.base_url, |_| {}).await;

    let answer = sign(&signer, body()).await;

    // The inline signature: a badge.blue attestation over the body.
    let inline = &answer["inlineSignature"];
    assert_eq!(inline["$type"], DEFAULT_SIGNATURE_TYPE);
    assert!(
        inline["cid"]
            .as_str()
            .expect("a cid")
            .starts_with("bafyrei")
    );
    assert!(inline["signature"]["$bytes"].is_string());
    // Issued by the DID minted for this request, and naming that DID's own
    // verification method -- so resolving the issuer yields the key.
    let did = answer["did"].as_str().expect("a did");
    assert_eq!(inline["issuer"], did);
    // The key is a did:key rather than a reference into the DID document, so
    // the signature is checkable with no directory and no network. It is the
    // key the DID document publishes, which is what ties the two together.
    assert_eq!(inline["key"], answer["statement"]["didKey"]);
    assert_eq!(
        answer["didDocument"]["verificationMethod"][0]["publicKeyMultibase"],
        inline["key"]
            .as_str()
            .expect("a did:key")
            .trim_start_matches("did:key:")
    );

    // The signed record carries the body unchanged, plus the signature.
    assert_eq!(answer["signedRecord"]["text"], "hello scitt");
    assert_eq!(
        answer["signedRecord"]["signatures"]
            .as_array()
            .expect("a signatures array")
            .len(),
        1
    );

    // The statement: a COSE_Sign1 with a per-request did:jwk issuer.
    assert_eq!(answer["statement"]["algorithm"], "ES256");
    assert!(
        answer["statement"]["issuer"]
            .as_str()
            .expect("an issuer")
            .starts_with("did:jwk:")
    );
    let statement = decode(
        answer["statement"]["coseSign1"]
            .as_str()
            .expect("a statement"),
    );
    assert_eq!(&statement[..2], &[0xd2, 0x84], "not a tag-18 4-array");

    // The transparent statement: the same statement with a receipt attached.
    let transparent = decode(
        answer["transparentStatement"]["coseSign1"]
            .as_str()
            .expect("a transparent statement"),
    );
    assert_eq!(&transparent[..2], &[0xd2, 0x84]);
    assert!(
        transparent.len() > statement.len(),
        "the receipt is not in the transparent statement"
    );

    let receipt = decode(
        answer["transparentStatement"]["receipt"]
            .as_str()
            .expect("a receipt"),
    );
    assert!(!receipt.is_empty(), "the service returned an empty receipt");
    assert_eq!(
        answer["transparentStatement"]["entryId"]
            .as_str()
            .map(str::len),
        Some(43),
        "an EntryID is unpadded base64url of a SHA-256"
    );
    assert!(
        answer["transparentStatement"]["location"]
            .as_str()
            .expect("a location")
            .ends_with(
                answer["transparentStatement"]["entryId"]
                    .as_str()
                    .expect("an id")
            )
    );
}

/// A per-request key, asserted the only way it can be: two requests must not
/// share one. This is the property that keeps statements from being correlable
/// and keeps one key's compromise out of earlier statements' history.
#[tokio::test]
async fn each_request_gets_its_own_key() {
    let Some(python) = emulator_python() else {
        return skip("no emulator environment; run scripts/setup-emulator.sh");
    };
    let emulator = Emulator::start(&python, false).await;
    let signer = Signer::start(&emulator.base_url, |_| {}).await;

    let first = sign(&signer, body()).await;
    let second = sign(&signer, body()).await;

    assert_ne!(first["statement"]["issuer"], second["statement"]["issuer"]);
    assert_ne!(first["statement"]["kid"], second["statement"]["kid"]);
    assert_ne!(
        first["inlineSignature"]["key"],
        second["inlineSignature"]["key"]
    );
    // Different keys, so different signatures over the same body.
    assert_ne!(
        first["inlineSignature"]["signature"]["$bytes"],
        second["inlineSignature"]["signature"]["$bytes"]
    );
    // And the same body, so the statement's payload is not what differs.
    assert_eq!(
        decode(
            first["statement"]["coseSign1"]
                .as_str()
                .expect("a statement")
        )
        .len(),
        decode(
            second["statement"]["coseSign1"]
                .as_str()
                .expect("a statement")
        )
        .len()
    );
}

/// The body is the artifact. A round trip through a JSON library would reorder
/// keys and drop whitespace, and the signature would then cover bytes the
/// caller never sent.
#[tokio::test]
async fn the_statement_payload_is_the_body_byte_for_byte() {
    let Some(python) = emulator_python() else {
        return skip("no emulator environment; run scripts/setup-emulator.sh");
    };
    let emulator = Emulator::start(&python, false).await;
    let signer = Signer::start(&emulator.base_url, |_| {}).await;

    // Keys out of order, and padding an encoder would drop.
    let body = "{ \"zed\" : 1 ,\n  \"$type\" : \"app.example.thing\" , \"alpha\" : true }";
    let answer = sign(&signer, body).await;

    let statement = decode(
        answer["statement"]["coseSign1"]
            .as_str()
            .expect("a statement"),
    );
    // The payload is the fourth element and is a byte string; find it by
    // looking for the body's bytes, which is the assertion that matters.
    assert!(
        statement
            .windows(body.len())
            .any(|window| window == body.as_bytes()),
        "the body is not in the statement as sent"
    );
    // And the emulator read the same bytes, since it echoed the record back.
    assert_eq!(answer["signedRecord"]["zed"], 1);
    assert_eq!(answer["signedRecord"]["alpha"], true);
}

/// The registered statement must be the statement that was signed, and the
/// service must be able to resolve it back.
#[tokio::test]
async fn the_registered_statement_is_retrievable_and_matches() {
    let Some(python) = emulator_python() else {
        return skip("no emulator environment; run scripts/setup-emulator.sh");
    };
    let emulator = Emulator::start(&python, false).await;
    let signer = Signer::start(&emulator.base_url, |_| {}).await;

    let answer = sign(&signer, body()).await;
    let entry_id = answer["transparentStatement"]["entryId"]
        .as_str()
        .expect("an entry id");

    let client = reqwest::Client::new();
    let receipt = client
        .get(format!("{}/entries/{entry_id}", emulator.base_url))
        .send()
        .await
        .expect("the receipt request is sent");
    assert_eq!(receipt.status(), 200, "the receipt did not resolve");
    let receipt = receipt.bytes().await.expect("a receipt body");
    assert_eq!(
        receipt.to_vec(),
        decode(
            answer["transparentStatement"]["receipt"]
                .as_str()
                .expect("a receipt")
        ),
        "the receipt the service returned is not the one the log holds"
    );

    // The emulator's own extension for reading a statement back.
    let statement = client
        .get(format!(
            "{}/entries/{entry_id}/statement",
            emulator.base_url
        ))
        .send()
        .await
        .expect("the statement request is sent");
    assert_eq!(statement.status(), 200);
    assert_eq!(
        statement.bytes().await.expect("a statement body").to_vec(),
        decode(
            answer["statement"]["coseSign1"]
                .as_str()
                .expect("a statement")
        ),
        "the log holds a different statement than the one signed"
    );
}

/// RFC 9943 Section6.3 requires a Transparency Service to verify a statement's
/// signature at registration. The emulator does not, by default. With the
/// check on, this fails unless the statement really is signed by the key its
/// `did:jwk` issuer names.
///
/// The request below is the emulator's *first*, and that is deliberate: a
/// COSE header label resolves to a registered attribute class at decode time,
/// so an emulator that registers those labels after decoding answers `400
/// Rejected` for the first statement it ever sees -- anyone's, not just this
/// service's. `tests/first_request.py` in the emulator checkout pins that
/// directly; this test would catch it too, by failing on a statement that
/// verifies perfectly well.
#[tokio::test]
async fn the_emulator_verifies_the_statement_when_asked_to() {
    let Some(python) = emulator_python() else {
        return skip("no emulator environment; run scripts/setup-emulator.sh");
    };
    let emulator = Emulator::start(&python, true).await;
    let signer = Signer::start(&emulator.base_url, |_| {}).await;

    let answer = sign(&signer, body()).await;
    assert!(
        !answer["transparentStatement"]["receipt"]
            .as_str()
            .expect("a receipt")
            .is_empty(),
        "the service registered a statement the emulator did not accept"
    );

    // And a second one, so the first is not the only one that got past.
    let second = sign(&signer, "{\"$type\":\"app.example.thing\",\"n\":2}").await;
    assert!(
        !second["transparentStatement"]["receipt"]
            .as_str()
            .expect("a receipt")
            .is_empty()
    );
}

/// A body that cannot carry a `signatures` array is a bad request, and must be
/// refused before anything is registered. Registering it would put a statement
/// in the log that no badge.blue verifier can make sense of.
#[tokio::test]
async fn a_body_that_is_not_a_json_object_is_refused_and_nothing_is_registered() {
    let Some(python) = emulator_python() else {
        return skip("no emulator environment; run scripts/setup-emulator.sh");
    };
    let emulator = Emulator::start(&python, false).await;
    let signer = Signer::start(&emulator.base_url, |_| {}).await;

    for unacceptable in ["[1,2,3]", "\"just a string\"", "not json at all", ""] {
        let response = reqwest::Client::new()
            .post(signer.sign_url())
            .header("content-type", "application/json")
            .body(unacceptable.to_string())
            .send()
            .await
            .expect("the request is sent");

        assert_eq!(
            response.status(),
            400,
            "the body {unacceptable:?} was accepted"
        );
        let body: Value = response.json().await.expect("an error body");
        assert_eq!(body["error"], "InvalidRequest");
    }

    // The emulator still holds an empty log, so nothing was registered before
    // the refusal.
    let keys = reqwest::Client::new()
        .get(format!("{}/.well-known/scitt-keys", emulator.base_url))
        .send()
        .await
        .expect("a request");
    assert_eq!(keys.status(), 200);
}

/// A Transparency Service that is not there is an upstream failure, not a
/// crash and not a 200 with a missing statement.
#[tokio::test]
async fn an_unreachable_transparency_service_is_a_bad_gateway() {
    let port = free_port();
    let signer = Signer::start(&format!("http://127.0.0.1:{port}"), |_| {}).await;

    let response = reqwest::Client::new()
        .post(signer.sign_url())
        .header("content-type", "application/json")
        .body(body().to_string())
        .send()
        .await
        .expect("the request is sent");

    assert_eq!(response.status(), 502);
    let answer: Value = response.json().await.expect("an error body");
    assert_eq!(answer["error"], "UpstreamFailure");
    assert!(
        answer["message"]
            .as_str()
            .expect("a message")
            .contains("error-scitt-atproto-signer-scitt-1"),
        "{answer}"
    );
}

/// The heart of the design: the DID minted for a request must publish a
/// service entry whose endpoint *is* the Receipt for that request.
///
/// Resolving the DID an attestation names therefore answers both questions a
/// holder has -- which key signed, and where the transparency evidence is --
/// without either being stated anywhere else.
#[tokio::test]
async fn the_minted_did_points_at_the_receipt_it_registered() {
    let Some(python) = emulator_python() else {
        return skip("no emulator environment; run scripts/setup-emulator.sh");
    };
    let emulator = Emulator::start(&python, false).await;
    let signer = Signer::start(&emulator.base_url, |_| {}).await;

    let answer = sign(&signer, body()).await;
    let did = answer["did"].as_str().expect("a did");
    assert!(did.starts_with("did:plc:"), "{did}");

    // The endpoint the document publishes is the Receipt resource the
    // Transparency Service named, to the character.
    let service = &answer["didDocument"]["service"][0];
    assert_eq!(service["id"], format!("{did}#scitt_scrapi"));
    assert_eq!(service["type"], "SCITTSCRAPI");
    assert_eq!(
        service["serviceEndpoint"],
        answer["transparentStatement"]["location"]
    );

    // And the attestation is issued by that DID, so following it to the DID
    // is the whole traversal. Its `key` is the did:key the document publishes,
    // which is what makes the signature verifiable without resolving anything.
    assert_eq!(answer["inlineSignature"]["issuer"], did);
    assert_eq!(
        answer["didDocument"]["verificationMethod"][0]["publicKeyMultibase"],
        answer["inlineSignature"]["key"]
            .as_str()
            .expect("a did:key")
            .trim_start_matches("did:key:")
    );

    // Resolving the DID needs a directory, so an unconfigured deployment says
    // so rather than leaving a caller to discover it.
    assert_eq!(answer["didPublished"], false);
    assert_eq!(answer["genesisOperation"]["type"], "plc_operation");
}

/// The service has no identity of its own, so there is nothing to describe.
/// This is deliberately asserted rather than left to a 404: an AT Protocol
/// client probing for a PDS would otherwise read the failure as an outage.
#[tokio::test]
async fn the_service_reports_no_identity_of_its_own() {
    let signer = Signer::start("http://127.0.0.1:1", |_| {}).await;
    let client = reqwest::Client::new();

    let health: Value = client
        .get(format!("{}/xrpc/_health", signer.base_url))
        .send()
        .await
        .expect("a request")
        .json()
        .await
        .expect("a body");
    assert_eq!(health["version"], env!("CARGO_PKG_VERSION"));

    let index: Value = client
        .get(&signer.base_url)
        .send()
        .await
        .expect("a request")
        .json()
        .await
        .expect("the service index");
    assert_eq!(index["method"], DEFAULT_NSID);
    assert!(
        index.get("did").is_none(),
        "the service must not claim a DID of its own: {index}"
    );

    let described = client
        .get(format!(
            "{}/xrpc/com.atproto.server.describeServer",
            signer.base_url
        ))
        .send()
        .await
        .expect("a request");
    assert_eq!(described.status(), 404);
}

/// A PLC directory stub: it records what is submitted and accepts it.
#[derive(Clone, Default)]
struct PlcStub {
    submitted: Arc<Mutex<Vec<(String, Value)>>>,
}

/// Start the stub and return it with its base URL.
async fn plc_stub() -> (PlcStub, String) {
    let stub = PlcStub::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a free port");
    let address = listener.local_addr().expect("an address");
    let router = axum::Router::new()
        .route("/{did}", post(record_operation))
        .with_state(stub.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (stub, format!("http://{address}"))
}

/// `POST /{did}` -- the directory's operation submission resource.
async fn record_operation(
    State(stub): State<PlcStub>,
    axum::extract::Path(did): axum::extract::Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    let operation: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    stub.submitted
        .lock()
        .expect("the stub is not poisoned")
        .push((did, operation));
    axum::http::StatusCode::OK
}

/// With a directory configured, each request's genesis operation is submitted
/// under the DID it derives -- which is the only way the DID an attestation
/// names becomes resolvable by anyone but the caller holding the response.
///
/// Two requests, because "one identity per request" is the property, and a
/// single request cannot show it: a service that reused one DID would pass
/// with one submission and a matching document.
#[tokio::test]
async fn a_configured_plc_directory_receives_a_genesis_operation_per_request() {
    let Some(python) = emulator_python() else {
        return skip("no emulator environment; run scripts/setup-emulator.sh");
    };
    let emulator = Emulator::start(&python, false).await;
    let (stub, directory) = plc_stub().await;
    let signer = Signer::start(&emulator.base_url, |config| {
        config.plc_directory = Some(directory.clone());
    })
    .await;

    let first = sign(&signer, body()).await;
    let second = sign(&signer, "{\"$type\":\"app.example.thing\",\"n\":2}").await;

    let first_did = first["did"].as_str().expect("a did");
    let second_did = second["did"].as_str().expect("a did");
    assert_ne!(first_did, second_did, "one DID served two requests");

    let submitted = stub.submitted.lock().expect("not poisoned").clone();
    assert_eq!(submitted.len(), 2, "the directory got {submitted:?}");

    for (answer, did) in [(&first, first_did), (&second, second_did)] {
        // Filed under its own DID, and the operation is the one the response
        // reports -- a directory holding a different operation would publish an
        // identity the service is not serving.
        let (filed_under, operation) = submitted
            .iter()
            .find(|(filed_under, _)| filed_under == did)
            .unwrap_or_else(|| panic!("{did} was never submitted: {submitted:?}"));
        assert_eq!(operation["type"], "plc_operation");
        assert_eq!(answer["genesisOperation"], *operation);
        assert_eq!(answer["didPublished"], true);
        assert_eq!(answer["didDocument"]["id"], did);

        // And what the directory holds points at this request's Receipt.
        assert_eq!(
            operation["services"]["scitt_scrapi"]["endpoint"],
            answer["transparentStatement"]["location"]
        );
        let _ = filed_under;
    }
}

/// The DID is a hash of the genesis operation. A hash that does not reproduce
/// is a DID nobody can resolve to the document the service handed back, so it
/// is recomputed here rather than taken on trust.
#[tokio::test]
async fn the_did_is_the_hash_of_the_operation_it_reports() {
    let Some(python) = emulator_python() else {
        return skip("no emulator environment; run scripts/setup-emulator.sh");
    };
    let emulator = Emulator::start(&python, false).await;
    let signer = Signer::start(&emulator.base_url, |_| {}).await;

    let answer = sign(&signer, body()).await;
    let reported = answer["did"].as_str().expect("a did");

    let operation: atproto_identity::plc::Operation =
        serde_json::from_value(answer["genesisOperation"].clone())
            .expect("the reported operation deserializes");
    let derived = atproto_identity::plc::Did::from_genesis(&operation)
        .expect("a genesis operation derives a DID");

    assert_eq!(derived.as_str(), reported);
}

/// The whole point, checked by an implementation that is not this one: the
/// Python verifier decodes the response with pycose, resolves the statement's
/// `did:jwk` issuer with the emulator's own key loader, rebuilds the Merkle
/// root from the inclusion proof, and checks both signatures.
///
/// Run it with `--nocapture` to see the checks.
#[tokio::test]
async fn an_independent_verifier_accepts_the_transparent_statement() {
    let Some(python) = emulator_python() else {
        return skip("no emulator environment; run scripts/setup-emulator.sh");
    };
    let emulator = Emulator::start(&python, false).await;
    let signer = Signer::start(&emulator.base_url, |_| {}).await;

    let answer = sign(&signer, body()).await;
    let response_path = crate_dir().join("target/verify-response.json");
    std::fs::create_dir_all(response_path.parent().expect("a parent")).expect("creates target");
    std::fs::write(&response_path, answer.to_string()).expect("writes the response");

    let output = Command::new(&python)
        .arg(crate_dir().join("scripts/verify-transparent-statement.py"))
        .arg(&response_path)
        .arg(&emulator.base_url)
        .output()
        .expect("the verifier runs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in stdout.lines() {
        println!("{line}");
    }
    assert!(
        output.status.success(),
        "the independent verifier refused the response:\n{stdout}\n{stderr}"
    );
}

/// The subject a caller passes reaches the statement, and the repository the
/// attestation is bound to reaches the content CID. Both are query parameters,
/// so neither needs a second code path to be checked.
#[tokio::test]
async fn query_parameters_reach_the_statement_and_the_attestation() {
    let Some(python) = emulator_python() else {
        return skip("no emulator environment; run scripts/setup-emulator.sh");
    };
    let emulator = Emulator::start(&python, false).await;
    let signer = Signer::start(&emulator.base_url, |_| {}).await;

    let response = reqwest::Client::new()
        .post(format!(
            "{}?repository=did:plc:someotherrepo&subject=a-specific-subject",
            signer.sign_url()
        ))
        .header("content-type", "application/json")
        .body(body().to_string())
        .send()
        .await
        .expect("the request is sent");
    assert!(response.status().is_success());
    let answer: Value = response.json().await.expect("an answer");

    assert_eq!(answer["repository"], "did:plc:someotherrepo");
    // The subject is inside the protected header, so it is in the statement's
    // own bytes and not merely echoed back.
    let statement = decode(
        answer["statement"]["coseSign1"]
            .as_str()
            .expect("a statement"),
    );
    assert!(
        statement
            .windows("a-specific-subject".len())
            .any(|window| window == b"a-specific-subject"),
        "the subject is not in the statement"
    );

    // The subject is the caller's, not the configured default.
    assert!(
        !statement
            .windows(DEFAULT_SUBJECT.len())
            .any(|window| window == DEFAULT_SUBJECT.as_bytes()),
        "the configured default subject reached a statement that named its own"
    );

    // The repository is bound into the content CID, so a different one is a
    // different CID over the same body.
    let default_repository = sign(&signer, body()).await;
    assert_ne!(answer["contentCid"], default_repository["contentCid"]);
    // With no `repository`, the attestation is bound to the DID minted for the
    // request: the only identity that has anything to do with this signature.
    assert_eq!(default_repository["repository"], default_repository["did"]);
}

/// A service configured for another subject still works, so the default is a
/// default rather than a requirement.
#[tokio::test]
async fn a_configured_subject_is_the_default() {
    let Some(python) = emulator_python() else {
        return skip("no emulator environment; run scripts/setup-emulator.sh");
    };
    let emulator = Emulator::start(&python, false).await;
    let signer = Signer::start(&emulator.base_url, |config| {
        config.subject = "a-configured-subject".to_string();
    })
    .await;

    let answer = sign(&signer, body()).await;
    let statement = decode(
        answer["statement"]["coseSign1"]
            .as_str()
            .expect("a statement"),
    );
    assert!(
        statement
            .windows("a-configured-subject".len())
            .any(|window| window == b"a-configured-subject"),
        "the configured subject is not in the statement"
    );
}
