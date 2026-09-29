# scitt-atproto-signer

An AT Protocol XRPC service that signs the **request body itself** and returns
two artefacts over it:

* a **SCITT Signed Statement** -- a `COSE_Sign1` whose issuer is a
  `did:jwk` for a key minted for that one request -- registered with a
  Transparency Service speaking [SCRAPI], and returned as a **Transparent
  Statement** with its Receipt attached;
* a **badge.blue inline attestation**, returned as `inlineSignature`.

Both come back together, with the public key needed to verify either.

```
POST /xrpc/blue.scitt.sign?repository=<did>&subject=<string>
Content-Type: application/json

{"$type": "app.bsky.feed.post", "text": "hello"}
```

## Why the body is the artifact

The signature covers the bytes the caller sent. Parsing the body and writing
it back out would reorder keys and change whitespace, and the signature would
then cover a document the caller never sent -- verifiable by this service and
nobody else. The body is passed through untouched, and only *read* as JSON
where the attestation layer needs an object.

It does have to be a JSON **object**: the inline attestation is appended to
the record's `signatures` array, and there is nowhere to append it on a
scalar or an array. A body that is not one is refused with `400` before
anything is registered.

## Why a key per request

A service-wide key would make every statement this service ever produced part
of one correlation set, and would put that key's compromise in the past of
every statement already issued. A fresh P-256 key per request costs a
millisecond and removes both.

The cost is that a verifier cannot resolve the key from a directory. So the
key travels in the response, the SCITT issuer is a `did:jwk` (the key *is* the
identifier), and the badge.blue metadata names it as a `did:key`.

## The `did:plc` minted for each request

Every call mints a `did:plc` for the key it just generated. Its DID document
does two things:

* it publishes the request's public key as a verification method, `#atproto`;
* it carries one service entry whose endpoint **is the Receipt**:

```json
{
  "id": "#scitt_scrapi",
  "type": "SCITTSCRAPI",
  "serviceEndpoint": "http://127.0.0.1:8000/entries/6jZWRUsucVNM"
}
```

So resolving the DID the attestation names answers both questions a holder
has: **which key** signed it, and **where the transparency evidence is**. That
is the whole traversal -- attestation -> DID -> key and Receipt.

### Why the DID cannot be inside the statement it points at

The service entry names the EntryID. The EntryID is a hash of the Signed
Statement. Putting this DID in the statement's `iss` claim would need the
EntryID before the statement exists, and the statement before the EntryID
exists.

So the statement's issuer is a `did:jwk` -- the key is its own identifier, and
nothing has to be resolved to check it -- and the DID is minted afterwards,
once the EntryID is known. Nothing is lost: the DID document names the same
key the statement was signed with, so resolving it checks the statement too.

### Publishing

Without `SCITT_PLC_DIRECTORY` the DID is derived and its document is returned,
but nothing is submitted: the DID is resolvable by nobody but the holder of
the response, and `didPublished` says `false`. With it set, each request's
genesis operation is submitted to that directory and the DID resolves for
anyone.

Two things follow, both worth knowing before pointing this at a real
directory. A `did:plc` per request means a **permanent, irreversible entry in
a public log for every statement signed**, at whatever rate the directory
accepts. And the DID is a hash of its genesis operation, so a request's
identity is fixed the moment it is served; the operation to submit is in the
response, so a failed submission can be retried from it.

The service itself has no `did:plc`. There is nothing here to resolve: callers
reach it by URL, and `com.atproto.server.describeServer` is deliberately not
served, because answering it would mean inventing an identity the service does
not have.

## The response

| field | what it is |
| --- | --- |
| `did` | the `did:plc` minted for this request |
| `didPublished` | whether its genesis operation reached a PLC directory |
| `didDocument` | that DID's document: the request's key, and the Receipt resource |
| `genesisOperation` | the signed operation `did` is derived from, for submitting yourself |
| `repository` | the repository the attestation is bound to |
| `contentType` | the media type of the body, as it arrived |
| `statement.issuer` | the `did:jwk` of the request's key |
| `statement.key` | that key, as a JWK |
| `statement.didKey` | the same key as a `did:key`, for a verifier with no directory access |
| `statement.kid` | its RFC 7638 thumbprint, which is the COSE `kid` |
| `statement.algorithm` | `ES256` |
| `statement.coseSign1` | the Signed Statement, unpadded base64url |
| `transparentStatement.entryId` | the EntryID of the registration |
| `transparentStatement.location` | the Receipt resource -- the same URL as the service entry |
| `transparentStatement.receipt` | the Receipt, unpadded base64url |
| `transparentStatement.coseSign1` | the statement with the Receipt in its unprotected header under label 394 |
| `inlineSignature` | the badge.blue signature entry: issued by `did`, signed with a `did:key` its document publishes |
| `contentCid` | the content CID that signature covers |
| `signedRecord` | the body with the signature appended to `signatures` |

---

# Running it

## 0. What has to be next to it

The crate depends by path on three crates from `atproto-crates`, which is
expected as a sibling checkout:

```
scitt-atproto/
|-- atproto-crates/         # atproto-attestation, atproto-identity, atproto-record
|-- scitt-api-emulator/     # the Transparency Service the tests drive
`-- scitt-atproto-signer/   # this crate
```

`atproto-crates` pins its toolchain to Rust 1.97 in `rust-toolchain.toml`, and
this crate's `rust-version` matches, so `rustup` will fetch it on first build.

## 1. A Transparency Service

The [SCITT API Emulator] implements [draft-ietf-scitt-scrapi-11]. Set it up
into a virtual environment beside this crate and start it:

```sh
./scripts/setup-emulator.sh
./.emulator-venv/bin/python scripts/run-emulator.py /tmp/scitt-workspace 8000
```

`scripts/run-emulator.py` starts the emulator without Flask's debug reloader
and with its random-error rate at zero. Both are wrong for anything scripted:
the reloader forks, so a signal to the parent leaves the child holding the
port, and a 1% error rate turns a mostly-passing test into a flaky one. Add
`--verify-signature` to make it check each statement's signature at
registration, as RFC 9943 Section 6.3 requires.

The emulator's own entry point works too, if you would rather:

```sh
cd ../scitt-api-emulator && ./scitt-emulator.sh server --workspace workspace/
```

## 2. The signer

```sh
cargo build --release

SCITT_SCRAPI_ENDPOINT=http://127.0.0.1:8000 \
SCITT_XRPC_BIND=127.0.0.1:8787 \
  ./target/release/scitt-atproto-signer
```

Add `SCITT_PLC_DIRECTORY=plc.directory` to make each request's DID resolvable
by anyone rather than only by the caller holding the response.

`SCITT_SCRAPI_ENDPOINT` is the only setting without a default. Every setting
is an environment variable, and `--help` lists them.

| variable | default | meaning |
| --- | --- | --- |
| `SCITT_SCRAPI_ENDPOINT` | *(required)* | the Transparency Service to register with |
| `SCITT_XRPC_BIND` | `127.0.0.1:8787` | the address to listen on |
| `SCITT_XRPC_NSID` | `blue.scitt.sign` | the NSID this service answers at |
| `SCITT_PLC_DIRECTORY` | unset | a PLC directory to publish each request's DID to; unset leaves them local |
| `SCITT_SUBJECT` | `scitt-atproto-signer` | the default `sub` claim |
| `SCITT_SIGNATURE_TYPE` | `blue.badge.inlineSignature` | the `$type` of the inline signature record |

## 3. Sign something

### curl

```sh
curl -s -X POST 'http://127.0.0.1:8787/xrpc/blue.scitt.sign' \
  -H 'content-type: application/json' \
  -d '{"$type":"app.bsky.feed.post","text":"hello scitt","createdAt":"2026-09-28T00:00:00.000Z"}' \
  | jq '{did, entry: .transparentStatement.entryId, receipt: .didDocument.service[0].serviceEndpoint}'
```

```json
{
  "did": "did:plc:c6kpfuggl2acwvvj6jbm2rxw",
  "entry": "Flfh3wKvWqVjtBauzCvNwpFY2bUnLVWUf9Zp_6AwwQo",
  "receipt": "http://127.0.0.1:8000/entries/Flfh3wKvWqVjtBauzCvNwpFY2bUnLVWUf9Zp_6AwwQo"
}
```

The `did` is new for every call -- it is minted for that one statement. The
third line is the point: resolving it leads to the Receipt.

Add `?repository=did:plc:yourownrepo` to bind the attestation to the repository
the record is destined for rather than to the minted DID, and `?subject=...`
to set the statement's `sub` claim.

### goat

[`goat`] calls any XRPC endpoint. `httpie`-style arguments build a JSON body:

```sh
goat xrpc procedure http://127.0.0.1:8787 blue.scitt.sign \
  '$type=app.bsky.feed.post' 'text=hello from goat' \
  | jq '{entry: .transparentStatement.entryId, cid: .contentCid}'
```

Query parameters use `==`, and the body can come from stdin instead:

```sh
echo '{"$type":"app.bsky.feed.post","text":"from a file"}' \
  | goat xrpc procedure http://127.0.0.1:8787 blue.scitt.sign \
      repository==did:plc:example \
      content-type:application/json -
```

Liveness, which is what a client checks before trusting an endpoint:

```console
$ curl -s http://127.0.0.1:8787/xrpc/_health
{"version":"0.1.0"}
```

`com.atproto.server.describeServer` is not served: it would have to name a DID
for the service, and the service has none.

### atpxrpc

`atpxrpc` (from [`atproto-crates`]) is the authenticated client, and it is
worth being precise about what it can and cannot do here. Both of its proxying
forms resolve a service DID and call the endpoint that DID document names. The
minted did:plc names the *Receipt*, not this XRPC method, and the service has
no DID of its own -- so there is nothing for a PDS to proxy to, and the call
belongs on the service's URL, as in the `goat` and `curl` examples above.

### The lexicon

The method's Lexicon is at `lexicons/blue/scitt/sign.json`:

```console
$ goat lex parse lexicons/blue/scitt/sign.json
lexicons/blue/scitt/sign.json: success
```

`goat lex lint` reports `unlimited-string` warnings for `coseSign1` and
`receipt`. Those are encoded binary blobs, not caller-supplied text, so a
length constraint on them would be a fiction.

## 4. Verify what came back

`scripts/verify-transparent-statement.py` is a second implementation reading
the same bytes. In Python, with no code from this crate: it decodes the
`COSE_Sign1` with `pycose`, resolves the statement's `did:jwk` issuer with the
emulator's own key loader, rebuilds the Merkle root from the RFC 9162
inclusion proof, checks the Receipt against the COSE Key Set the Transparency
Service publishes, recomputes the badge.blue content CID from DAG-CBOR,
checks the inline signature over it, **re-derives the `did:plc` from the
genesis operation**, and follows the service entry to the Receipt.

Every artefact the service returns is therefore verified by something other
than the code that produced it. Tamper with the record, the CID, or the
operation the DID is derived from and it says so.

```sh
curl -s -X POST 'http://127.0.0.1:8787/xrpc/blue.scitt.sign' \
  -H 'content-type: application/json' \
  -d '{"$type":"app.bsky.feed.post","text":"hello scitt"}' > /tmp/sign.json

./.emulator-venv/bin/python scripts/verify-transparent-statement.py \
  /tmp/sign.json http://127.0.0.1:8000
```

```console
1. structure
  [ok  ] the transparent statement decodes as COSE_Sign1
  [ok  ] its payload is the request body, byte for byte -- 51 bytes
  [ok  ] it carries receipts under label 394
  [ok  ] the receipt in the header is the one the service returned
  [ok  ] the protected header is unchanged by the receipt
  [ok  ] the payload is unchanged by the receipt
2. the statement's own signature
  [ok  ] the protected header carries CWT claims
  [ok  ] the issuer is a did:jwk -- did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVD...
  [ok  ] the issuer's key resolves
  [ok  ] the kid names that key
  [ok  ] the statement's signature verifies
3. the receipt proves this statement is in the log
  [ok  ] the receipt is a tag-18 COSE_Sign1
  [ok  ] the receipt's payload is detached
  [ok  ] the receipt carries proofs under label 396
  [ok  ] the receipt carries at least one inclusion proof
  [ok  ] the leaf is over the statement as registered
  [ok  ] the proof names a leaf inside the tree -- leaf 0 of 1
  [ok  ] every inclusion proof reconstructs a 32-byte root
  [ok  ] the receipt names a kid
  [ok  ] the service publishes a COSE Key Set
  [ok  ] the receipt's kid is in the published key set
  [ok  ] exactly one inclusion proof yields the root the receipt signed -- 1 of 1 matched
4. the receipt names the statement that was registered
  [ok  ] the receipt carries CWT claims
  [ok  ] the receipt's subject is the statement's subject -- scitt-atproto-signer
5. the badge.blue inline signature
  [ok  ] the record carries exactly one signature
  [ok  ] the content CID recomputes from the record, the metadata and the repository -- bafyreih2kvo23ul66tgsyjg5gv4rgc7vrdvtscfvxy5msjzrmgeppcgxcu
  [ok  ] the response reports the same content CID
  [ok  ] the key is a did:key this verifier can decode
  [ok  ] the issuer's document publishes a verification method
  [ok  ] that method is the key the attestation names
  [ok  ] the signature is a 64-byte P-256 signature
  [ok  ] the inline signature verifies over the content CID
6. the DID resolves to the key and to the receipt
   (this is what a reader of the attestation does: resolve the DID)
  [ok  ] the attestation is issued by that DID
  [ok  ] the document is that DID's own
  [ok  ] the identifier is the hash of the genesis operation it reports -- did:plc:cvlnmnqerz6hegtelblfg5ix derived, did:plc:cvlnmnqerz6hegtelblfg5ix reported
  [ok  ] the document carries one service entry
  [ok  ] its id is #scitt_scrapi
  [ok  ] its type is SCITTSCRAPI
  [ok  ] its endpoint is the Receipt this response reports
  [ok  ] its endpoint names the EntryID that was registered

all checks passed
```

The same crate's `atproto-attestation-verify` binary is a third check on the
inline signature, and it reads the record as a file rather than in memory:

```sh
curl -s -X POST 'http://127.0.0.1:8787/xrpc/blue.scitt.sign' \
  -H 'content-type: application/json' \
  -d '{"$type":"app.bsky.feed.post","text":"hello"}' \
  | jq -r '.signedRecord' > /tmp/record.json

cargo run --manifest-path ../atproto-crates/Cargo.toml \
  -p atproto-attestation --features clap,tokio \
  --bin atproto-attestation-verify -- /tmp/record.json "$REPOSITORY"
```

```console
[ok] [0] inline blue.badge.inlineSignature key did:key:zDnaewYP6MuQMMcGQACiu19UtyTmtN7RfRiNQgtnSeU3Kfc5q issuer did:plc:r3ofeokngzoihvwq7foqy2o5
1 of 1 attestations verified.
```

The binary marks a verified attestation with a check mark; it is shown here
as `[ok]`.

The second argument is the `repository` from the response -- the DID minted for
that request, unless `?repository=` was given. The CLI resolves the
attestation's `did:key` and checks the signature; it does not resolve the
issuer, which needs a PLC directory and is what the Python verifier's sixth
section covers. `atproto-attestation-sign` -- the CLI this crate's attestation
path is built on -- produces the same inline shape from the command line, for
comparison.

Read the statement back out of the log with the emulator's own client -- the
`/entries/{entry_id}/statement` resource is an emulator extension, not part of
SCRAPI:

```sh
./.emulator-venv/bin/scitt-emulator client retrieve-receipt \
  --url http://127.0.0.1:8000 \
  --entry-id Flfh3wKvWqVjtBauzCvNwpFY2bUnLVWUf9Zp_6AwwQo \
  --out receipt.cbor
```

---

# Tests

```sh
./scripts/setup-emulator.sh          # once: the Python environment
cargo test
cargo test --test integration -- --nocapture   # to see the verifier's checks
```

The integration tests drive a **real** SCITT API Emulator rather than a mock,
because the property under test is whether this service speaks SCRAPI:
agreement between two readings of the same draft is not evidence. They check
that both artefacts come back together, that each request mints its own key,
that the statement payload is the body byte for byte, that the registered
statement resolves and matches what was signed, that a bad body is refused
before anything is registered, that an unreachable service is `502` rather
than a crash, that the minted DID document carries the `#scitt_scrapi` entry
whose endpoint is that request's Receipt, that its identifier is the hash of
the genesis operation it reports, that a configured PLC directory receives one
genesis operation per request, and that the emulator accepts the statement
with its registration-time signature check on.

If the Python environment is absent the integration tests report that and
pass, because it is a prerequisite a `cargo test` on a machine without Python
cannot satisfy. Everything after the environment is found is a hard assertion.

One test asserts that the emulator's **first** request under
`--verify-signature` succeeds. That is not padding: a COSE header label
resolves to a registered attribute class at decode time, so an emulator that
registers those labels after decoding refuses the first statement it ever
sees. If this test fails while the others pass, the sibling checkout of
`scitt-api-emulator` is one that has that bug -- `tests/first_request.py` in
that tree pins it there, in a fresh process, where it can be reproduced.

# References

* [RFC 9943] -- SCITT architecture: Signed Statements, Receipts, Transparent Statements
* [draft-ietf-scitt-scrapi-11] -- the SCRAPI resources
* [RFC 9052] -- COSE, `COSE_Sign1` and the `Sig_structure`
* [RFC 9162] -- the Merkle tree and inclusion proofs a Receipt's payload commits to
* [RFC 9597] -- the CWT Claims header parameter
* [RFC 7638] -- JWK thumbprints, which are the COSE `kid`
* [did:plc](https://web.plc.directory/spec/v0.1/did-plc) -- the service's identity
* [badge.blue] -- the inline attestation format

[SCRAPI]: https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11
[draft-ietf-scitt-scrapi-11]: https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11
[RFC 9943]: https://www.rfc-editor.org/rfc/rfc9943.html
[RFC 9052]: https://www.rfc-editor.org/rfc/rfc9052.html
[RFC 9162]: https://www.rfc-editor.org/rfc/rfc9162.html
[RFC 9597]: https://www.rfc-editor.org/rfc/rfc9597.html
[RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638.html
[SCITT API Emulator]: https://github.com/publicdomainrelay/scitt-api-emulator
[`goat`]: https://github.com/bluesky-social/goat
[`atproto-crates`]: https://tangled.org/ngerakines.me/atproto-crates
[badge.blue]: https://badge.blue/
