# scitt-atproto-signer

XRPC service. Signs the request body as-is. Returns:

* SCITT **Transparent Statement** (`COSE_Sign1`, `did:jwk` issuer, one fresh P-256 key per request, registered via [SCRAPI])
* [badge.blue] **inline attestation**
* a `did:plc` minted per request. Its DID document holds the key and a `#scitt_scrapi` service entry whose endpoint is the Receipt.

Body must be a JSON object. Other bodies get `400`.

## Setup

Sibling checkouts needed (`atproto-crates` pins Rust 1.97):

```
scitt-atproto/
|-- atproto-crates/
|-- scitt-api-emulator/
`-- scitt-atproto-signer/
```

Start a Transparency Service ([SCITT API Emulator]):

```sh
./scripts/setup-emulator.sh
./.emulator-venv/bin/python scripts/run-emulator.py /tmp/scitt-workspace 8000
```

Start the signer:

```sh
cargo build --release

SCITT_SCRAPI_ENDPOINT=http://127.0.0.1:8000 \
SCITT_XRPC_BIND=127.0.0.1:8787 \
  ./target/release/scitt-atproto-signer
```

| variable | default | meaning |
| --- | --- | --- |
| `SCITT_SCRAPI_ENDPOINT` | *(required)* | Transparency Service |
| `SCITT_XRPC_BIND` | `127.0.0.1:8787` | listen address |
| `SCITT_XRPC_NSID` | `blue.scitt.sign` | NSID |
| `SCITT_PLC_DIRECTORY` | unset | publish each request's DID here. Every request becomes a permanent public log entry. |
| `SCITT_SUBJECT` | `scitt-atproto-signer` | default `sub` claim |
| `SCITT_SIGNATURE_TYPE` | `blue.badge.inlineSignature` | inline signature `$type` |

## Health

```sh
curl -s http://127.0.0.1:8787/xrpc/_health
```

```json
{"version":"0.1.0"}
```

## Sign

```sh
curl -s -X POST 'http://127.0.0.1:8787/xrpc/blue.scitt.sign' \
  -H 'content-type: application/json' \
  -d '{"$type":"app.bsky.feed.post","text":"hello scitt","createdAt":"2026-09-28T00:00:00.000Z"}' \
  | jq '{did, entry: .transparentStatement.entryId, receipt: .didDocument.service[0].serviceEndpoint}'
```

```json
{
  "did": "did:plc:ccfvk2stovekgflnzuyajds5",
  "entry": "DDlkBKmZx1Z726c40PeFKIpXxbbnifrRWYcnmlT5h40",
  "receipt": "http://127.0.0.1:8000/entries/DDlkBKmZx1Z726c40PeFKIpXxbbnifrRWYcnmlT5h40"
}
```

Query params: `?repository=<did>` binds attestation to that repo. `?subject=<string>` sets `sub`.

With [`goat`]:

```sh
goat xrpc procedure http://127.0.0.1:8787 blue.scitt.sign \
  '$type=app.bsky.feed.post' 'text=hello from goat' \
  | jq '{entry: .transparentStatement.entryId, cid: .contentCid}'
```

```json
{
  "entry": "bwyl32IE86iZYx-dAdVzQeCDSN12T65jqI5X9eAUlO8",
  "cid": "bafyreie5bmwtnh4lwkbp7ieluxcmwujcwzyr2o4szr5xl7twb3m4rnmz7y"
}
```

Bad body:

```sh
curl -s -X POST 'http://127.0.0.1:8787/xrpc/blue.scitt.sign' \
  -H 'content-type: application/json' -d '[1]' -w '\n%{http_code}\n'
```

```text
{"error":"InvalidRequest","message":"error-scitt-atproto-signer-request-1 bad request: the request body must be a JSON object to carry a signatures array, and it is an array"}
400
```

## Response

```sh
curl -s -X POST 'http://127.0.0.1:8787/xrpc/blue.scitt.sign' \
  -H 'content-type: application/json' \
  -d '{"$type":"app.bsky.feed.post","text":"hello scitt"}' > /tmp/sign.json

jq '{did, didPublished, repository, contentType, statement: (.statement | del(.coseSign1)), contentCid}' /tmp/sign.json
```

```json
{
  "did": "did:plc:i7qf4mqosmx65siwoebmi5rp",
  "didPublished": false,
  "repository": "did:plc:i7qf4mqosmx65siwoebmi5rp",
  "contentType": "application/json",
  "statement": {
    "algorithm": "ES256",
    "didKey": "did:key:zDnaeZPzVoJBTK4GPvrSujE7vr4nRNmvGz8cq7BvaF5YkZLFv",
    "issuer": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImhUZXBXeENzbjE1eTNmdlJaX2syVU5tcmphWHY0TE5scl9XazNmeE5PUjAiLCJ5IjoieEY2Q1ZnTjNBOHdTYkwtUXpQNEdQc2k3a2hyYW8zYnlRc2UtVG1acjRFUSJ9",
    "key": {
      "crv": "P-256",
      "kty": "EC",
      "x": "hTepWxCsn15y3fvRZ_k2UNmrjaXv4LNlr_Wk3fxNOR0",
      "y": "xF6CVgN3A8wSbL-QzP4GPsi7khrao3byQse-TmZr4EQ"
    },
    "kid": "tMYinGg3eXgOnChs9bkpCYJ6YM1C3qHPMSj3c7pMV1Y"
  },
  "contentCid": "bafyreifpkveuw4xjpuz6v2omvxbr5jt76pphki5bd7ny46bziyefvsumaa"
}
```

Other top-level keys: `didDocument`, `genesisOperation`, `inlineSignature`, `signedRecord`, `transparentStatement` (`entryId`, `location`, `receipt`, `coseSign1`). Full shape: `lexicons/blue/scitt/sign.json`.

The minted DID document:

```sh
jq '.didDocument' /tmp/sign.json
```

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1"
  ],
  "alsoKnownAs": [],
  "id": "did:plc:i7qf4mqosmx65siwoebmi5rp",
  "service": [
    {
      "id": "did:plc:i7qf4mqosmx65siwoebmi5rp#scitt_scrapi",
      "serviceEndpoint": "http://127.0.0.1:8000/entries/_Ll1IidR5NqM49b4uVNeQgK-0a_Oyf43jxEfS_Qd4m4",
      "type": "SCITTSCRAPI"
    }
  ],
  "verificationMethod": [
    {
      "controller": "did:plc:i7qf4mqosmx65siwoebmi5rp",
      "id": "did:plc:i7qf4mqosmx65siwoebmi5rp#atproto",
      "publicKeyMultibase": "zDnaeZPzVoJBTK4GPvrSujE7vr4nRNmvGz8cq7BvaF5YkZLFv",
      "type": "Multikey"
    }
  ]
}
```

## Verify

Python verifier. No code from this crate. Checks COSE signature, Merkle inclusion proof, Receipt, inline signature, and re-derives the `did:plc` from the genesis operation.

```sh
./.emulator-venv/bin/python scripts/verify-transparent-statement.py \
  /tmp/sign.json http://127.0.0.1:8000
```

```console
1. structure
2. the statement's own signature
3. the receipt proves this statement is in the log
4. the receipt names the statement that was registered
5. the badge.blue inline signature
6. the DID resolves to the key and to the receipt

all checks passed
```

(Output above shows section headings only. Each section prints `[ok  ]` per check.)

Check the inline signature with the Rust CLI:

```sh
jq -r '.signedRecord' /tmp/sign.json > /tmp/record.json
REPOSITORY=$(jq -r .repository /tmp/sign.json)

cargo +1.97 run -q --manifest-path ../atproto-crates/Cargo.toml \
  -p atproto-attestation --features clap,tokio \
  --bin atproto-attestation-verify -- /tmp/record.json "$REPOSITORY"
```

```text
✓ [0] inline blue.badge.inlineSignature key did:key:zDnaeZPzVoJBTK4GPvrSujE7vr4nRNmvGz8cq7BvaF5YkZLFv issuer did:plc:i7qf4mqosmx65siwoebmi5rp
1 of 1 attestations verified.
```

Lexicon:

```sh
goat lex parse lexicons/blue/scitt/sign.json
```

```text
lexicons/blue/scitt/sign.json: success
```

## Test

Drives a real emulator, not a mock.

```sh
./scripts/setup-emulator.sh
cargo test
```

## References

[RFC 9943] (SCITT) · [draft-ietf-scitt-scrapi-11] · [RFC 9052] (COSE) · [RFC 9162] (Merkle proofs) · [RFC 9597] (CWT claims) · [RFC 7638] (JWK thumbprint) · [did:plc](https://web.plc.directory/spec/v0.1/did-plc) · [badge.blue]

[SCRAPI]: https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11
[draft-ietf-scitt-scrapi-11]: https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11
[RFC 9943]: https://www.rfc-editor.org/rfc/rfc9943.html
[RFC 9052]: https://www.rfc-editor.org/rfc/rfc9052.html
[RFC 9162]: https://www.rfc-editor.org/rfc/rfc9162.html
[RFC 9597]: https://www.rfc-editor.org/rfc/rfc9597.html
[RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638.html
[SCITT API Emulator]: https://github.com/publicdomainrelay/scitt-api-emulator
[`goat`]: https://github.com/bluesky-social/goat
[badge.blue]: https://badge.blue/
