# scitt-atproto-signer

XRPC service that creates a [badge.blue] signature over the
JSON request body and returns an `inlineSignature` object where the `issuer` is
a `did:plc` with a `#scitt_scrapi` service entry whose endpoint is the
[transparent statement].

The point of this is that we can bridge the ATProto ecosystem with external
Transparency Services.

## Setup

Needs Rust 1.97 (`rust-toolchain.toml` makes `rustup` fetch it). The `atproto-*` crates are git dependencies pinned to a commit, so no sibling checkouts are needed.

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
  | tee /tmp/sign.json | jq
```

```json
{
  "contentCid": "bafyreih4qqvumus5owhqzqiykds3c7hfqjmdihul65yez4jazokuc24df4",
  "contentType": "application/json",
  "did": "did:plc:6qegb3nj6ezhovunn44voqaz",
  "didDocument": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1"
    ],
    "alsoKnownAs": [],
    "id": "did:plc:6qegb3nj6ezhovunn44voqaz",
    "service": [
      {
        "id": "did:plc:6qegb3nj6ezhovunn44voqaz#scitt_scrapi",
        "serviceEndpoint": "http://127.0.0.1:8000/entries/CKDu5qhc4DRG8Va6GfNIKPjFdEh0RAZby28an_BLvBo",
        "type": "SCITTSCRAPI"
      }
    ],
    "verificationMethod": [
      {
        "controller": "did:plc:6qegb3nj6ezhovunn44voqaz",
        "id": "did:plc:6qegb3nj6ezhovunn44voqaz#atproto",
        "publicKeyMultibase": "zDnaeV5adQbcC1EXKYLpJfVJ4xCeuodLJFEfCrGgqpKqnJsfM",
        "type": "Multikey"
      }
    ]
  },
  "didPublished": false,
  "genesisOperation": {
    "alsoKnownAs": [],
    "prev": null,
    "rotationKeys": [
      "did:key:zDnaeV5adQbcC1EXKYLpJfVJ4xCeuodLJFEfCrGgqpKqnJsfM"
    ],
    "services": {
      "scitt_scrapi": {
        "endpoint": "http://127.0.0.1:8000/entries/CKDu5qhc4DRG8Va6GfNIKPjFdEh0RAZby28an_BLvBo",
        "type": "SCITTSCRAPI"
      }
    },
    "sig": "tkFji-l1UZf0FI4qwJfp4IynZ6T040lHLki1wN8we7BD3y8jgQP30rFzI20mdPm21bKHHEefWltwqDST3I_M9A",
    "type": "plc_operation",
    "verificationMethods": {
      "atproto": "did:key:zDnaeV5adQbcC1EXKYLpJfVJ4xCeuodLJFEfCrGgqpKqnJsfM"
    }
  },
  "inlineSignature": {
    "$type": "blue.badge.inlineSignature",
    "cid": "bafyreih4qqvumus5owhqzqiykds3c7hfqjmdihul65yez4jazokuc24df4",
    "issuedAt": "2026-09-30T04:57:25.331Z",
    "issuer": "did:plc:6qegb3nj6ezhovunn44voqaz",
    "key": "did:key:zDnaeV5adQbcC1EXKYLpJfVJ4xCeuodLJFEfCrGgqpKqnJsfM",
    "signature": {
      "$bytes": "AZl2mmanLzoCORWWvzG+j7cbNyJLJGTDDijc7MKUfdQKgm6GZ0ArVTMEwiyPkv/Wb55JABKomck19O1BqkJ6kw=="
    }
  },
  "repository": "did:plc:6qegb3nj6ezhovunn44voqaz",
  "signedRecord": {
    "$type": "app.bsky.feed.post",
    "createdAt": "2026-09-28T00:00:00.000Z",
    "signatures": [
      {
        "$type": "blue.badge.inlineSignature",
        "cid": "bafyreih4qqvumus5owhqzqiykds3c7hfqjmdihul65yez4jazokuc24df4",
        "issuedAt": "2026-09-30T04:57:25.331Z",
        "issuer": "did:plc:6qegb3nj6ezhovunn44voqaz",
        "key": "did:key:zDnaeV5adQbcC1EXKYLpJfVJ4xCeuodLJFEfCrGgqpKqnJsfM",
        "signature": {
          "$bytes": "AZl2mmanLzoCORWWvzG+j7cbNyJLJGTDDijc7MKUfdQKgm6GZ0ArVTMEwiyPkv/Wb55JABKomck19O1BqkJ6kw=="
        }
      }
    ],
    "text": "hello scitt"
  },
  "statement": {
    "algorithm": "ES256",
    "coseSign1": "0oRZAQ6kASYDcGFwcGxpY2F0aW9uL2pzb24EWCs0RlRDS2E1LXNCNFVWNXNqUFZjajNVcFFUUmg5NGpNQk9BMU16b0RudnNJD6IBeLBkaWQ6andrOmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJbEpTUmpSblVteFpZbWRPWm00NGRVZERWa1JDYldSWk9UVlpaMWx2ZVhreFVFWlRjRTVVZUVWaFJFRWlMQ0o1SWpvaVJHbFRSbmR6UmpkcVRYZ3dkRWQwZG1VeVExOVhZVWwzY0daZldEbFRaR05mT1ZOMGN6ZFZZV3RqUVNKOQJ0c2NpdHQtYXRwcm90by1zaWduZXKgWFp7IiR0eXBlIjoiYXBwLmJza3kuZmVlZC5wb3N0IiwidGV4dCI6ImhlbGxvIHNjaXR0IiwiY3JlYXRlZEF0IjoiMjAyNi0wOS0yOFQwMDowMDowMC4wMDBaIn1YQF0kvTPPR1w2BvkSNfb_4_abzi3ws2nIXA-Yo-TLn00kMCkRRavlgwHAMJZwIVZTwl3z6q9NSD8Y4lR7MlOGtOI",
    "didKey": "did:key:zDnaeV5adQbcC1EXKYLpJfVJ4xCeuodLJFEfCrGgqpKqnJsfM",
    "issuer": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IlJSRjRnUmxZYmdOZm44dUdDVkRCbWRZOTVZZ1lveXkxUEZTcE5UeEVhREEiLCJ5IjoiRGlTRndzRjdqTXgwdEd0dmUyQ19XYUl3cGZfWDlTZGNfOVN0czdVYWtjQSJ9",
    "key": {
      "crv": "P-256",
      "kty": "EC",
      "x": "RRF4gRlYbgNfn8uGCVDBmdY95YgYoyy1PFSpNTxEaDA",
      "y": "DiSFwsF7jMx0tGtve2C_WaIwpf_X9Sdc_9Sts7UakcA"
    },
    "kid": "4FTCKa5-sB4UV5sjPVcj3UpQTRh94jMBOA1MzoDnvsI"
  },
  "transparentStatement": {
    "coseSign1": "0oRZAQ6kASYDcGFwcGxpY2F0aW9uL2pzb24EWCs0RlRDS2E1LXNCNFVWNXNqUFZjajNVcFFUUmg5NGpNQk9BMU16b0RudnNJD6IBeLBkaWQ6andrOmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJbEpTUmpSblVteFpZbWRPWm00NGRVZERWa1JDYldSWk9UVlpaMWx2ZVhreFVFWlRjRTVVZUVWaFJFRWlMQ0o1SWpvaVJHbFRSbmR6UmpkcVRYZ3dkRWQwZG1VeVExOVhZVWwzY0daZldEbFRaR05mT1ZOMGN6ZFZZV3RqUVNKOQJ0c2NpdHQtYXRwcm90by1zaWduZXKhGQGKgVjw0oRYWKQBJgRYIBtTrgDpLAig7ttBtTAThGd2YBppKR9VqFjeZqlRmdiFD6IBdHRyYW5zcGFyZW5jeS5leGFtcGxlAnRzY2l0dC1hdHByb3RvLXNpZ25lchkBiwGhGQGMoSCBWEiDBgWCWCC2HDX5Al-_himKyVSUbd5j2ugZCXtHf5oz8sySNzM6M1ggXPwQEAXwjqyGOiPtELYmNvHC3kdNriA48MC1J3Yr4dT2WEAtilYCv6zDysIFQ3Sdrxf2vwpXmpLwpewJc0zIQRf-kiSIRXtNmspcTrSpQ5liZ9zvR0qkADDuzDP1Y2GLaWmEWFp7IiR0eXBlIjoiYXBwLmJza3kuZmVlZC5wb3N0IiwidGV4dCI6ImhlbGxvIHNjaXR0IiwiY3JlYXRlZEF0IjoiMjAyNi0wOS0yOFQwMDowMDowMC4wMDBaIn1YQF0kvTPPR1w2BvkSNfb_4_abzi3ws2nIXA-Yo-TLn00kMCkRRavlgwHAMJZwIVZTwl3z6q9NSD8Y4lR7MlOGtOI",
    "entryId": "CKDu5qhc4DRG8Va6GfNIKPjFdEh0RAZby28an_BLvBo",
    "location": "http://127.0.0.1:8000/entries/CKDu5qhc4DRG8Va6GfNIKPjFdEh0RAZby28an_BLvBo",
    "receipt": "0oRYWKQBJgRYIBtTrgDpLAig7ttBtTAThGd2YBppKR9VqFjeZqlRmdiFD6IBdHRyYW5zcGFyZW5jeS5leGFtcGxlAnRzY2l0dC1hdHByb3RvLXNpZ25lchkBiwGhGQGMoSCBWEiDBgWCWCC2HDX5Al-_himKyVSUbd5j2ugZCXtHf5oz8sySNzM6M1ggXPwQEAXwjqyGOiPtELYmNvHC3kdNriA48MC1J3Yr4dT2WEAtilYCv6zDysIFQ3Sdrxf2vwpXmpLwpewJc0zIQRf-kiSIRXtNmspcTrSpQ5liZ9zvR0qkADDuzDP1Y2GLaWmE"
  }
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
  [ok  ] the proof names a leaf inside the tree -- leaf 6 of 7
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
  [ok  ] the content CID recomputes from the record, the metadata and the repository -- bafyreig2bkrsvb2hohqwwlv6l7jaapiaeapqxwzr2zxyitgucperrtpeum
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
  [ok  ] the identifier is the hash of the genesis operation it reports -- did:plc:cgk4ys3qtoubg3btlfg7iz2i derived, did:plc:cgk4ys3qtoubg3btlfg7iz2i reported
  [ok  ] the document carries one service entry
  [ok  ] its id is #scitt_scrapi
  [ok  ] its type is SCITTSCRAPI
  [ok  ] its endpoint is the Receipt this response reports
  [ok  ] its endpoint names the EntryID that was registered

all checks passed
```

Check the [badge.blue] inline signature with the Rust CLI:

```sh
jq -r '.signedRecord' /tmp/sign.json > /tmp/record.json
REPOSITORY=$(jq -r .repository /tmp/sign.json)

cargo install --git https://tangled.org/ngerakines.me/atproto-crates \
  --rev 242693e1956e4f96659846194154c97ecbe60d72 \
  atproto-attestation --features clap,tokio --bin atproto-attestation-verify

atproto-attestation-verify /tmp/record.json "$REPOSITORY"
```

```text
✓ [0] inline blue.badge.inlineSignature key did:key:zDnaeydns3BxPfXXsa8eB8AUQif9KUsi6gyrXSbPM59N57ds3 issuer did:plc:cgk4ys3qtoubg3btlfg7iz2i
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
[transparent statement]: https://www.rfc-editor.org/info/rfc9943/#section-7
