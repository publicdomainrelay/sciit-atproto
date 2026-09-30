# scitt-atproto-signer

XRPC service that creates a [badge.blue](https://badge.blue) signature over the
JSON request body and returns an `inlineSignature` object where the `issuer` is
a `did:plc` with a `#scitt_scrapi` service entry whose endpoint is the
[transparent statement](https://www.rfc-editor.org/info/rfc9943/#section-7).

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
  | jq .
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

Query params: `?repository=<did>` binds attestation to that repo. `?subject=<string>` sets `sub`.

With [`goat`]:

```sh
goat xrpc procedure http://127.0.0.1:8787 blue.scitt.sign \
  '$type=app.bsky.feed.post' 'text=hello from goat'
```

```json
{
  "contentCid": "bafyreihc6twroalkon3vvoiptdfc5ngo7nv74lbwpcvzrddeicw45bipou",
  "contentType": "application/json",
  "did": "did:plc:iec6bspw6ctfbxhrdi4or275",
  "didDocument": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1"
    ],
    "alsoKnownAs": [],
    "id": "did:plc:iec6bspw6ctfbxhrdi4or275",
    "service": [
      {
        "id": "did:plc:iec6bspw6ctfbxhrdi4or275#scitt_scrapi",
        "serviceEndpoint": "http://127.0.0.1:8000/entries/dQFAHH-BizRa8wOxFcHrDgqzT0YQnW-KixBueL5g1Xo",
        "type": "SCITTSCRAPI"
      }
    ],
    "verificationMethod": [
      {
        "controller": "did:plc:iec6bspw6ctfbxhrdi4or275",
        "id": "did:plc:iec6bspw6ctfbxhrdi4or275#atproto",
        "publicKeyMultibase": "zDnaefWRXyXd3xqMRpV9B1WFHBThngbw5GLTc1KwYUvDowNfE",
        "type": "Multikey"
      }
    ]
  },
  "didPublished": false,
  "genesisOperation": {
    "alsoKnownAs": [],
    "prev": null,
    "rotationKeys": [
      "did:key:zDnaefWRXyXd3xqMRpV9B1WFHBThngbw5GLTc1KwYUvDowNfE"
    ],
    "services": {
      "scitt_scrapi": {
        "endpoint": "http://127.0.0.1:8000/entries/dQFAHH-BizRa8wOxFcHrDgqzT0YQnW-KixBueL5g1Xo",
        "type": "SCITTSCRAPI"
      }
    },
    "sig": "PN03lT5pv6LfeRGb87mZkWpbYQkuWlJKrBCXl9tz0zF3r9RCqYpqH55hLhygwiiFk8wamWV3m_XziA04H0MQUA",
    "type": "plc_operation",
    "verificationMethods": {
      "atproto": "did:key:zDnaefWRXyXd3xqMRpV9B1WFHBThngbw5GLTc1KwYUvDowNfE"
    }
  },
  "inlineSignature": {
    "$type": "blue.badge.inlineSignature",
    "cid": "bafyreihc6twroalkon3vvoiptdfc5ngo7nv74lbwpcvzrddeicw45bipou",
    "issuedAt": "2026-09-30T04:50:15.184Z",
    "issuer": "did:plc:iec6bspw6ctfbxhrdi4or275",
    "key": "did:key:zDnaefWRXyXd3xqMRpV9B1WFHBThngbw5GLTc1KwYUvDowNfE",
    "signature": {
      "$bytes": "u+b+Ib2+g5NCa35UiGfYkQGBuBiGH4MMdHNuC5IOZTlT/BzR2qo6C5MA1TgQKb+i27GRcv25MAfLRJaVRmOJUg=="
    }
  },
  "repository": "did:plc:iec6bspw6ctfbxhrdi4or275",
  "signedRecord": {
    "$type": "app.bsky.feed.post",
    "signatures": [
      {
        "$type": "blue.badge.inlineSignature",
        "cid": "bafyreihc6twroalkon3vvoiptdfc5ngo7nv74lbwpcvzrddeicw45bipou",
        "issuedAt": "2026-09-30T04:50:15.184Z",
        "issuer": "did:plc:iec6bspw6ctfbxhrdi4or275",
        "key": "did:key:zDnaefWRXyXd3xqMRpV9B1WFHBThngbw5GLTc1KwYUvDowNfE",
        "signature": {
          "$bytes": "u+b+Ib2+g5NCa35UiGfYkQGBuBiGH4MMdHNuC5IOZTlT/BzR2qo6C5MA1TgQKb+i27GRcv25MAfLRJaVRmOJUg=="
        }
      }
    ],
    "text": "hello from goat"
  },
  "statement": {
    "algorithm": "ES256",
    "coseSign1": "0oRZAQ6kASYDcGFwcGxpY2F0aW9uL2pzb24EWCs2T0NIbVd1dW1wRDExb2Y1UVItR0c5ektRRktNZFp0amhHWUwxemRnYk1VD6IBeLBkaWQ6andrOmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJalJCVDFRNWJFdHVXRkpyU0hwdVNURjNlamxTYTFWUVVuZE1NR3BFVTJkalpEZFJPVkk0YWpFeGVUQWlMQ0o1SWpvaWIxaEVTWGcyZVhSZlExRTNjV3RsVDNOR1lucHVkREpQYm00MWVubEdWRGxOYkY5aFRESm5ja3RCTkNKOQJ0c2NpdHQtYXRwcm90by1zaWduZXKgWDd7IiR0eXBlIjoiYXBwLmJza3kuZmVlZC5wb3N0IiwidGV4dCI6ImhlbGxvIGZyb20gZ29hdCJ9WEAhBuz7MPOjSzRPcxdN8O7XETaaTg-SBAZmXnE-K0IFgQKbrJvtUeZ0kf-IM4LEha5KuXpVD9MySjZcrsGDR3rU",
    "didKey": "did:key:zDnaefWRXyXd3xqMRpV9B1WFHBThngbw5GLTc1KwYUvDowNfE",
    "issuer": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IjRBT1Q5bEtuWFJrSHpuSTF3ejlSa1VQUndMMGpEU2djZDdROVI4ajExeTAiLCJ5Ijoib1hESXg2eXRfQ1E3cWtlT3NGYnpudDJPbm41enlGVDlNbF9hTDJncktBNCJ9",
    "key": {
      "crv": "P-256",
      "kty": "EC",
      "x": "4AOT9lKnXRkHznI1wz9RkUPRwL0jDSgcd7Q9R8j11y0",
      "y": "oXDIx6yt_CQ7qkeOsFbznt2Onn5zyFT9Ml_aL2grKA4"
    },
    "kid": "6OCHmWuumpD11of5QR-GG9zKQFKMdZtjhGYL1zdgbMU"
  },
  "transparentStatement": {
    "coseSign1": "0oRZAQ6kASYDcGFwcGxpY2F0aW9uL2pzb24EWCs2T0NIbVd1dW1wRDExb2Y1UVItR0c5ektRRktNZFp0amhHWUwxemRnYk1VD6IBeLBkaWQ6andrOmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJalJCVDFRNWJFdHVXRkpyU0hwdVNURjNlamxTYTFWUVVuZE1NR3BFVTJkalpEZFJPVkk0YWpFeGVUQWlMQ0o1SWpvaWIxaEVTWGcyZVhSZlExRTNjV3RsVDNOR1lucHVkREpQYm00MWVubEdWRGxOYkY5aFRESm5ja3RCTkNKOQJ0c2NpdHQtYXRwcm90by1zaWduZXKhGQGKgVjO0oRYWKQBJgRYIBtTrgDpLAig7ttBtTAThGd2YBppKR9VqFjeZqlRmdiFD6IBdHRyYW5zcGFyZW5jeS5leGFtcGxlAnRzY2l0dC1hdHByb3RvLXNpZ25lchkBiwGhGQGMoSCBWCaDBQSBWCBc_BAQBfCOrIY6I-0QtiY28cLeR02uIDjwwLUndivh1PZYQCkSVysec4AaBoYR3Kt98MVXCZ1aIk4dR21MhwxadcEgD7gHPblvyOB4jChdse--QDBPOKcaT9b1L1ebOCo7Q2FYN3siJHR5cGUiOiJhcHAuYnNreS5mZWVkLnBvc3QiLCJ0ZXh0IjoiaGVsbG8gZnJvbSBnb2F0In1YQCEG7Psw86NLNE9zF03w7tcRNppOD5IEBmZecT4rQgWBApusm-1R5nSR_4gzgsSFrkq5elUP0zJKNlyuwYNHetQ",
    "entryId": "dQFAHH-BizRa8wOxFcHrDgqzT0YQnW-KixBueL5g1Xo",
    "location": "http://127.0.0.1:8000/entries/dQFAHH-BizRa8wOxFcHrDgqzT0YQnW-KixBueL5g1Xo",
    "receipt": "0oRYWKQBJgRYIBtTrgDpLAig7ttBtTAThGd2YBppKR9VqFjeZqlRmdiFD6IBdHRyYW5zcGFyZW5jeS5leGFtcGxlAnRzY2l0dC1hdHByb3RvLXNpZ25lchkBiwGhGQGMoSCBWCaDBQSBWCBc_BAQBfCOrIY6I-0QtiY28cLeR02uIDjwwLUndivh1PZYQCkSVysec4AaBoYR3Kt98MVXCZ1aIk4dR21MhwxadcEgD7gHPblvyOB4jChdse--QDBPOKcaT9b1L1ebOCo7Q2E"
  }
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

Every call returns one JSON object. Full output, saved for the verify step:

```sh
curl -s -X POST 'http://127.0.0.1:8787/xrpc/blue.scitt.sign' \
  -H 'content-type: application/json' \
  -d '{"$type":"app.bsky.feed.post","text":"hello scitt"}' > /tmp/sign.json

jq . /tmp/sign.json
```

```json
{
  "contentCid": "bafyreig2bkrsvb2hohqwwlv6l7jaapiaeapqxwzr2zxyitgucperrtpeum",
  "contentType": "application/json",
  "did": "did:plc:cgk4ys3qtoubg3btlfg7iz2i",
  "didDocument": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1"
    ],
    "alsoKnownAs": [],
    "id": "did:plc:cgk4ys3qtoubg3btlfg7iz2i",
    "service": [
      {
        "id": "did:plc:cgk4ys3qtoubg3btlfg7iz2i#scitt_scrapi",
        "serviceEndpoint": "http://127.0.0.1:8000/entries/Mysc1-qS4CfkUY6WgW42ev7XzI6r_L4lyCqOQ6zWkmQ",
        "type": "SCITTSCRAPI"
      }
    ],
    "verificationMethod": [
      {
        "controller": "did:plc:cgk4ys3qtoubg3btlfg7iz2i",
        "id": "did:plc:cgk4ys3qtoubg3btlfg7iz2i#atproto",
        "publicKeyMultibase": "zDnaeydns3BxPfXXsa8eB8AUQif9KUsi6gyrXSbPM59N57ds3",
        "type": "Multikey"
      }
    ]
  },
  "didPublished": false,
  "genesisOperation": {
    "alsoKnownAs": [],
    "prev": null,
    "rotationKeys": [
      "did:key:zDnaeydns3BxPfXXsa8eB8AUQif9KUsi6gyrXSbPM59N57ds3"
    ],
    "services": {
      "scitt_scrapi": {
        "endpoint": "http://127.0.0.1:8000/entries/Mysc1-qS4CfkUY6WgW42ev7XzI6r_L4lyCqOQ6zWkmQ",
        "type": "SCITTSCRAPI"
      }
    },
    "sig": "geJnMNXiaPljjN1Tp1A_B1gWCdUMeK8PJOZ8ju18jsUp2FomW47IDfUDsGy6fpqp2K_O2Sn4YaGVP2puFbZMow",
    "type": "plc_operation",
    "verificationMethods": {
      "atproto": "did:key:zDnaeydns3BxPfXXsa8eB8AUQif9KUsi6gyrXSbPM59N57ds3"
    }
  },
  "inlineSignature": {
    "$type": "blue.badge.inlineSignature",
    "cid": "bafyreig2bkrsvb2hohqwwlv6l7jaapiaeapqxwzr2zxyitgucperrtpeum",
    "issuedAt": "2026-09-30T04:57:25.336Z",
    "issuer": "did:plc:cgk4ys3qtoubg3btlfg7iz2i",
    "key": "did:key:zDnaeydns3BxPfXXsa8eB8AUQif9KUsi6gyrXSbPM59N57ds3",
    "signature": {
      "$bytes": "GR8hnsLUdVv046zOrwqskYeRuV1N/TBoTLVPtDPePtsV2POjZ+fdWyMXP2nEX1QozJEgN6I2uLaSxzqHYpHXiw=="
    }
  },
  "repository": "did:plc:cgk4ys3qtoubg3btlfg7iz2i",
  "signedRecord": {
    "$type": "app.bsky.feed.post",
    "signatures": [
      {
        "$type": "blue.badge.inlineSignature",
        "cid": "bafyreig2bkrsvb2hohqwwlv6l7jaapiaeapqxwzr2zxyitgucperrtpeum",
        "issuedAt": "2026-09-30T04:57:25.336Z",
        "issuer": "did:plc:cgk4ys3qtoubg3btlfg7iz2i",
        "key": "did:key:zDnaeydns3BxPfXXsa8eB8AUQif9KUsi6gyrXSbPM59N57ds3",
        "signature": {
          "$bytes": "GR8hnsLUdVv046zOrwqskYeRuV1N/TBoTLVPtDPePtsV2POjZ+fdWyMXP2nEX1QozJEgN6I2uLaSxzqHYpHXiw=="
        }
      }
    ],
    "text": "hello scitt"
  },
  "statement": {
    "algorithm": "ES256",
    "coseSign1": "0oRZAQ6kASYDcGFwcGxpY2F0aW9uL2pzb24EWCtmcGhWY3RhTURSZTYtbE81Q0FmMjRjQlRNdFE0YUpNV2dadzBCc0ZlY2hjD6IBeLBkaWQ6andrOmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJamRXYTJZM1pUZEtVV041WjJjeGJrbEpWVmRGYVhSRWN6TndTM1pWVkZVM2R6QXdkbk14Umxaa04xa2lMQ0o1SWpvaU1reEtRbGRXWmpGVFgxazRkM1pJZEVFMVFreFRVRWxvZURkNlpqQm5hak5GTmpNeFJVUlFRMjVqWXlKOQJ0c2NpdHQtYXRwcm90by1zaWduZXKgWDN7IiR0eXBlIjoiYXBwLmJza3kuZmVlZC5wb3N0IiwidGV4dCI6ImhlbGxvIHNjaXR0In1YQNPG8mv6wepOYokUm7UtyOWH7nx7aD0ZK0Vrv1n5A0OlPccX-iwKlNOVZEqiwfkL95R8tEsNhV9RXoRwYg3J8tU",
    "didKey": "did:key:zDnaeydns3BxPfXXsa8eB8AUQif9KUsi6gyrXSbPM59N57ds3",
    "issuer": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IjdWa2Y3ZTdKUWN5Z2cxbklJVVdFaXREczNwS3ZVVFU3dzAwdnMxRlZkN1kiLCJ5IjoiMkxKQldWZjFTX1k4d3ZIdEE1QkxTUEloeDd6ZjBnajNFNjMxRURQQ25jYyJ9",
    "key": {
      "crv": "P-256",
      "kty": "EC",
      "x": "7Vkf7e7JQcygg1nIIUWEitDs3pKvUTU7w00vs1FVd7Y",
      "y": "2LJBWVf1S_Y8wvHtA5BLSPIhx7zf0gj3E631EDPCncc"
    },
    "kid": "fphVctaMDRe6-lO5CAf24cBTMtQ4aJMWgZw0BsFechc"
  },
  "transparentStatement": {
    "coseSign1": "0oRZAQ6kASYDcGFwcGxpY2F0aW9uL2pzb24EWCtmcGhWY3RhTURSZTYtbE81Q0FmMjRjQlRNdFE0YUpNV2dadzBCc0ZlY2hjD6IBeLBkaWQ6andrOmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJamRXYTJZM1pUZEtVV041WjJjeGJrbEpWVmRGYVhSRWN6TndTM1pWVkZVM2R6QXdkbk14Umxaa04xa2lMQ0o1SWpvaU1reEtRbGRXWmpGVFgxazRkM1pJZEVFMVFreFRVRWxvZURkNlpqQm5hak5GTmpNeFJVUlFRMjVqWXlKOQJ0c2NpdHQtYXRwcm90by1zaWduZXKhGQGKgVjw0oRYWKQBJgRYIBtTrgDpLAig7ttBtTAThGd2YBppKR9VqFjeZqlRmdiFD6IBdHRyYW5zcGFyZW5jeS5leGFtcGxlAnRzY2l0dC1hdHByb3RvLXNpZ25lchkBiwGhGQGMoSCBWEiDBwaCWCBV373A49lLcqtoZ91MO1br_x3Xw9aszrrHYyF-HdKjpVggXPwQEAXwjqyGOiPtELYmNvHC3kdNriA48MC1J3Yr4dT2WEAx_Z40mgqt7O6zXdMSUEO7GIiCLd4qHkIDN3MsQJGSQZ7rdndJFvYfYV8bWcpEMc-gwWozQc1DYJ2-q1KYCiAxWDN7IiR0eXBlIjoiYXBwLmJza3kuZmVlZC5wb3N0IiwidGV4dCI6ImhlbGxvIHNjaXR0In1YQNPG8mv6wepOYokUm7UtyOWH7nx7aD0ZK0Vrv1n5A0OlPccX-iwKlNOVZEqiwfkL95R8tEsNhV9RXoRwYg3J8tU",
    "entryId": "Mysc1-qS4CfkUY6WgW42ev7XzI6r_L4lyCqOQ6zWkmQ",
    "location": "http://127.0.0.1:8000/entries/Mysc1-qS4CfkUY6WgW42ev7XzI6r_L4lyCqOQ6zWkmQ",
    "receipt": "0oRYWKQBJgRYIBtTrgDpLAig7ttBtTAThGd2YBppKR9VqFjeZqlRmdiFD6IBdHRyYW5zcGFyZW5jeS5leGFtcGxlAnRzY2l0dC1hdHByb3RvLXNpZ25lchkBiwGhGQGMoSCBWEiDBwaCWCBV373A49lLcqtoZ91MO1br_x3Xw9aszrrHYyF-HdKjpVggXPwQEAXwjqyGOiPtELYmNvHC3kdNriA48MC1J3Yr4dT2WEAx_Z40mgqt7O6zXdMSUEO7GIiCLd4qHkIDN3MsQJGSQZ7rdndJFvYfYV8bWcpEMc-gwWozQc1DYJ2-q1KYCiAx"
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

Check the inline signature with the Rust CLI:

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
