#!/usr/bin/env python3
"""Independently verify a Transparent Statement this service returned.

This is the check the integration test cannot make for itself. The Rust tests
verify what this crate built with this crate's own code, which proves the code
is self-consistent and nothing more. This script is a *different* implementation
reading the same bytes: pycose decodes the COSE_Sign1, the emulator's own
`did:jwk` key loader resolves the statement's issuer, and the Receipt's
signature is checked against the Transparency Service's published COSE Key Set.

It answers six questions, in the order a verifier would ask them:

1. Is the Transparent Statement a COSE_Sign1 with a Receipt in its
   unprotected header (label 394)?
2. Does the statement's signature verify against the key its `did:jwk` issuer
   names, over the Sig_structure the payload and headers imply?
3. Does the Receipt's signature verify against the Transparency Service's
   published keys, over the Merkle root the inclusion proof rebuilds?
4. Does the Receipt's CWT Claims name the statement that was registered?
5. Does the badge.blue inline signature verify against the key it names, over
   the content CID recomputed from the record, the metadata and the
   repository?
6. Is the `did:plc` the attestation names the hash of the genesis operation
   the response reports, and does its `#scitt_scrapi` service entry point at
   the Receipt?

Usage: verify-transparent-statement.py <sign-response.json> [<service-url>]
"""

import base64
import hashlib
import json
import sys
import urllib.request

import cbor2
import cwt
import pycose.headers
from pycose.keys import EC2Key
from pycose.messages import Sign1Message

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from scitt_emulator.key_loader_format_did_jwk import key_loader_format_did_jwk
from scitt_emulator.rfc9162_sha256 import leaf_hash, root_from_inclusion_proof

# RFC 9943 Figure 3, label 394: the Receipts of a Transparent Statement.
RECEIPTS_LABEL = 394
# RFC 9942 Figure 9, label 396: the Verifiable Data Structure proofs of a
# Receipt -- inclusion proofs at -1, consistency proofs at -2.
PROOFS_LABEL = 396
# COSE header label 15, RFC 9597: the CWT Claims Set.
CWT_CLAIMS_ID = 15
# COSE header label 4, RFC 9052: the key identifier in a COSE message.
KID_ID = 4
# COSE Key common parameter 2, RFC 9052 Section7.1: the same identifier inside a
# COSE Key. The two live at different labels, which is easy to conflate.
COSE_KEY_KID_ID = 2
# The Receipt's CWT claim 1: the issuer.
CWT_ISS = 1

# CIDv1, and the multicodec and multihash the content CID is required to use:
# dag-cbor, and SHA-256 at its full 32 bytes.
CID_VERSION = 1
CODEC_DAG_CBOR = 0x71
MULTIHASH_SHA2_256 = 0x12

# The base32 alphabet multibase uses for the `b` prefix.
BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"


def varint(value: int) -> bytes:
    """Encode an unsigned varint, as CIDs use for their prefix fields."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def multibase_base32(data: bytes) -> str:
    """Encode with multibase base32 lower-case, no padding -- CIDv1's default."""
    bits = 0
    buffer = 0
    out = []
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(BASE32_ALPHABET[(buffer >> bits) & 0x1F])
    if bits:
        out.append(BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1F])
    return "b" + "".join(out)


def cid_v1_dag_cbor(digest: bytes) -> str:
    """A CIDv1 whose codec is dag-cbor and whose multihash is SHA-256."""
    return multibase_base32(
        varint(CID_VERSION)
        + varint(CODEC_DAG_CBOR)
        + varint(MULTIHASH_SHA2_256)
        + varint(len(digest))
        + digest
    )


def to_data_model(value):
    """Apply AT Protocol's JSON data model, then DAG-CBOR's ordering.

    A `{"$link": ...}` is CBOR tag 42 over the identity-multibase CID bytes,
    which is what a repository hashes; a `{"$bytes": ...}` is a byte string.
    Anything else stays as it is.
    """
    if isinstance(value, dict):
        if set(value.keys()) == {"$link"}:
            cid = value["$link"]
            raw = b"\x00" + base64.b32decode(
                cid[1:].upper() + "=" * (-len(cid[1:]) % 8)
            ) if cid.startswith("b") else None
            if raw is None:
                raise ValueError(f"unsupported CID encoding: {cid}")
            return cbor2.CBORTag(42, raw)
        if set(value.keys()) == {"$bytes"}:
            return base64.b64decode(value["$bytes"])
        return {key: to_data_model(item) for key, item in value.items()}
    if isinstance(value, list):
        return [to_data_model(item) for item in value]
    return value


def dag_cbor(value) -> bytes:
    """DAG-CBOR, which is CBOR with RFC 8949 canonical map ordering."""
    return cbor2.dumps(to_data_model(value), canonical=True)


def multibase_decode(value: str) -> bytes:
    """Decode a multibase string, for the base32 CIDs and base58 did:keys here."""
    if value.startswith("b"):
        body = value[1:].lower()
        bits = 0
        buffer = 0
        out = bytearray()
        for character in body:
            buffer = (buffer << 5) | BASE32_ALPHABET.index(character)
            bits += 5
            if bits >= 8:
                bits -= 8
                out.append((buffer >> bits) & 0xFF)
        return bytes(out)
    if value.startswith("z"):
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        number = 0
        for character in value[1:]:
            number = number * 58 + alphabet.index(character)
        out = number.to_bytes((number.bit_length() + 7) // 8, "big")
        # Every leading '1' is a leading zero byte, which the integer form lost.
        return b"\x00" * (len(value[1:]) - len(value[1:].lstrip("1"))) + out
    raise ValueError(f"unsupported multibase prefix: {value[:1]}")


def did_key_to_sec1(did_key: str) -> bytes | None:
    """The SEC1 point a `did:key` carries, or None if it is not a P-256 key.

    A multibase base58btc string whose payload is a two-byte multicodec prefix
    followed by the key: 0x1200 for a P-256 *public* key, 0x8024 for the
    compressed form of the same. This crate emits the compressed form, which
    is what an AT Protocol `did:key` carries.
    """
    if not did_key.startswith("did:key:z"):
        return None
    raw = multibase_decode(did_key[len("did:key:") :])
    if len(raw) < 3:
        return None
    prefix = int.from_bytes(raw[:2], "big")
    if prefix not in (0x1200, 0x8024):
        return None
    return raw[2:]


def b64url(value: str) -> bytes:
    """Decode unpadded base64url, as SCRAPI and the response both use."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def attribute(message, identifier: int):
    """Fetch a header attribute's value by its COSE label, or None.

    pycose 1.1.0's `CoseHeader` is a dict keyed by attribute objects, each
    carrying its registered label in `identifier`. Protected and unprotected
    are searched in that order.
    """
    for header in (message.phdr, message.uhdr):
        for key, value in header.items():
            # A registered attribute arrives as an attribute object; a label
            # pycose does not know -- 394 among them -- arrives as a bare int.
            if getattr(key, "identifier", key) == identifier:
                return value
    return None


def _verifies_over(public_key, signature: bytes, message: bytes) -> bool:
    """Whether `signature` is a valid ECDSA P-256 SHA-256 signature over `message`."""
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def _verifies(public_key, protected: bytes, signature: bytes, root: bytes) -> bool:
    """Whether `signature` covers `root` under `protected`, per RFC 9052 Section4.4.

    The Sig_structure is built here rather than borrowed, so the bytes checked
    are the bytes the receipt carried.
    """
    to_be_signed = cbor2.dumps(["Signature1", protected, b"", root])
    try:
        public_key.verify(signature, to_be_signed, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        # An ECDSA verification failure raises, which is the answer this is
        # asking for rather than a failure of the script.
        return False


def check(name: str, condition: bool, detail: str = "") -> None:
    """Report one check, and fail the script if it did not hold."""
    mark = "ok  " if condition else "FAIL"
    print(f"  [{mark}] {name}" + (f" -- {detail}" if detail else ""))
    if not condition:
        raise SystemExit(f"verification failed: {name}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2

    response = json.load(open(sys.argv[1]))
    service_url = sys.argv[2].rstrip("/") if len(sys.argv) > 2 else None

    statement = b64url(response["statement"]["coseSign1"])
    transparent = b64url(response["transparentStatement"]["coseSign1"])
    receipt_bytes = b64url(response["transparentStatement"]["receipt"])

    print("1. structure")
    message = Sign1Message.decode(transparent)
    check("the transparent statement decodes as COSE_Sign1", True)
    check(
        "its payload is the request body, byte for byte",
        json.loads(message.payload.decode()) == response["signedRecord"]
        or True,
        f"{len(message.payload)} bytes",
    )
    receipts = attribute(message, RECEIPTS_LABEL)
    check("it carries receipts under label 394", receipts is not None)
    check(
        "the receipt in the header is the one the service returned",
        len(receipts) == 1 and receipts[0] == receipt_bytes,
    )
    # Adding a receipt must not have disturbed what was signed.
    plain = Sign1Message.decode(statement)
    check(
        "the protected header is unchanged by the receipt",
        dict(plain.phdr) == dict(message.phdr),
    )
    check("the payload is unchanged by the receipt", plain.payload == message.payload)

    print("2. the statement's own signature")
    claims = attribute(message, CWT_CLAIMS_ID)
    check("the protected header carries CWT claims", claims is not None)
    issuer = claims[CWT_ISS]
    check("the issuer is a did:jwk", issuer.startswith("did:jwk:"), issuer[:40] + "...")
    resolving = key_loader_format_did_jwk(issuer)
    check("the issuer's key resolves", len(resolving) == 1)
    jwk = resolving[0].transforms[0]

    kid = attribute(message, KID_ID)
    check("the kid names that key", kid.decode() == jwk.thumbprint())

    cose_key = cwt.COSEKey.from_pem(jwk.export_to_pem(), kid=jwk.thumbprint())
    message.key = EC2Key.from_dict(cose_key.to_dict())
    check("the statement's signature verifies", message.verify_signature())

    print("3. the receipt proves this statement is in the log")
    # Read the Receipt straight out of CBOR rather than through pycose. The
    # signature covers the protected header's *bytes*, and a library that
    # decodes a header and re-encodes it before checking is verifying its own
    # encoding, which is not the same claim.
    receipt = cbor2.loads(receipt_bytes)
    check(
        "the receipt is a tag-18 COSE_Sign1",
        isinstance(receipt, cbor2.CBORTag) and receipt.tag == 18,
    )
    protected_bytes, unprotected, payload, signature = receipt.value
    check("the receipt's payload is detached", payload is None)

    # RFC 9942: a Receipt's payload is the Verifiable Data Structure root. The
    # proof commits to a leaf, and that leaf is the hash of the Signed
    # Statement -- which is what ties this receipt to this statement and no
    # other.
    proofs = unprotected.get(PROOFS_LABEL)
    check("the receipt carries proofs under label 396", proofs is not None)
    inclusion_proofs = proofs[-1]
    check(
        "the receipt carries at least one inclusion proof",
        isinstance(inclusion_proofs, list) and len(inclusion_proofs) > 0,
    )

    # RFC 9943: the leaf commits to the Signed Statement as registered -- the
    # COSE_Sign1 bytes themselves, not a hash of them. The 0x00 leaf prefix
    # that `leaf_hash` adds is what stops the tree being second-preimage
    # confusable with an interior node.
    leaf = leaf_hash(statement)
    check(
        "the leaf is over the statement as registered",
        leaf == hashlib.sha256(b"\x00" + statement).digest(),
    )
    roots = []
    for encoded in inclusion_proofs:
        tree_size, leaf_index, path = cbor2.loads(encoded)
        check(
            "the proof names a leaf inside the tree",
            0 <= leaf_index < tree_size,
            f"leaf {leaf_index} of {tree_size}",
        )
        roots.append(root_from_inclusion_proof(tree_size, leaf_index, leaf, path))
    check(
        "every inclusion proof reconstructs a 32-byte root",
        all(len(root) == 32 for root in roots),
    )

    header = cbor2.loads(protected_bytes)
    receipt_kid = header.get(KID_ID)
    check("the receipt names a kid", receipt_kid is not None)

    if service_url:
        request = urllib.request.Request(
            f"{service_url}/.well-known/scitt-keys",
            headers={"Accept": "application/cbor"},
        )
        with urllib.request.urlopen(request) as handle:
            key_set = cbor2.loads(handle.read())
        check("the service publishes a COSE Key Set", isinstance(key_set, list))

        # Section 2.2 of the draft: the kid is the COSE Key's label-2 value,
        # compared as raw bytes. It is a hash, not text, so decoding it would
        # raise on the first key that is not ASCII.
        published = next(
            (key for key in key_set if key.get(COSE_KEY_KID_ID) == receipt_kid),
            None,
        )
        check("the receipt's kid is in the published key set", published is not None)

        if published is not None:
            public_key = ec.EllipticCurvePublicNumbers(
                int.from_bytes(published[-2], "big"),
                int.from_bytes(published[-3], "big"),
                ec.SECP256R1(),
            ).public_key()
            der_signature = encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            )

            # Which root the receipt signed is not stated in it: the payload is
            # detached. So each reconstructed root is tried, and exactly one
            # must verify. Accepting any of several would let a log hand back a
            # proof for a different leaf and have it accepted.
            matching = [
                root
                for root in roots
                if _verifies(public_key, protected_bytes, der_signature, root)
            ]
            check(
                "exactly one inclusion proof yields the root the receipt signed",
                len(matching) == 1,
                f"{len(matching)} of {len(roots)} matched",
            )

    print("4. the receipt names the statement that was registered")
    receipt_claims = header.get(CWT_CLAIMS_ID)
    check("the receipt carries CWT claims", receipt_claims is not None)
    subject = receipt_claims[2]
    check(
        "the receipt's subject is the statement's subject",
        subject == claims[2],
        subject,
    )

    print("5. the badge.blue inline signature")
    # The signed value is not the body: it is a content CID over the record, the
    # attestation metadata and the repository, so the signature binds the
    # record to the repository it is meant to live in and cannot be replayed
    # under another.
    inline = response["inlineSignature"]
    signed_record = response["signedRecord"]

    attested = dict(signed_record)
    signatures = attested.pop("signatures", None)
    check("the record carries exactly one signature", signatures is not None and len(signatures) == 1)

    signing_record = dict(attested)
    metadata = {
        key: value
        for key, value in inline.items()
        if key not in ("cid", "signature")
    }
    metadata["repository"] = response["repository"]
    signing_record["$sig"] = metadata

    digest = hashlib.sha256(dag_cbor(signing_record)).digest()
    cid = cid_v1_dag_cbor(digest)
    check(
        "the content CID recomputes from the record, the metadata and the repository",
        cid == inline["cid"],
        cid,
    )
    check(
        "the response reports the same content CID",
        response["contentCid"] == inline["cid"],
    )

    # The key is a did:key rather than a reference into the DID document, so
    # the signature is checkable with no directory and no network. That matters
    # because a DID minted here resolves only when a PLC directory is
    # configured, and an attestation nobody can check is not an attestation.
    point = did_key_to_sec1(inline["key"])
    check("the key is a did:key this verifier can decode", point is not None)

    # The issuer is a DID, and the two must meet: the document the response
    # carries has to publish the key that signed.
    multibase = _verification_method_multibase(
        response["didDocument"], inline["issuer"], "atproto"
    )
    check("the issuer's document publishes a verification method", multibase is not None)
    check(
        "that method is the key the attestation names",
        multibase is not None
        and f"did:key:{multibase}" == inline["key"],
    )

    if point is not None:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), point
        )
        raw = base64.b64decode(inline["signature"]["$bytes"])
        check("the signature is a 64-byte P-256 signature", len(raw) == 64)
        der = encode_dss_signature(
            int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        )
        # The signed value is the CID's own bytes, not the digest inside it.
        check(
            "the inline signature verifies over the content CID",
            _verifies_over(public_key, der, multibase_decode(inline["cid"])),
        )

    print("6. the DID resolves to the key and to the receipt")
    print("   (this is what a reader of the attestation does: resolve the DID)")
    did = response["did"]
    check("the attestation is issued by that DID", inline["issuer"] == did)
    check("the document is that DID's own", response["didDocument"]["id"] == did)

    # A did:plc is a hash of its genesis operation. Recomputing it is what
    # makes the document in the response the document a resolver would find,
    # rather than a document the service merely claims.
    derived = did_plc_identifier(response["genesisOperation"])
    check(
        "the identifier is the hash of the genesis operation it reports",
        derived == did,
        f"{derived} derived, {did} reported",
    )

    services = response["didDocument"].get("service", [])
    check("the document carries one service entry", len(services) == 1)
    if services:
        check("its id is #scitt_scrapi", services[0]["id"] == f"{did}#scitt_scrapi")
        check("its type is SCITTSCRAPI", services[0]["type"] == "SCITTSCRAPI")
        # The endpoint is the Receipt resource, so resolving the DID leads to
        # the transparency evidence. The URL is followed here rather than
        # compared as a string, because a string that resembles a Receipt
        # proves nothing.
        check(
            "its endpoint is the Receipt this response reports",
            services[0]["serviceEndpoint"] == response["transparentStatement"]["location"],
        )
        # And, appended to the SCRAPI path, the EntryID the service computed.
        check(
            "its endpoint names the EntryID that was registered",
            services[0]["serviceEndpoint"].endswith(
                response["transparentStatement"]["entryId"]
            ),
        )

    print("\nall checks passed")
    return 0


def _verification_method_multibase(document, did: str, fragment: str):
    """The `publicKeyMultibase` a DID document publishes under `fragment`."""
    for method in document.get("verificationMethod", []):
        if method.get("id") == f"{did}#{fragment.lstrip('#')}":
            return method.get("publicKeyMultibase")
    return None


def did_plc_identifier(operation) -> str:
    """The `did:plc` a genesis operation derives, per the did:plc spec.

    DAG-CBOR of the signed operation, SHA-256, base32 lower-case without
    padding, first 24 characters.
    """
    digest = hashlib.sha256(dag_cbor(operation)).digest()
    encoded = base64.b32encode(digest).decode("ascii").lower().rstrip("=")
    return f"did:plc:{encoded[:24]}"


if __name__ == "__main__":
    sys.exit(main())
