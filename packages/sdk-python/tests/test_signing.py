"""Cross-language conformance: reproduce the TypeScript reference vectors byte for byte."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from agenttrust.signing import body_sha256, build_string_to_sign, b64url, load_private_key, local_signer, sign_request

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "identity" / "test" / "vectors" / "request-signing.json").read_text("utf-8"))


@pytest.mark.parametrize("v", VECTORS["vectors"], ids=lambda v: v["name"])
def test_vector(v):
    assert body_sha256(v["body"]) == v["bodySha256"]
    assert build_string_to_sign(v["method"], v["path"], str(v["timestamp"]), v["nonce"], v["bodySha256"]) == v["stringToSign"]
    headers = sign_request(
        v["credentialId"], local_signer(VECTORS["privateKeyPem"]), v["method"], v["path"], v["body"].encode("utf-8"),
        timestamp=v["timestamp"], nonce=v["nonce"],
    )
    assert headers == v["headers"]


def test_signature_verifies_with_reference_public_key():
    v = VECTORS["vectors"][0]
    public = serialization.load_pem_public_key(VECTORS["publicKeyPem"].encode())
    import base64

    sig = v["headers"]["x-agenttrust-signature"]
    public.verify(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)), v["stringToSign"].encode("utf-8"))


def test_base64url_has_no_padding():
    assert b64url(b"\x00" * 64).find("=") == -1


def test_rejects_non_ed25519_keys():
    from cryptography.hazmat.primitives.asymmetric import ec

    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    with pytest.raises(TypeError):
        load_private_key(pem)
