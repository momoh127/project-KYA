"""AGENTTRUST-ED25519-V1 request signing (byte-compatible with the TypeScript reference).

String to sign (UTF-8, newline-separated):
    AGENTTRUST-ED25519-V1
    <METHOD uppercased>
    <path including query>
    <unix timestamp seconds>
    <nonce>
    <hex SHA-256 of the exact request body bytes>
"""

import base64
import hashlib
import secrets
import time
from typing import Callable, Dict, Optional, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SIGNATURE_SCHEME = "AGENTTRUST-ED25519-V1"

HEADER_CREDENTIAL = "x-agenttrust-credential"
HEADER_TIMESTAMP = "x-agenttrust-timestamp"
HEADER_NONCE = "x-agenttrust-nonce"
HEADER_SIGNATURE = "x-agenttrust-signature"

#: Signs bytes and returns a 64-byte Ed25519 signature. Lets the long-lived key
#: live outside the agent/LLM process (sidecar, OS keychain, KMS/HSM).
Signer = Callable[[bytes], bytes]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def body_sha256(body: Union[bytes, str]) -> str:
    return hashlib.sha256(body.encode("utf-8") if isinstance(body, str) else body).hexdigest()


def build_string_to_sign(method: str, path: str, timestamp: str, nonce: str, body_sha256_hex: str) -> str:
    return "\n".join([SIGNATURE_SCHEME, method.upper(), path, timestamp, nonce, body_sha256_hex])


def load_private_key(pem: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("private key must be Ed25519")
    return key


def local_signer(private_key_pem: str) -> Signer:
    """DEVELOPMENT ONLY: holds the key in this process. Production: a sidecar/KMS-backed Signer."""
    key = load_private_key(private_key_pem)
    return key.sign


def generate_key_pair() -> Tuple[str, str]:
    """Returns (public_key_pem, private_key_pem) for a new Ed25519 key (SPKI / PKCS#8 PEM)."""
    key = Ed25519PrivateKey.generate()
    public_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    private_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode("ascii")
    return public_pem, private_pem


def sign_request(
    credential_id: str,
    signer: Signer,
    method: str,
    path: str,
    body: Union[bytes, str] = b"",
    *,
    timestamp: Optional[int] = None,
    nonce: Optional[str] = None,
) -> Dict[str, str]:
    ts = str(int(time.time()) if timestamp is None else timestamp)
    n = nonce if nonce is not None else secrets.token_hex(16)
    to_sign = build_string_to_sign(method, path, ts, n, body_sha256(body))
    signature = signer(to_sign.encode("utf-8"))
    return {
        HEADER_CREDENTIAL: credential_id,
        HEADER_TIMESTAMP: ts,
        HEADER_NONCE: n,
        HEADER_SIGNATURE: b64url(signature),
    }
