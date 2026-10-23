"""Client for an AI agent's RUNTIME (not the LLM itself).

Expose only high-level tools to the model (e.g. "request purchase
authorization"); keep this client and its keys in the runtime. The agent never
holds payment credentials: the only way to pay is ``transactions.execute``,
which the AgentTrust gateway enforces.
"""

import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._http import DEFAULT_TIMEOUT, encode_json, send
from .signing import Signer, local_signer, sign_request

Json = Dict[str, Any]


class _Session:
    def __init__(self, session_id: str, key: Ed25519PrivateKey, expires_at: float) -> None:
        self.id = session_id
        self.key = key
        self.expires_at = expires_at


class AgentTrust:
    """Agent client.

    The long-lived WORKLOAD key (``workload_signer`` / ``private_key_pem``) can
    only mint short-lived SESSION keys. Every API call is signed with the
    current session key (in memory, never exported), rotated before expiry.

    Inputs and outputs are plain dicts with exactly the field names of the API
    reference (camelCase), e.g. ``{"amountCents": 48000, "currency": "USD"}``.
    """

    def __init__(
        self,
        base_url: str,
        credential_id: str,
        *,
        workload_signer: Optional[Signer] = None,
        private_key_pem: Optional[str] = None,
        session_ttl_seconds: int = 900,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        signer = workload_signer or (local_signer(private_key_pem) if private_key_pem else None)
        if signer is None:
            raise ValueError("AgentTrust: provide workload_signer (or private_key_pem for local development)")
        self._base_url = base_url.rstrip("/")
        self._credential_id = credential_id
        self._workload_signer = signer
        self._ttl = session_ttl_seconds
        self._timeout = timeout
        self._session: Optional[_Session] = None
        self._lock = threading.Lock()
        self.sessions = _Sessions(self)
        self.instructions = _AgentInstructions(self)
        self.authorizations = _AgentAuthorizations(self)
        self.transactions = _AgentTransactions(self)

    # -- sessions ---------------------------------------------------------------
    def _ensure_session(self, force: bool = False) -> _Session:
        with self._lock:
            s = self._session
            if not force and s is not None and s.expires_at - time.time() > 60:
                return s
            key = Ed25519PrivateKey.generate()
            public_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
            path = "/v1/agent-sessions"
            body = encode_json({"publicKeyPem": public_pem, "ttlSeconds": self._ttl})
            headers = sign_request(self._credential_id, self._workload_signer, "POST", path, body)
            res = send("POST", self._base_url + path, headers, body, self._timeout)
            self._session = _Session(res["sessionId"], key, _parse_iso(res["expiresAt"]))
            return self._session

    def _request(self, method: str, path: str, payload: Optional[Any] = None) -> Any:
        session = self._ensure_session()
        body = encode_json(payload) if payload is not None else b""
        headers = sign_request(session.id, session.key.sign, method, path, body)
        return send(method, self._base_url + path, headers, body, self._timeout)


class _Sessions:
    def __init__(self, c: AgentTrust) -> None:
        self._c = c

    def current(self) -> str:
        return self._c._ensure_session().id

    def rotate(self) -> str:
        """Force a fresh session key now (e.g. after suspected exposure)."""
        return self._c._ensure_session(force=True).id


class _AgentInstructions:
    """Read-only view of the approved purchase instructions assigned to this agent."""

    def __init__(self, c: AgentTrust) -> None:
        self._c = c

    def list(self) -> Json:
        return self._c._request("GET", "/v1/agent/purchase-instructions")

    def get(self, instruction_id: str) -> Json:
        return self._c._request("GET", f"/v1/agent/purchase-instructions/{_enc(instruction_id)}")


class _AgentAuthorizations:
    def __init__(self, c: AgentTrust) -> None:
        self._c = c

    def create(self, request: Json) -> Json:
        """Ask whether this payment is authorized. Returns decision ALLOW | REVIEW | DENY.

        Required: idempotencyKey, action="purchase", payee, amountCents, currency.
        For ALLOW you will normally also need supplierId, purchaseInstructionId and invoiceId.
        A token is present only when status == "allowed" (single use, short lived).
        """
        return self._c._request("POST", "/v1/authorizations", request)

    def get(self, authorization_id: str) -> Json:
        return self._c._request("GET", f"/v1/authorizations/{_enc(authorization_id)}")


class _AgentTransactions:
    def __init__(self, c: AgentTrust) -> None:
        self._c = c

    def execute(self, token: str, expected: Json) -> Json:
        """Executes through the enforcing gateway. There is no other payment path.

        ``expected`` states what YOU believe you are paying (supplierId, amountCents,
        currency, purchaseOrderId, invoiceId); any mismatch with the authorization fails.
        Provider acceptance is not payment: only status "settled" means money moved.
        On in-flight statuses, retry with the SAME token (it reconciles, never re-pays).
        """
        return self._c._request("POST", "/v1/transactions/execute", {"token": token, "expected": expected})

    def get(self, transaction_id: str) -> Json:
        return self._c._request("GET", f"/v1/transactions/{_enc(transaction_id)}")


def _enc(value: str) -> str:
    return quote(value, safe="")


def _parse_iso(value: str) -> float:
    from datetime import datetime

    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
