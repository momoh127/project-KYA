"""Hosted-sandbox helper (evaluation only: no real money; persona logins are development tokens).

A sandbox organization comes with three personas so one developer can exercise
dual control alone:
  - ``admin``    you: registers agents, enters suppliers, POs, instructions, invoices
  - ``verifier`` a second administrator: verifies supplier bank details you entered
  - ``approver`` approves purchase instructions and grants delegations
"""

import threading
import time
from typing import Any, Dict, Optional, Tuple

from ._http import DEFAULT_TIMEOUT, encode_json, send
from .admin import AgentTrustAdmin
from .agent import AgentTrust, _enc, _parse_iso
from .signing import generate_key_pair

Json = Dict[str, Any]

SANDBOX_KEY_HEADER = "x-agenttrust-sandbox-key"
PERSONAS = ("admin", "verifier", "approver")

#: Sandbox-only bank details for the example supplier (not a real account).
SANDBOX_SUPPLIER_BANK: Json = {"type": "us_ach", "routingNumber": "021000021", "accountNumber": "4000123456"}


class AgentTrustSandbox:
    def __init__(self, base_url: str, sandbox_key: str, *, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.base_url = base_url.rstrip("/")
        self._key = sandbox_key
        self._timeout = timeout
        self._cache: Dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()

    @classmethod
    def signup(cls, base_url: str, organization_name: str, email: str, *, timeout: float = DEFAULT_TIMEOUT) -> Tuple["AgentTrustSandbox", Json]:
        """Creates a sandbox organization. Keep ``account["sandboxKey"]``: it is shown only once."""
        account = send("POST", base_url.rstrip("/") + "/v1/sandbox/signup", {}, encode_json({"organizationName": organization_name, "email": email}), timeout)
        return cls(base_url, account["sandboxKey"], timeout=timeout), account

    def _call(self, method: str, path: str, payload: Optional[Any] = None) -> Any:
        body = encode_json(payload) if payload is not None else b""
        return send(method, self.base_url + path, {SANDBOX_KEY_HEADER: self._key}, body, self._timeout)

    def token(self, persona: str) -> str:
        """A short-lived access token for one persona (cached; refreshed 5 minutes before expiry)."""
        if persona not in PERSONAS:
            raise ValueError(f"persona must be one of {PERSONAS}")
        with self._lock:
            hit = self._cache.get(persona)
            if hit and hit[1] - time.time() > 300:
                return hit[0]
            res = self._call("POST", "/v1/sandbox/token", {"persona": persona})
            self._cache[persona] = (res["accessToken"], _parse_iso(res["expiresAt"]))
            return res["accessToken"]

    def as_persona(self, persona: str) -> AgentTrustAdmin:
        """An admin/approver client acting as ``persona``, with automatic token refresh."""
        return AgentTrustAdmin(self.base_url, lambda: self.token(persona), timeout=self._timeout)

    def advance_payment(self, transaction_id: str, status: str, duplicate_delivery: bool = False) -> Json:
        """Plays the payment provider for one of YOUR sandbox payments (signed webhook path).

        Only ``settled`` marks the invoice paid; ``returned``/``reversed`` never auto-repay.
        """
        return self._call("POST", f"/v1/sandbox/transactions/{_enc(transaction_id)}/advance", {"status": status, "duplicateDelivery": duplicate_delivery})

    def progress(self) -> Json:
        """How far this sandbox got through the integration, with minutes from signup."""
        return self._call("GET", "/v1/sandbox/progress")

    def create_verified_supplier(self, name: str = "Northwind Industrial Supply", bank: Optional[Json] = None) -> Json:
        """Supplier entered by ``admin`` and verified out of band by ``verifier`` (dual control)."""
        bank = bank or SANDBOX_SUPPLIER_BANK
        supplier = self.as_persona("admin").suppliers.create({"name": name, "paymentDestination": bank})
        last4 = (bank.get("accountNumber") or bank.get("iban") or "")[-4:]
        self.as_persona("verifier").suppliers.verify_payment_destination(
            supplier["id"],
            evidence="Sandbox: called supplier AP at the number on the signed master agreement; confirmed account.",
            confirmed_last4=last4,
        )
        return {"supplierId": supplier["id"], "bank": bank}

    def register_agent(self, name: str = "Procurement agent") -> Json:
        """Registers an agent and returns {"agentId", "credentialId", "privateKeyPem", "client"}.

        DEVELOPMENT ONLY key handling: the private key is generated in this
        process. In production generate it in the agent's key holder (sidecar,
        KMS) and register only the public key.
        """
        admin = self.as_persona("admin")
        users = admin.users.list()["users"]
        owner = next((u for u in users if u["role"] == "admin" and not u["email"].startswith("verifier+")), users[0])
        public_pem, private_pem = generate_key_pair()
        reg = admin.agents.register({"name": name, "ownerUserId": owner["id"], "publicKeyPem": public_pem})
        return {
            "agentId": reg["agent"]["id"],
            "credentialId": reg["credential"]["id"],
            "privateKeyPem": private_pem,
            "client": AgentTrust(self.base_url, reg["credential"]["id"], private_key_pem=private_pem, timeout=self._timeout),
        }
