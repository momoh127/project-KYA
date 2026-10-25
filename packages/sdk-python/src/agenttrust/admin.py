"""Client for human administrators and approvers. Agents must never hold these credentials."""

from typing import Any, Callable, Dict, List, Optional, Union
from urllib.parse import quote, urlencode

from ._http import DEFAULT_TIMEOUT, encode_json, send

Json = Dict[str, Any]
#: A static bearer token, or a callable returning a current one (called per request).
AccessTokenSource = Union[str, Callable[[], str]]


class AgentTrustAdmin:
    """Back-office client: suppliers, POs, purchase instructions, approvals, audit.

    Dicts in, dicts out, with the API reference's field names (camelCase).
    """

    def __init__(self, base_url: str, access_token: AccessTokenSource, *, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = access_token
        self._timeout = timeout
        self.users = _Users(self)
        self.agents = _Agents(self)
        self.delegations = _Delegations(self)
        self.suppliers = _Suppliers(self)
        self.purchase_orders = _PurchaseOrders(self)
        self.invoices = _Invoices(self)
        self.instructions = _Instructions(self)
        self.receipts = _Receipts(self)
        self.authorizations = _Authorizations(self)
        self.transactions = _Transactions(self)
        self.policies = _Policies(self)
        self.audit = _Audit(self)

    def request(self, method: str, path: str, payload: Optional[Any] = None) -> Any:
        token = self._token if isinstance(self._token, str) else self._token()
        body = encode_json(payload) if payload is not None else b""
        return send(method, self._base_url + path, {"authorization": f"Bearer {token}"}, body, self._timeout)

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, payload: Optional[Any] = None) -> Any:
        return self.request("POST", path, payload if payload is not None else {})

    def put(self, path: str, payload: Any) -> Any:
        return self.request("PUT", path, payload)

    def patch(self, path: str, payload: Any) -> Any:
        return self.request("PATCH", path, payload)


class _R:
    def __init__(self, c: AgentTrustAdmin) -> None:
        self._c = c


class _Users(_R):
    def list(self) -> Json:
        return self._c.get("/v1/users")

    def create(self, user: Json) -> Json:
        return self._c.post("/v1/users", user)


class _Agents(_R):
    def register(self, agent: Json) -> Json:
        """Registers an agent with its workload PUBLIC key; returns {"agent", "credential": {"id"}}."""
        return self._c.post("/v1/agents", agent)

    def list(self) -> Json:
        return self._c.get("/v1/agents")

    def get(self, agent_id: str) -> Json:
        return self._c.get(f"/v1/agents/{_enc(agent_id)}")

    def revoke(self, agent_id: str, reason: Optional[str] = None) -> Json:
        """Kill switch: a revoked agent can never transact again."""
        return self._c.post(f"/v1/agents/{_enc(agent_id)}/revoke", {"reason": reason} if reason else {})

    def reactivate(self, agent_id: str, reason: Optional[str] = None) -> Json:
        return self._c.post(f"/v1/agents/{_enc(agent_id)}/reactivate", {"reason": reason} if reason else {})


class _Delegations(_R):
    """The most an agent may spend (a ceiling). Never authorizes a specific purchase by itself."""

    def create(self, delegation: Json) -> Json:
        return self._c.post("/v1/delegations", delegation)

    def get(self, delegation_id: str) -> Json:
        return self._c.get(f"/v1/delegations/{_enc(delegation_id)}")

    def revoke(self, delegation_id: str) -> Json:
        return self._c.post(f"/v1/delegations/{_enc(delegation_id)}/revoke", {})


class _Suppliers(_R):
    def create(self, supplier: Json) -> Json:
        return self._c.post("/v1/suppliers", supplier)

    def list(self) -> Json:
        return self._c.get("/v1/suppliers")

    def get(self, supplier_id: str) -> Json:
        return self._c.get(f"/v1/suppliers/{_enc(supplier_id)}")

    def update(self, supplier_id: str, changes: Json) -> Json:
        return self._c.patch(f"/v1/suppliers/{_enc(supplier_id)}", changes)

    def verify_payment_destination(self, supplier_id: str, evidence: str, confirmed_last4: str) -> Json:
        """Dual control: must be a DIFFERENT administrator than the one who entered the bank details."""
        return self._c.post(f"/v1/suppliers/{_enc(supplier_id)}/verify-payment-destination", {"evidence": evidence, "confirmedLast4": confirmed_last4})

    def account_verification(self, supplier_id: str, payment_destination: Json) -> Json:
        return self._c.post(f"/v1/suppliers/{_enc(supplier_id)}/account-verification", {"paymentDestination": payment_destination})


class _PurchaseOrders(_R):
    def create(self, po: Json) -> Json:
        return self._c.post("/v1/purchase-orders", po)

    def get(self, po_id: str) -> Json:
        return self._c.get(f"/v1/purchase-orders/{_enc(po_id)}")


class _Invoices(_R):
    def create(self, invoice: Json) -> Json:
        return self._c.post("/v1/invoices", invoice)

    def get(self, invoice_id: str) -> Json:
        return self._c.get(f"/v1/invoices/{_enc(invoice_id)}")


class _Instructions(_R):
    """Independently approved purchase instructions. Humans create/approve; agents only read their own."""

    def create(self, instruction: Json) -> Json:
        return self._c.post("/v1/purchase-instructions", instruction)

    def update(self, instruction_id: str, instruction: Json) -> Json:
        return self._c.put(f"/v1/purchase-instructions/{_enc(instruction_id)}", instruction)

    def approve(self, instruction_id: str, comment: Optional[str] = None) -> Json:
        return self._c.post(f"/v1/purchase-instructions/{_enc(instruction_id)}/approve", {"comment": comment} if comment else {})

    def reject(self, instruction_id: str, reason: str) -> Json:
        return self._c.post(f"/v1/purchase-instructions/{_enc(instruction_id)}/reject", {"reason": reason})

    def revoke(self, instruction_id: str, reason: str) -> Json:
        return self._c.post(f"/v1/purchase-instructions/{_enc(instruction_id)}/revoke", {"reason": reason})

    def list(self, agent_id: Optional[str] = None, status: Optional[str] = None) -> Json:
        return self._c.get("/v1/purchase-instructions" + _query(agentId=agent_id, status=status))

    def get(self, instruction_id: str) -> Json:
        return self._c.get(f"/v1/purchase-instructions/{_enc(instruction_id)}")


class _Receipts(_R):
    def create(self, receipt: Json) -> Json:
        return self._c.post("/v1/receipts", receipt)

    def void(self, receipt_id: str, reason: str) -> Json:
        return self._c.post(f"/v1/receipts/{_enc(receipt_id)}/void", {"reason": reason})


class _Authorizations(_R):
    """Review queue: REVIEW decisions wait here for a human."""

    def list(self, status: Optional[str] = None) -> Json:
        return self._c.get("/v1/authorizations" + _query(status=status))

    def get(self, authorization_id: str) -> Json:
        return self._c.get(f"/v1/authorizations/{_enc(authorization_id)}")

    def approve(self, authorization_id: str, comment: Optional[str] = None) -> Json:
        return self._c.post(f"/v1/authorizations/{_enc(authorization_id)}/approve", {"comment": comment} if comment else {})

    def deny(self, authorization_id: str, comment: Optional[str] = None) -> Json:
        return self._c.post(f"/v1/authorizations/{_enc(authorization_id)}/deny", {"comment": comment} if comment else {})


class _Transactions(_R):
    def get(self, transaction_id: str) -> Json:
        return self._c.get(f"/v1/transactions/{_enc(transaction_id)}")

    def reconcile(self, transaction_id: str) -> Json:
        return self._c.post(f"/v1/transactions/{_enc(transaction_id)}/reconcile", {})

    def resolve(self, transaction_id: str, note: str) -> Json:
        return self._c.post(f"/v1/transactions/{_enc(transaction_id)}/resolve", {"note": note})


class _Policies(_R):
    def list(self) -> Json:
        return self._c.get("/v1/policies")

    def update(self, policy_id: str, rules: Json) -> Json:
        """Creates a new active policy version (previous versions are retained)."""
        return self._c.put(f"/v1/policies/{_enc(policy_id)}", {"rules": rules})


class _Audit(_R):
    def verify(self) -> Json:
        """Recomputes the organization's audit hash chain and signatures."""
        return self._c.get("/v1/audit/verify")

    def events(self) -> Json:
        return self._c.get("/v1/audit/events")

    def anchors(self) -> Json:
        return self._c.get("/v1/audit/anchors")

    def anchor_now(self) -> Json:
        return self._c.post("/v1/audit/anchors", {})


def _enc(value: str) -> str:
    return quote(value, safe="")


def _query(**params: Optional[str]) -> str:
    items: List[tuple] = [(k, v) for k, v in params.items() if v is not None]
    return f"?{urlencode(items)}" if items else ""
