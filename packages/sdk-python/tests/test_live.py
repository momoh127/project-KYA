"""Live tests against a running AgentTrust API with sandbox signup enabled.

Run via `pnpm test:python` (starts a server on the test database), or point
AGENTTRUST_BASE_URL at any sandbox. Skipped when AGENTTRUST_BASE_URL is unset.
"""

import os
import secrets
from datetime import datetime, timedelta, timezone

import pytest

from agenttrust import SANDBOX_SUPPLIER_BANK, AgentTrust, AgentTrustError, AgentTrustSandbox

BASE_URL = os.environ.get("AGENTTRUST_BASE_URL")
pytestmark = pytest.mark.skipif(not BASE_URL, reason="AGENTTRUST_BASE_URL not set")


def uniq() -> str:
    return secrets.token_hex(4)


def in_a_week() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=7)).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def world():
    sandbox, account = AgentTrustSandbox.signup(BASE_URL, f"Py Eval {uniq()}", f"py+{uniq()}@eval.test")
    admin, approver = sandbox.as_persona("admin"), sandbox.as_persona("approver")
    supplier_id = sandbox.create_verified_supplier()["supplierId"]
    agent = sandbox.register_agent()
    approver.delegations.create({
        "agentId": agent["agentId"], "actions": ["purchase"], "currency": "USD",
        "maxTransactionCents": 100_000, "monthlyLimitCents": 500_000, "expiresAt": in_a_week(),
    })
    po = admin.purchase_orders.create({"supplierId": supplier_id, "externalReference": f"PO-{uniq()}", "approvedAmountCents": 48_000, "currency": "USD"})
    lines = [{"lineNumber": 1, "sku": "DRL-100", "description": "Cordless drill", "quantity": "4", "unitPriceCents": 12_000}]
    instruction = admin.instructions.create({
        "agentId": agent["agentId"], "supplierId": supplier_id, "purchaseOrderId": po["id"], "fulfillmentType": "physical_goods",
        "currency": "USD", "lines": lines, "expiresAt": in_a_week(),
    })
    approver.instructions.approve(instruction["id"], "Approved in sandbox")
    invoice = admin.invoices.create({
        "supplierId": supplier_id, "purchaseOrderId": po["id"], "purchaseInstructionId": instruction["id"], "invoiceNumber": f"INV-{uniq()}",
        "amountCents": 48_000, "currency": "USD", "lines": [dict(l, instructionLineNumber=l["lineNumber"]) for l in lines],
    })
    return {
        "sandbox": sandbox, "account": account, "admin": admin, "agent": agent["client"], "supplierId": supplier_id,
        "poId": po["id"], "instructionId": instruction["id"], "invoiceId": invoice["id"],
    }


def authorize(w, **overrides):
    req = {
        "idempotencyKey": f"buy-{uniq()}", "action": "purchase", "supplierId": w["supplierId"], "payee": SANDBOX_SUPPLIER_BANK,
        "amountCents": 48_000, "currency": "USD", "purchaseOrderId": w["poId"], "invoiceId": w["invoiceId"], "purchaseInstructionId": w["instructionId"],
    }
    req.update(overrides)
    return w["agent"].authorizations.create(req)


def expected(w, amount=48_000):
    return {"supplierId": w["supplierId"], "amountCents": amount, "currency": "USD", "purchaseOrderId": w["poId"], "invoiceId": w["invoiceId"]}


def test_quickstart_allow_execute_settle(world):
    w = world
    assert w["instructionId"] in [i["id"] for i in w["agent"].instructions.list()["instructions"]]
    auth = authorize(w)
    assert auth["decision"] == "ALLOW", auth["reasonCodes"]
    tx = w["agent"].transactions.execute(auth["token"], expected(w))
    assert tx["status"] == "accepted"
    advanced = w["sandbox"].advance_payment(tx["id"], "settled")
    assert advanced["transactionStatus"] == "settled"
    assert w["admin"].invoices.get(w["invoiceId"])["status"] == "paid"
    assert w["admin"].audit.verify()["valid"] is True
    assert w["sandbox"].progress()["completed"] is True


def test_changed_bank_account_is_denied_without_token(world):
    auth = authorize(world, payee={"type": "us_ach", "routingNumber": "026009593", "accountNumber": "9999000011"})
    assert auth["decision"] == "DENY"
    assert "token" not in auth


def test_amount_above_instruction_is_not_allowed(world):
    auth = authorize(world, amountCents=58_000)
    assert auth["decision"] != "ALLOW"


def test_expected_mismatch_at_execution_fails_closed(world):
    w = world
    auth = authorize(w)
    with pytest.raises(AgentTrustError) as e:
        w["agent"].transactions.execute(auth["token"], expected(w, amount=48_001))
    assert e.value.status >= 400


def test_token_replay_never_creates_a_second_payment(world):
    w = world
    auth = authorize(w)
    first = w["agent"].transactions.execute(auth["token"], expected(w))
    try:
        again = w["agent"].transactions.execute(auth["token"], expected(w))
    except AgentTrustError as e:
        assert e.status >= 400  # refused outright
    else:
        assert again["id"] == first["id"]  # or reconciled to the SAME transaction (never re-paid)


def test_wrong_workload_key_cannot_mint_sessions(world):
    other = AgentTrustSandbox.signup(BASE_URL, f"Other {uniq()}", f"o+{uniq()}@eval.test")[0].register_agent()
    impostor = AgentTrust(BASE_URL, world["agent"]._credential_id, private_key_pem=other["privateKeyPem"])
    with pytest.raises(AgentTrustError) as e:
        impostor.instructions.list()
    assert e.value.status == 401


def test_network_failure_is_an_error_not_a_decision():
    with pytest.raises(AgentTrustError) as e:
        AgentTrustSandbox.signup("http://127.0.0.1:9", "X", "x@eval.test", timeout=2)
    assert e.value.code == "NETWORK_ERROR"
