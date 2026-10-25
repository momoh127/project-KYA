"""AgentTrust quickstart (Python): from nothing to a settled sandbox payment, then two blocked attacks.

    pip install agenttrust-0.4.0-py3-none-any.whl
    AGENTTRUST_BASE_URL=https://<sandbox> python quickstart.py

Optional: AGENTTRUST_SANDBOX_KEY to reuse an existing sandbox.
"""

import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

from agenttrust import SANDBOX_SUPPLIER_BANK, AgentTrustError, AgentTrustSandbox

BASE_URL = os.environ.get("AGENTTRUST_BASE_URL", "http://localhost:4000")


def in_days(d: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=d)).isoformat().replace("+00:00", "Z")


def uid() -> str:
    return secrets.token_hex(4)


def step(n: int, text: str) -> None:
    print(f"\n{n}. {text}")


def main() -> int:
    step(1, "Sandbox")
    if os.environ.get("AGENTTRUST_SANDBOX_KEY"):
        sandbox = AgentTrustSandbox(BASE_URL, os.environ["AGENTTRUST_SANDBOX_KEY"])
    else:
        sandbox, account = AgentTrustSandbox.signup(BASE_URL, "Quickstart Co", f"dev+{uid()}@example.com")
        print(f"   sandbox key (save it, shown once): {account['sandboxKey']}")
    admin, approver = sandbox.as_persona("admin"), sandbox.as_persona("approver")

    step(2, "Supplier entered by admin, bank details verified by a second admin (dual control)")
    supplier_id = sandbox.create_verified_supplier("Northwind Industrial Supply")["supplierId"]

    step(3, "Register the agent and give it a spending ceiling")
    agent = sandbox.register_agent("Procurement agent")
    approver.delegations.create({
        "agentId": agent["agentId"], "actions": ["purchase"], "currency": "USD",
        "maxTransactionCents": 100_000, "monthlyLimitCents": 500_000, "expiresAt": in_days(30),
    })

    step(4, "Approved purchase instruction + PO + invoice")
    po = admin.purchase_orders.create({"supplierId": supplier_id, "externalReference": f"PO-{uid()}", "approvedAmountCents": 48_000, "currency": "USD"})
    lines = [{"lineNumber": 1, "sku": "DRL-100", "description": "Cordless drill", "quantity": "4", "unitPriceCents": 12_000}]
    instruction = admin.instructions.create({
        "agentId": agent["agentId"], "supplierId": supplier_id, "purchaseOrderId": po["id"], "fulfillmentType": "physical_goods",
        "currency": "USD", "lines": lines, "maxUses": 1, "expiresAt": in_days(7),
    })
    approver.instructions.approve(instruction["id"], "Quickstart approval")
    invoice = admin.invoices.create({
        "supplierId": supplier_id, "purchaseOrderId": po["id"], "purchaseInstructionId": instruction["id"], "invoiceNumber": f"INV-{uid()}",
        "amountCents": 48_000, "currency": "USD", "lines": [dict(l, instructionLineNumber=l["lineNumber"]) for l in lines],
    })

    step(5, "Agent requests authorization")
    client = agent["client"]
    request = {
        "action": "purchase", "supplierId": supplier_id, "payee": SANDBOX_SUPPLIER_BANK, "amountCents": 48_000, "currency": "USD",
        "purchaseOrderId": po["id"], "invoiceId": invoice["id"], "purchaseInstructionId": instruction["id"],
    }
    swapped = client.authorizations.create(dict(request, idempotencyKey=f"buy-{uid()}", payee={"type": "us_ach", "routingNumber": "026009593", "accountNumber": "9999000011"}))
    failing = [c["code"] for c in swapped["checks"] if c["outcome"] != "pass"]
    print(f"   attack: same invoice, bank account changed -> {swapped['decision']} ({', '.join(failing)}), token issued: {'token' in swapped}")
    auth = client.authorizations.create(dict(request, idempotencyKey=f"buy-{uid()}"))
    print(f"   decision: {auth['decision']}")
    if auth["decision"] != "ALLOW":
        print(f"   unexpected: {auth['reasonCodes']}")
        return 1

    step(6, "Execute through the enforcing gateway, then the (sandbox) provider settles")
    expected = {"supplierId": supplier_id, "amountCents": 48_000, "currency": "USD", "purchaseOrderId": po["id"], "invoiceId": invoice["id"]}
    tx = client.transactions.execute(auth["token"], expected)
    print(f"   transaction {tx['id']}: {tx['status']} (accepted is NOT paid)")
    settled = sandbox.advance_payment(tx["id"], "settled")
    print(f"   provider webhook -> {settled['transactionStatus']}; invoice is now {admin.invoices.get(invoice['id'])['status']}")

    step(7, "Attack: reuse the token for more money")
    try:
        client.transactions.execute(auth["token"], dict(expected, amountCents=58_000))
        print("   reuse the token for $580.00 -> UNEXPECTEDLY ALLOWED")
        return 1
    except AgentTrustError as e:
        print(f"   reuse the token for $580.00 -> blocked ({e.status} {e.code})")

    print(f"\nDone: first settled payment {sandbox.progress()['minutesToFirstSettledPayment']} min after signup.")
    return 0 if swapped["decision"] == "DENY" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AgentTrustError as e:
        print(f"AgentTrustError {e.status} {e.code}: {e.message}", file=sys.stderr)
        sys.exit(1)
