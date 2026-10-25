"""AgentTrust Python SDK (sandbox).

AgentTrust verifies that an AI agent's payment matches what the business
actually approved (supplier, line items, amount, PO/invoice, verified payee,
policy) before the payment can execute. Any exception means NOT AUTHORIZED.
"""

from .admin import AgentTrustAdmin
from .agent import AgentTrust
from .errors import AgentTrustError
from .sandbox import SANDBOX_SUPPLIER_BANK, AgentTrustSandbox
from .signing import Signer, build_string_to_sign, generate_key_pair, local_signer, sign_request

__version__ = "0.4.0"

__all__ = [
    "AgentTrust",
    "AgentTrustAdmin",
    "AgentTrustError",
    "AgentTrustSandbox",
    "SANDBOX_SUPPLIER_BANK",
    "Signer",
    "build_string_to_sign",
    "generate_key_pair",
    "local_signer",
    "sign_request",
]
