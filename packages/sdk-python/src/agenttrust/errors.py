"""Errors. Any error means NOT AUTHORIZED: never pay on an exception (fail closed)."""

from typing import Any, Optional


class AgentTrustError(Exception):
    """Raised for every non-2xx response, network failure, or unreadable response."""

    def __init__(self, status: int, code: str, message: str, details: Optional[Any] = None) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.details = details
