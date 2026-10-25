"""Minimal JSON-over-HTTP transport on the standard library (no third-party HTTP dependency)."""

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from .errors import AgentTrustError

DEFAULT_TIMEOUT = 30.0


def encode_json(payload: Any) -> bytes:
    """The exact bytes that are both signed and sent (compact, UTF-8)."""
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def send(method: str, url: str, headers: Dict[str, str], body: Optional[bytes], timeout: float = DEFAULT_TIMEOUT) -> Any:
    req = urllib.request.Request(url, data=body if body else None, method=method, headers=dict(headers))
    if body:
        req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:  # noqa: S310 (caller-provided base URL)
            return _parse(res.status, res.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            raise AgentTrustError(e.code, "INVALID_RESPONSE", f"Non-JSON error response (HTTP {e.code})") from None
        err = data.get("error", {}) if isinstance(data, dict) else {}
        raise AgentTrustError(e.code, err.get("code", "HTTP_ERROR"), err.get("message", e.reason or "HTTP error"), err.get("details")) from None
    except urllib.error.URLError as e:
        raise AgentTrustError(0, "NETWORK_ERROR", f"Could not reach AgentTrust: {e.reason}") from None


def _parse(status: int, raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        raise AgentTrustError(status, "INVALID_RESPONSE", f"Non-JSON response (HTTP {status})") from None
