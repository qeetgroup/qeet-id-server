"""OAuth helpers: RFC 8693 token exchange, RFC 7662 introspect, MCP guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from .errors import QeetidError

__all__ = [
    "TokenExchangeInput",
    "TokenExchangeResult",
    "IntrospectResult",
    "OAuth",
]


@dataclass
class TokenExchangeInput:
    client_id: str
    client_secret: str
    subject_token: str
    scope: Optional[str] = None
    actor_token: Optional[str] = None
    actor_token_type: Optional[str] = None


@dataclass
class TokenExchangeResult:
    access_token: str
    token_type: str
    expires_in: int
    scope: Optional[str] = None
    issued_token_type: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "TokenExchangeResult":
        return cls(
            access_token=d.get("access_token", ""),
            token_type=d.get("token_type", "bearer"),
            expires_in=d.get("expires_in", 0),
            scope=d.get("scope"),
            issued_token_type=d.get("issued_token_type"),
        )


@dataclass
class IntrospectResult:
    active: bool
    sub: Optional[str] = None
    scope: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    tenant_id: Optional[str] = None
    actor_type: Optional[str] = None
    agent_id: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "IntrospectResult":
        return cls(
            active=bool(d.get("active", False)),
            sub=d.get("sub"),
            scope=d.get("scope"),
            exp=d.get("exp"),
            iat=d.get("iat"),
            tenant_id=d.get("tenant_id"),
            actor_type=d.get("actor_type"),
            agent_id=d.get("agent_id"),
        )


class OAuth:
    """RFC 8693 token exchange, RFC 7662 introspect, and MCP token guard.

    Uses form-encoded requests with OIDC client credentials — different from
    the API-key transport used by management resources.
    """

    def __init__(self, base_url: str, http_client: httpx.Client) -> None:
        self._base_url = base_url.rstrip("/")
        self._hc = http_client

    def token_exchange(self, input: TokenExchangeInput) -> TokenExchangeResult:
        """RFC 8693 downscoping and delegation."""
        data: Dict[str, str] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": input.subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }
        if input.scope:
            data["scope"] = input.scope
        if input.actor_token:
            data["actor_token"] = input.actor_token
            data["actor_token_type"] = (
                input.actor_token_type or "urn:ietf:params:oauth:token-type:access_token"
            )
        res = self._hc.post(
            f"{self._base_url}/v1/oauth/token",
            data=data,
            auth=(input.client_id, input.client_secret),
            headers={"Accept": "application/json"},
        )
        body = res.json()
        if res.status_code >= 300:
            raise QeetidError(
                res.status_code,
                body.get("error", "token_exchange_failed"),
                body.get("error_description", "Token exchange failed"),
            )
        return TokenExchangeResult._from_json(body)

    def introspect(self, token: str) -> IntrospectResult:
        """RFC 7662 token introspection."""
        res = self._hc.post(
            f"{self._base_url}/v1/oauth/introspect",
            data={"token": token},
            headers={"Accept": "application/json"},
        )
        if res.status_code >= 300:
            raise QeetidError(res.status_code, "introspect_failed", "Token introspection failed")
        return IntrospectResult._from_json(res.json())

    def verify(self, token: str, required_scope: Optional[str] = None) -> IntrospectResult:
        """MCP token guard — verify active + optional scope check.

        Raises QeetidError(401) if inactive, QeetidError(403) if scope missing.
        """
        result = self.introspect(token)
        if not result.active:
            raise QeetidError(401, "token_inactive", "Token is not active")
        if required_scope:
            scopes: List[str] = (result.scope or "").split()
            if required_scope not in scopes:
                raise QeetidError(403, "insufficient_scope", f"Required scope: {required_scope}")
        return result
