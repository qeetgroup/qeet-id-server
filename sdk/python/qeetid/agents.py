"""AI agent management (maps to /v1/tenants/{id}/agents + /v1/agents/token)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from .client import HttpClient

__all__ = ["Agent", "CreateAgentInput", "AgentTokenResult", "Agents"]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class Agent:
    id: str
    tenant_id: str
    name: str
    scopes: List[str]
    token_ttl_seconds: int
    disabled: bool
    created_at: str
    secret: Optional[str] = None  # only on create

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "Agent":
        return cls(
            id=d.get("id", ""),
            tenant_id=d.get("tenant_id", ""),
            name=d.get("name", ""),
            scopes=d.get("scopes") or [],
            token_ttl_seconds=d.get("token_ttl_seconds", 0),
            disabled=bool(d.get("disabled", False)),
            created_at=d.get("created_at", ""),
            secret=d.get("secret"),
        )


@dataclass
class CreateAgentInput:
    name: str
    scopes: Optional[List[str]] = None
    token_ttl_seconds: Optional[int] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "name": self.name,
            "scopes": self.scopes,
            "token_ttl_seconds": self.token_ttl_seconds,
        })


@dataclass
class AgentTokenResult:
    access_token: str
    token_type: str
    expires_in: int
    scope: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "AgentTokenResult":
        return cls(
            access_token=d.get("access_token", ""),
            token_type=d.get("token_type", "bearer"),
            expires_in=d.get("expires_in", 0),
            scope=d.get("scope"),
        )


class Agents:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(self, tenant_id: str, input: CreateAgentInput) -> Agent:
        res = self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/agents",
            input._to_json(),
        )
        return Agent._from_json(res or {})

    def delete(self, tenant_id: str, id: str) -> None:
        self._http.delete(
            f"/v1/tenants/{quote(tenant_id, safe='')}/agents/{quote(id, safe='')}"
        )

    def list(self, tenant_id: str) -> List[Agent]:
        res = self._http.get(f"/v1/tenants/{quote(tenant_id, safe='')}/agents")
        env = res or {}
        items = env.get("items") or env.get("data") or []
        return [Agent._from_json(a) for a in items]

    def token(self, tenant_id: str, agent_id: str, secret: str, scope: Optional[str] = None) -> AgentTokenResult:
        body: Dict[str, Any] = {"tenant_id": tenant_id, "agent_id": agent_id, "secret": secret}
        if scope:
            body["scope"] = scope
        res = self._http.post("/v1/agents/token", body)
        return AgentTokenResult._from_json(res or {})
