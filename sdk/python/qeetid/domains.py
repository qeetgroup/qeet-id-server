"""Domain verification resource (maps to /v1/tenants/{id}/domains)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from .client import HttpClient

__all__ = [
    "Domain",
    "CreateDomainInput",
    "Domains",
]


@dataclass
class Domain:
    id: str
    tenant_id: str
    domain: str
    verified: bool
    created_at: str
    verification_token: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "Domain":
        return cls(
            id=d.get("id", ""),
            tenant_id=d.get("tenant_id", ""),
            domain=d.get("domain", ""),
            verified=bool(d.get("verified", False)),
            created_at=d.get("created_at", ""),
            verification_token=d.get("verification_token"),
            updated_at=d.get("updated_at"),
        )


@dataclass
class CreateDomainInput:
    domain: str

    def _to_json(self) -> Dict[str, Any]:
        return {"domain": self.domain}


class Domains:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(self, tenant_id: str, input: CreateDomainInput) -> Domain:
        res = self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/domains",
            input._to_json(),
        )
        return Domain._from_json(res or {})

    def get(self, tenant_id: str, id: str) -> Domain:
        res = self._http.get(
            f"/v1/tenants/{quote(tenant_id, safe='')}/domains/{quote(id, safe='')}"
        )
        return Domain._from_json(res or {})

    def delete(self, tenant_id: str, id: str) -> None:
        self._http.delete(
            f"/v1/tenants/{quote(tenant_id, safe='')}/domains/{quote(id, safe='')}"
        )

    def verify(self, tenant_id: str, id: str) -> Domain:
        res = self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/domains/{quote(id, safe='')}/verify",
            {},
        )
        return Domain._from_json(res or {})

    def list(self, tenant_id: str) -> List[Domain]:
        res = self._http.get(f"/v1/tenants/{quote(tenant_id, safe='')}/domains")
        env = res or {}
        items = env.get("items") or env.get("data") or []
        return [Domain._from_json(d) for d in items]
