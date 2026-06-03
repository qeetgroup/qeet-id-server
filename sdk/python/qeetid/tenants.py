"""Tenant management resource (maps to /v1/tenants)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from .client import HttpClient
from .users import Page

__all__ = [
    "Tenant",
    "CreateTenantInput",
    "UpdateTenantInput",
    "Tenants",
]


@dataclass
class Tenant:
    id: str
    name: str
    slug: str
    created_at: str
    region: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "Tenant":
        return cls(
            id=d.get("id", ""),
            name=d.get("name", ""),
            slug=d.get("slug", ""),
            created_at=d.get("created_at", ""),
            region=d.get("region"),
            updated_at=d.get("updated_at"),
        )


@dataclass
class CreateTenantInput:
    name: str
    slug: str
    region: Optional[str] = None

    def _to_json(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"name": self.name, "slug": self.slug}
        if self.region is not None:
            out["region"] = self.region
        return out


@dataclass
class UpdateTenantInput:
    name: Optional[str] = None
    region: Optional[str] = None

    def _to_json(self) -> Dict[str, Any]:
        return {k: v for k, v in {"name": self.name, "region": self.region}.items() if v is not None}


class Tenants:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(self, input: CreateTenantInput) -> Tenant:
        res = self._http.post("/v1/tenants", input._to_json())
        return Tenant._from_json(res or {})

    def get(self, id: str) -> Tenant:
        res = self._http.get(f"/v1/tenants/{quote(id, safe='')}")
        return Tenant._from_json(res or {})

    def update(self, id: str, input: UpdateTenantInput) -> Tenant:
        res = self._http.patch(f"/v1/tenants/{quote(id, safe='')}", input._to_json())
        return Tenant._from_json(res or {})

    def delete(self, id: str) -> None:
        self._http.delete(f"/v1/tenants/{quote(id, safe='')}")

    def list(
        self, limit: Optional[int] = None, cursor: Optional[str] = None
    ) -> Page[Tenant]:
        res = self._http.get("/v1/tenants", query={"limit": limit, "cursor": cursor})
        env = res or {}
        items = env.get("items")
        if items is None:
            items = env.get("data") or []
        return Page(
            data=[Tenant._from_json(t) for t in items],
            next_cursor=env.get("next_cursor"),
        )
