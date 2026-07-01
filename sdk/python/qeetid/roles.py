"""Role management resource (maps to /v1/rbac/roles)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import quote

from .client import HttpClient
from .users import ListParams, Page

__all__ = ["Role", "CreateRoleInput", "UpdateRoleInput", "Roles"]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class Role:
    id: str
    name: str
    created_at: str
    tenant_id: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[str]] = None
    updated_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "Role":
        return cls(
            id=d.get("id", ""),
            name=d.get("name", ""),
            created_at=d.get("created_at", ""),
            tenant_id=d.get("tenant_id"),
            description=d.get("description"),
            permissions=d.get("permissions"),
            updated_at=d.get("updated_at"),
        )


@dataclass
class CreateRoleInput:
    name: str
    tenant_id: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[str]] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "name": self.name,
            "tenant_id": self.tenant_id,
            "description": self.description,
            "permissions": self.permissions,
        })


@dataclass
class UpdateRoleInput:
    name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[str]] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "name": self.name,
            "description": self.description,
            "permissions": self.permissions,
        })


class Roles:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(self, input: CreateRoleInput) -> Role:
        res = self._http.post("/v1/rbac/roles", input._to_json())
        return Role._from_json(res or {})

    def get(self, id: str) -> Role:
        res = self._http.get(f"/v1/rbac/roles/{quote(id, safe='')}")
        return Role._from_json(res or {})

    def update(self, id: str, input: UpdateRoleInput) -> Role:
        res = self._http.patch(f"/v1/rbac/roles/{quote(id, safe='')}", input._to_json())
        return Role._from_json(res or {})

    def delete(self, id: str) -> None:
        self._http.delete(f"/v1/rbac/roles/{quote(id, safe='')}")

    def assign_to_user(self, role_id: str, user_id: str, tenant_id: str) -> None:
        self._http.post(
            f"/v1/rbac/roles/{quote(role_id, safe='')}/assign",
            {"user_id": user_id, "tenant_id": tenant_id},
        )

    def remove_from_user(self, role_id: str, user_id: str, tenant_id: str) -> None:
        self._http.post(
            f"/v1/rbac/roles/{quote(role_id, safe='')}/remove",
            {"user_id": user_id, "tenant_id": tenant_id},
        )

    def list(self, params: Optional[ListParams] = None) -> Page[Role]:
        params = params or ListParams()
        res = self._http.get(
            "/v1/rbac/roles",
            query={"tenant": params.tenant, "limit": params.limit, "cursor": params.cursor},
        )
        env = res or {}
        items = env.get("items")
        if items is None:
            items = env.get("data") or []
        return Page(data=[Role._from_json(r) for r in items], next_cursor=env.get("next_cursor"))

    def list_all(self, params: Optional[ListParams] = None) -> Iterator[Role]:
        params = params or ListParams()
        cursor = params.cursor
        while True:
            page = self.list(ListParams(tenant=params.tenant, limit=params.limit, cursor=cursor))
            for role in page.data:
                yield role
            cursor = page.next_cursor
            if not cursor:
                break
