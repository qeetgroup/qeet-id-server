"""Permission management resource (maps to /v1/rbac/permissions)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterator, Optional
from urllib.parse import quote

from .client import HttpClient
from .users import ListParams, Page

__all__ = ["Permission", "CreatePermissionInput", "Permissions"]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class Permission:
    id: str
    name: str
    created_at: str
    description: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "Permission":
        return cls(
            id=d.get("id", ""),
            name=d.get("name", ""),
            created_at=d.get("created_at", ""),
            description=d.get("description"),
            updated_at=d.get("updated_at"),
        )


@dataclass
class CreatePermissionInput:
    name: str
    description: Optional[str] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({"name": self.name, "description": self.description})


class Permissions:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(self, input: CreatePermissionInput) -> Permission:
        res = self._http.post("/v1/rbac/permissions", input._to_json())
        return Permission._from_json(res or {})

    def get(self, id: str) -> Permission:
        res = self._http.get(f"/v1/rbac/permissions/{quote(id, safe='')}")
        return Permission._from_json(res or {})

    def delete(self, id: str) -> None:
        self._http.delete(f"/v1/rbac/permissions/{quote(id, safe='')}")

    def list(self, params: Optional[ListParams] = None) -> Page[Permission]:
        params = params or ListParams()
        res = self._http.get(
            "/v1/rbac/permissions",
            query={"tenant": params.tenant, "limit": params.limit, "cursor": params.cursor},
        )
        env = res or {}
        items = env.get("items")
        if items is None:
            items = env.get("data") or []
        return Page(
            data=[Permission._from_json(p) for p in items],
            next_cursor=env.get("next_cursor"),
        )

    def list_all(self, params: Optional[ListParams] = None) -> Iterator[Permission]:
        params = params or ListParams()
        cursor = params.cursor
        while True:
            page = self.list(ListParams(tenant=params.tenant, limit=params.limit, cursor=cursor))
            for perm in page.data:
                yield perm
            cursor = page.next_cursor
            if not cursor:
                break
