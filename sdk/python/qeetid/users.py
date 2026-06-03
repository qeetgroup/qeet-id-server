"""User management resource (maps to /v1/users)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, TypeVar, Generic
from urllib.parse import quote

from .client import HttpClient

__all__ = [
    "User",
    "CreateUserInput",
    "UpdateUserInput",
    "ListParams",
    "Page",
    "Users",
]

T = TypeVar("T")


@dataclass
class User:
    id: str
    email: str
    status: str
    created_at: str
    tenant_id: Optional[str] = None
    display_name: Optional[str] = None
    phone: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    updated_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "User":
        return cls(
            id=d.get("id", ""),
            email=d.get("email", ""),
            status=d.get("status", ""),
            created_at=d.get("created_at", ""),
            tenant_id=d.get("tenant_id"),
            display_name=d.get("display_name"),
            phone=d.get("phone"),
            metadata=d.get("metadata"),
            updated_at=d.get("updated_at"),
        )


@dataclass
class CreateUserInput:
    email: str
    display_name: Optional[str] = None
    phone: Optional[str] = None
    password: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact(
            {
                "email": self.email,
                "display_name": self.display_name,
                "phone": self.phone,
                "password": self.password,
                "metadata": self.metadata,
            }
        )


@dataclass
class UpdateUserInput:
    display_name: Optional[str] = None
    phone: Optional[str] = None
    status: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact(
            {
                "display_name": self.display_name,
                "phone": self.phone,
                "status": self.status,
                "metadata": self.metadata,
            }
        )


@dataclass
class ListParams:
    tenant: Optional[str] = None
    limit: Optional[int] = None
    cursor: Optional[str] = None


@dataclass
class Page(Generic[T]):
    data: List[T]
    next_cursor: Optional[str] = None


class Users:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(self, input: CreateUserInput) -> User:
        res = self._http.post("/v1/users", input._to_json())
        return User._from_json(res or {})

    def get(self, id: str) -> User:
        res = self._http.get(f"/v1/users/{quote(id, safe='')}")
        return User._from_json(res or {})

    def update(self, id: str, input: UpdateUserInput) -> User:
        res = self._http.patch(f"/v1/users/{quote(id, safe='')}", input._to_json())
        return User._from_json(res or {})

    def delete(self, id: str) -> None:
        self._http.delete(f"/v1/users/{quote(id, safe='')}")

    def set_password(self, id: str, password: str) -> None:
        self._http.post(
            f"/v1/users/{quote(id, safe='')}/password", {"password": password}
        )

    def list(self, params: Optional[ListParams] = None) -> Page[User]:
        params = params or ListParams()
        res = self._http.get(
            "/v1/users",
            query={
                "tenant": params.tenant,
                "limit": params.limit,
                "cursor": params.cursor,
            },
        )
        env = res or {}
        items = env.get("items")
        if items is None:
            items = env.get("data") or []
        return Page(
            data=[User._from_json(u) for u in items],
            next_cursor=env.get("next_cursor"),
        )

    def list_all(self, params: Optional[ListParams] = None) -> Iterator[User]:
        """Auto-paginate every page into a single iterator."""
        params = params or ListParams()
        cursor = params.cursor
        while True:
            page = self.list(
                ListParams(tenant=params.tenant, limit=params.limit, cursor=cursor)
            )
            for user in page.data:
                yield user
            cursor = page.next_cursor
            if not cursor:
                break


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}
