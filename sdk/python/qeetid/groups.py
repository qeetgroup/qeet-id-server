"""Group management resource (maps to /v1/groups)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import quote

from .client import HttpClient
from .users import ListParams, Page

__all__ = [
    "Group",
    "CreateGroupInput",
    "UpdateGroupInput",
    "GroupMember",
    "Groups",
]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class Group:
    id: str
    tenant_id: str
    name: str
    created_at: str
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    updated_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "Group":
        return cls(
            id=d.get("id", ""),
            tenant_id=d.get("tenant_id", ""),
            name=d.get("name", ""),
            created_at=d.get("created_at", ""),
            description=d.get("description"),
            metadata=d.get("metadata"),
            updated_at=d.get("updated_at"),
        )


@dataclass
class CreateGroupInput:
    name: str
    tenant_id: Optional[str] = None
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "name": self.name,
            "tenant_id": self.tenant_id,
            "description": self.description,
            "metadata": self.metadata,
        })


@dataclass
class UpdateGroupInput:
    name: Optional[str] = None
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "name": self.name,
            "description": self.description,
            "metadata": self.metadata,
        })


@dataclass
class GroupMember:
    user_id: str
    group_id: str
    added_at: str

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "GroupMember":
        return cls(
            user_id=d.get("user_id", ""),
            group_id=d.get("group_id", ""),
            added_at=d.get("added_at", ""),
        )


class Groups:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(self, input: CreateGroupInput) -> Group:
        res = self._http.post("/v1/groups", input._to_json())
        return Group._from_json(res or {})

    def get(self, id: str) -> Group:
        res = self._http.get(f"/v1/groups/{quote(id, safe='')}")
        return Group._from_json(res or {})

    def update(self, id: str, input: UpdateGroupInput) -> Group:
        res = self._http.patch(f"/v1/groups/{quote(id, safe='')}", input._to_json())
        return Group._from_json(res or {})

    def delete(self, id: str) -> None:
        self._http.delete(f"/v1/groups/{quote(id, safe='')}")

    def list(self, params: Optional[ListParams] = None) -> Page[Group]:
        params = params or ListParams()
        res = self._http.get(
            "/v1/groups",
            query={"tenant": params.tenant, "limit": params.limit, "cursor": params.cursor},
        )
        env = res or {}
        items = env.get("items")
        if items is None:
            items = env.get("data") or []
        return Page(data=[Group._from_json(g) for g in items], next_cursor=env.get("next_cursor"))

    def list_all(self, params: Optional[ListParams] = None) -> Iterator[Group]:
        params = params or ListParams()
        cursor = params.cursor
        while True:
            page = self.list(ListParams(tenant=params.tenant, limit=params.limit, cursor=cursor))
            for group in page.data:
                yield group
            cursor = page.next_cursor
            if not cursor:
                break

    def add_member(self, group_id: str, user_id: str) -> None:
        self._http.post(f"/v1/groups/{quote(group_id, safe='')}/members", {"user_id": user_id})

    def remove_member(self, group_id: str, user_id: str) -> None:
        self._http.delete(
            f"/v1/groups/{quote(group_id, safe='')}/members/{quote(user_id, safe='')}"
        )

    def list_members(self, group_id: str) -> List[GroupMember]:
        res = self._http.get(f"/v1/groups/{quote(group_id, safe='')}/members")
        env = res or {}
        items = env.get("items") or env.get("data") or []
        return [GroupMember._from_json(m) for m in items]
