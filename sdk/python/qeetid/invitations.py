"""Invitation management resource (maps to /v1/invites)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterator, Optional
from urllib.parse import quote

from .client import HttpClient
from .users import ListParams, Page

__all__ = [
    "Invitation",
    "CreateInvitationInput",
    "Invitations",
]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class Invitation:
    id: str
    tenant_id: str
    email: str
    status: str
    created_at: str
    role: Optional[str] = None
    invited_by: Optional[str] = None
    expires_at: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    updated_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "Invitation":
        return cls(
            id=d.get("id", ""),
            tenant_id=d.get("tenant_id", ""),
            email=d.get("email", ""),
            status=d.get("status", ""),
            created_at=d.get("created_at", ""),
            role=d.get("role"),
            invited_by=d.get("invited_by"),
            expires_at=d.get("expires_at"),
            metadata=d.get("metadata"),
            updated_at=d.get("updated_at"),
        )


@dataclass
class CreateInvitationInput:
    email: str
    tenant_id: str
    role: Optional[str] = None
    expires_in_days: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "email": self.email,
            "tenant_id": self.tenant_id,
            "role": self.role,
            "expires_in_days": self.expires_in_days,
            "metadata": self.metadata,
        })


class Invitations:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(self, input: CreateInvitationInput) -> Invitation:
        res = self._http.post("/v1/invites", input._to_json())
        return Invitation._from_json(res or {})

    def get(self, id: str) -> Invitation:
        res = self._http.get(f"/v1/invites/{quote(id, safe='')}")
        return Invitation._from_json(res or {})

    def delete(self, id: str) -> None:
        self._http.delete(f"/v1/invites/{quote(id, safe='')}")

    def resend(self, id: str) -> None:
        self._http.post(f"/v1/invites/{quote(id, safe='')}/resend", {})

    def list(self, params: Optional[ListParams] = None) -> Page[Invitation]:
        params = params or ListParams()
        res = self._http.get(
            "/v1/invites",
            query={"tenant": params.tenant, "limit": params.limit, "cursor": params.cursor},
        )
        env = res or {}
        items = env.get("items")
        if items is None:
            items = env.get("data") or []
        return Page(
            data=[Invitation._from_json(i) for i in items],
            next_cursor=env.get("next_cursor"),
        )

    def list_all(self, params: Optional[ListParams] = None) -> Iterator[Invitation]:
        params = params or ListParams()
        cursor = params.cursor
        while True:
            page = self.list(ListParams(tenant=params.tenant, limit=params.limit, cursor=cursor))
            for inv in page.data:
                yield inv
            cursor = page.next_cursor
            if not cursor:
                break
