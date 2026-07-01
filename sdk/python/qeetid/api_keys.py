"""API key management resource (maps to /v1/api-keys)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import quote

from .client import HttpClient
from .users import ListParams, Page

__all__ = ["ApiKey", "CreateApiKeyInput", "ApiKeys"]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class ApiKey:
    id: str
    name: str
    prefix: str
    created_at: str
    tenant_id: Optional[str] = None
    scopes: Optional[List[str]] = None
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "ApiKey":
        return cls(
            id=d.get("id", ""),
            name=d.get("name", ""),
            prefix=d.get("prefix", ""),
            created_at=d.get("created_at", ""),
            tenant_id=d.get("tenant_id"),
            scopes=d.get("scopes"),
            expires_at=d.get("expires_at"),
            last_used_at=d.get("last_used_at"),
        )


@dataclass
class CreateApiKeyInput:
    name: str
    tenant_id: Optional[str] = None
    scopes: Optional[List[str]] = None
    expires_in_days: Optional[int] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "name": self.name,
            "tenant_id": self.tenant_id,
            "scopes": self.scopes,
            "expires_in_days": self.expires_in_days,
        })


class ApiKeys:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(self, input: CreateApiKeyInput) -> Dict[str, Any]:
        return self._http.post("/v1/api-keys", input._to_json()) or {}

    def get(self, id: str) -> ApiKey:
        res = self._http.get(f"/v1/api-keys/{quote(id, safe='')}")
        return ApiKey._from_json(res or {})

    def delete(self, id: str) -> None:
        self._http.delete(f"/v1/api-keys/{quote(id, safe='')}")

    def rotate(self, id: str) -> Dict[str, Any]:
        return self._http.post(f"/v1/api-keys/{quote(id, safe='')}/rotate", {}) or {}

    def list(self, params: Optional[ListParams] = None) -> Page[ApiKey]:
        params = params or ListParams()
        res = self._http.get(
            "/v1/api-keys",
            query={"tenant": params.tenant, "limit": params.limit, "cursor": params.cursor},
        )
        env = res or {}
        items = env.get("items")
        if items is None:
            items = env.get("data") or []
        return Page(data=[ApiKey._from_json(k) for k in items], next_cursor=env.get("next_cursor"))

    def list_all(self, params: Optional[ListParams] = None) -> Iterator[ApiKey]:
        params = params or ListParams()
        cursor = params.cursor
        while True:
            page = self.list(ListParams(tenant=params.tenant, limit=params.limit, cursor=cursor))
            for key in page.data:
                yield key
            cursor = page.next_cursor
            if not cursor:
                break
