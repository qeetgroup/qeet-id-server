"""Audit log resource (maps to /v1/tenants/{id}/audit)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import quote

from .client import HttpClient

__all__ = ["AuditLog", "AuditLogListParams", "AuditLogs"]


@dataclass
class AuditLog:
    id: str
    tenant_id: str
    event: str
    created_at: str
    actor_id: Optional[str] = None
    actor_type: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    hash: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "AuditLog":
        return cls(
            id=d.get("id", ""),
            tenant_id=d.get("tenant_id", ""),
            event=d.get("event", ""),
            created_at=d.get("created_at", ""),
            actor_id=d.get("actor_id"),
            actor_type=d.get("actor_type"),
            resource_type=d.get("resource_type"),
            resource_id=d.get("resource_id"),
            ip_address=d.get("ip_address"),
            user_agent=d.get("user_agent"),
            metadata=d.get("metadata"),
            hash=d.get("hash"),
        )


@dataclass
class AuditLogListParams:
    event: Optional[str] = None
    actor_id: Optional[str] = None
    from_: Optional[str] = None
    to: Optional[str] = None
    limit: Optional[int] = None
    cursor: Optional[str] = None


class AuditLogs:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self, tenant_id: str, params: Optional[AuditLogListParams] = None) -> Dict[str, Any]:
        params = params or AuditLogListParams()
        res = self._http.get(
            f"/v1/tenants/{quote(tenant_id, safe='')}/audit",
            query={
                "event": params.event,
                "actor_id": params.actor_id,
                "from": params.from_,
                "to": params.to,
                "limit": params.limit,
                "cursor": params.cursor,
            },
        )
        env = res or {}
        items = env.get("items")
        if items is None:
            items = env.get("data") or []
        return {
            "data": [AuditLog._from_json(e) for e in items],
            "next_cursor": env.get("next_cursor"),
        }

    def list_all(self, tenant_id: str, params: Optional[AuditLogListParams] = None) -> Iterator[AuditLog]:
        params = params or AuditLogListParams()
        cursor = params.cursor
        while True:
            result = self.list(
                tenant_id,
                AuditLogListParams(
                    event=params.event,
                    actor_id=params.actor_id,
                    from_=params.from_,
                    to=params.to,
                    limit=params.limit,
                    cursor=cursor,
                ),
            )
            for entry in result["data"]:
                yield entry
            cursor = result.get("next_cursor")
            if not cursor:
                break

    def verify(self, tenant_id: str, entry_id: str) -> bool:
        res = self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/audit/{quote(entry_id, safe='')}/verify",
            {},
        )
        return bool((res or {}).get("valid", False))
