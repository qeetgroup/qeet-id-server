"""IP allowlist/denylist resource (maps to /v1/tenants/{id}/ip-rules)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from .client import HttpClient

__all__ = ["IpRule", "CreateIpRuleInput", "IpRules"]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class IpRule:
    id: str
    tenant_id: str
    cidr: str
    action: str
    created_at: str
    description: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "IpRule":
        return cls(
            id=d.get("id", ""),
            tenant_id=d.get("tenant_id", ""),
            cidr=d.get("cidr", ""),
            action=d.get("action", ""),
            created_at=d.get("created_at", ""),
            description=d.get("description"),
        )


@dataclass
class CreateIpRuleInput:
    cidr: str
    action: str
    description: Optional[str] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({"cidr": self.cidr, "action": self.action, "description": self.description})


class IpRules:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(self, tenant_id: str, input: CreateIpRuleInput) -> IpRule:
        res = self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/ip-rules",
            input._to_json(),
        )
        return IpRule._from_json(res or {})

    def delete(self, tenant_id: str, id: str) -> None:
        self._http.delete(
            f"/v1/tenants/{quote(tenant_id, safe='')}/ip-rules/{quote(id, safe='')}"
        )

    def list(self, tenant_id: str) -> List[IpRule]:
        res = self._http.get(f"/v1/tenants/{quote(tenant_id, safe='')}/ip-rules")
        env = res or {}
        items = env.get("items") or env.get("data") or []
        return [IpRule._from_json(r) for r in items]
