"""MFA admin resource (maps to /v1/users/{id}/mfa)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from .client import HttpClient

__all__ = ["MfaFactor", "MfaAdmin"]


@dataclass
class MfaFactor:
    id: str
    user_id: str
    type: str
    status: str
    created_at: str

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "MfaFactor":
        return cls(
            id=d.get("id", ""),
            user_id=d.get("user_id", ""),
            type=d.get("type", ""),
            status=d.get("status", ""),
            created_at=d.get("created_at", ""),
        )


class MfaAdmin:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self, user_id: str) -> List[MfaFactor]:
        res = self._http.get(f"/v1/users/{quote(user_id, safe='')}/mfa")
        env = res or {}
        items = env.get("items") or env.get("data") or []
        return [MfaFactor._from_json(f) for f in items]

    def reset(self, user_id: str) -> None:
        self._http.delete(f"/v1/users/{quote(user_id, safe='')}/mfa")

    def require(self, user_id: str, tenant_id: str) -> None:
        self._http.post(
            f"/v1/users/{quote(user_id, safe='')}/mfa/require",
            {"tenant_id": tenant_id},
        )
