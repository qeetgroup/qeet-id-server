"""Auth hook settings resource (maps to /v1/tenants/{id}/auth-hooks)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import quote

from .client import HttpClient

__all__ = ["AuthHookSettings", "UpdateAuthHookInput", "AuthHooks"]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class AuthHookSettings:
    tenant_id: str
    enabled: bool
    pre_login_url: Optional[str] = None
    post_login_url: Optional[str] = None
    pre_signup_url: Optional[str] = None
    timeout_ms: Optional[int] = None
    updated_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "AuthHookSettings":
        return cls(
            tenant_id=d.get("tenant_id", ""),
            enabled=bool(d.get("enabled", False)),
            pre_login_url=d.get("pre_login_url"),
            post_login_url=d.get("post_login_url"),
            pre_signup_url=d.get("pre_signup_url"),
            timeout_ms=d.get("timeout_ms"),
            updated_at=d.get("updated_at"),
        )


@dataclass
class UpdateAuthHookInput:
    pre_login_url: Optional[str] = None
    post_login_url: Optional[str] = None
    pre_signup_url: Optional[str] = None
    enabled: Optional[bool] = None
    timeout_ms: Optional[int] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "pre_login_url": self.pre_login_url,
            "post_login_url": self.post_login_url,
            "pre_signup_url": self.pre_signup_url,
            "enabled": self.enabled,
            "timeout_ms": self.timeout_ms,
        })


class AuthHooks:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def get(self, tenant_id: str) -> AuthHookSettings:
        res = self._http.get(f"/v1/tenants/{quote(tenant_id, safe='')}/auth-hooks")
        return AuthHookSettings._from_json(res or {})

    def update(self, tenant_id: str, input: UpdateAuthHookInput) -> AuthHookSettings:
        res = self._http.request(
            "PUT",
            f"/v1/tenants/{quote(tenant_id, safe='')}/auth-hooks",
            body=input._to_json(),
        )
        return AuthHookSettings._from_json(res or {})
