"""Auth policy resource (maps to /v1/tenants/{id}/auth-policy)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from .client import HttpClient

__all__ = ["AuthPolicySettings", "UpdateAuthPolicyInput", "AuthPolicy"]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class AuthPolicySettings:
    tenant_id: str
    password_min_length: Optional[int] = None
    password_require_uppercase: Optional[bool] = None
    password_require_numbers: Optional[bool] = None
    password_require_symbols: Optional[bool] = None
    allowed_login_methods: Optional[List[str]] = None
    mfa_required: Optional[bool] = None
    session_duration_seconds: Optional[int] = None
    updated_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "AuthPolicySettings":
        return cls(
            tenant_id=d.get("tenant_id", ""),
            password_min_length=d.get("password_min_length"),
            password_require_uppercase=d.get("password_require_uppercase"),
            password_require_numbers=d.get("password_require_numbers"),
            password_require_symbols=d.get("password_require_symbols"),
            allowed_login_methods=d.get("allowed_login_methods"),
            mfa_required=d.get("mfa_required"),
            session_duration_seconds=d.get("session_duration_seconds"),
            updated_at=d.get("updated_at"),
        )


@dataclass
class UpdateAuthPolicyInput:
    password_min_length: Optional[int] = None
    password_require_uppercase: Optional[bool] = None
    password_require_numbers: Optional[bool] = None
    password_require_symbols: Optional[bool] = None
    allowed_login_methods: Optional[List[str]] = None
    mfa_required: Optional[bool] = None
    session_duration_seconds: Optional[int] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "password_min_length": self.password_min_length,
            "password_require_uppercase": self.password_require_uppercase,
            "password_require_numbers": self.password_require_numbers,
            "password_require_symbols": self.password_require_symbols,
            "allowed_login_methods": self.allowed_login_methods,
            "mfa_required": self.mfa_required,
            "session_duration_seconds": self.session_duration_seconds,
        })


class AuthPolicy:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def get(self, tenant_id: str) -> AuthPolicySettings:
        res = self._http.get(f"/v1/tenants/{quote(tenant_id, safe='')}/auth-policy")
        return AuthPolicySettings._from_json(res or {})

    def update(self, tenant_id: str, input: UpdateAuthPolicyInput) -> AuthPolicySettings:
        res = self._http.request(
            "PUT",
            f"/v1/tenants/{quote(tenant_id, safe='')}/auth-policy",
            body=input._to_json(),
        )
        return AuthPolicySettings._from_json(res or {})
