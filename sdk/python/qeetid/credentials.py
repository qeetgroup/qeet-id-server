"""W3C JWT-VC management (maps to /v1/tenants/{id}/credentials + /v1/credentials/verify)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from .client import HttpClient

__all__ = [
    "Credential",
    "IssueCredentialInput",
    "IssueCredentialResult",
    "VerifyCredentialResult",
    "Credentials",
]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class Credential:
    id: str
    subject: str
    type: str
    issued_at: str
    revoked: bool
    expires_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "Credential":
        return cls(
            id=d.get("id", ""),
            subject=d.get("subject", ""),
            type=d.get("type", ""),
            issued_at=d.get("issued_at", ""),
            revoked=bool(d.get("revoked", False)),
            expires_at=d.get("expires_at"),
        )


@dataclass
class IssueCredentialInput:
    subject: str
    type: str
    claims: Optional[Dict[str, Any]] = None
    ttl_seconds: Optional[int] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "subject": self.subject,
            "type": self.type,
            "claims": self.claims,
            "ttl_seconds": self.ttl_seconds,
        })


@dataclass
class IssueCredentialResult:
    credential_id: str
    jwt: str
    expires_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "IssueCredentialResult":
        return cls(
            credential_id=d.get("credential_id", ""),
            jwt=d.get("jwt", ""),
            expires_at=d.get("expires_at"),
        )


@dataclass
class VerifyCredentialResult:
    valid: bool
    reason: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    vc: Optional[Dict[str, Any]] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "VerifyCredentialResult":
        return cls(
            valid=bool(d.get("valid", False)),
            reason=d.get("reason"),
            subject=d.get("subject"),
            issuer=d.get("issuer"),
            vc=d.get("vc"),
        )


class Credentials:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def issue(self, tenant_id: str, input: IssueCredentialInput) -> IssueCredentialResult:
        res = self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/credentials",
            input._to_json(),
        )
        return IssueCredentialResult._from_json(res or {})

    def list(self, tenant_id: str) -> List[Credential]:
        res = self._http.get(f"/v1/tenants/{quote(tenant_id, safe='')}/credentials")
        env = res or {}
        items = env.get("items") or env.get("data") or []
        return [Credential._from_json(c) for c in items]

    def revoke(self, tenant_id: str, id: str) -> None:
        self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/credentials/{quote(id, safe='')}/revoke",
            {},
        )

    def verify(self, jwt: str) -> VerifyCredentialResult:
        res = self._http.post("/v1/credentials/verify", {"credential": jwt})
        return VerifyCredentialResult._from_json(res or {})
