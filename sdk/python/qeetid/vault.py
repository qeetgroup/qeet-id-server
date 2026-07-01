"""Secret vault (maps to /v1/vault/{name} + /v1/tenants/{id}/secrets)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from .client import HttpClient

__all__ = ["Secret", "CreateSecretInput", "UpdateSecretInput", "Vault"]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class Secret:
    id: str
    name: str
    scope: str
    last4: str
    created_at: str
    updated_at: str

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "Secret":
        return cls(
            id=d.get("id", ""),
            name=d.get("name", ""),
            scope=d.get("scope", ""),
            last4=d.get("last4", ""),
            created_at=d.get("created_at", ""),
            updated_at=d.get("updated_at", ""),
        )


@dataclass
class CreateSecretInput:
    name: str
    scope: str
    value: str

    def _to_json(self) -> Dict[str, Any]:
        return {"name": self.name, "scope": self.scope, "value": self.value}


@dataclass
class UpdateSecretInput:
    scope: Optional[str] = None
    value: Optional[str] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({"scope": self.scope, "value": self.value})


class Vault:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def get(self, name: str) -> str:
        res = self._http.get(f"/v1/vault/{quote(name, safe='')}")
        return (res or {}).get("value", "")

    def list_secrets(self, tenant_id: str) -> List[Secret]:
        res = self._http.get(f"/v1/tenants/{quote(tenant_id, safe='')}/secrets")
        env = res or {}
        items = env.get("items") or env.get("data") or []
        return [Secret._from_json(s) for s in items]

    def create_secret(self, tenant_id: str, input: CreateSecretInput) -> Secret:
        res = self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/secrets",
            input._to_json(),
        )
        return Secret._from_json(res or {})

    def update_secret(self, tenant_id: str, id: str, input: UpdateSecretInput) -> Secret:
        res = self._http.patch(
            f"/v1/tenants/{quote(tenant_id, safe='')}/secrets/{quote(id, safe='')}",
            input._to_json(),
        )
        return Secret._from_json(res or {})

    def reveal_secret(self, tenant_id: str, id: str) -> str:
        res = self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/secrets/{quote(id, safe='')}/reveal",
            {},
        )
        return (res or {}).get("value", "")

    def delete_secret(self, tenant_id: str, id: str) -> None:
        self._http.delete(
            f"/v1/tenants/{quote(tenant_id, safe='')}/secrets/{quote(id, safe='')}"
        )
