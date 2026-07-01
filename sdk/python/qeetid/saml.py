"""SAML connection management (maps to /v1/tenants/{id}/saml)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from .client import HttpClient

__all__ = ["SamlConnection", "CreateSamlConnectionInput", "UpdateSamlConnectionInput", "Saml"]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class SamlConnection:
    id: str
    tenant_id: str
    name: str
    enabled: bool
    created_at: str
    idp_entity_id: Optional[str] = None
    idp_sso_url: Optional[str] = None
    idp_certificate: Optional[str] = None
    sp_entity_id: Optional[str] = None
    sp_acs_url: Optional[str] = None
    attribute_mapping: Optional[Dict[str, str]] = None
    updated_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "SamlConnection":
        return cls(
            id=d.get("id", ""),
            tenant_id=d.get("tenant_id", ""),
            name=d.get("name", ""),
            enabled=bool(d.get("enabled", False)),
            created_at=d.get("created_at", ""),
            idp_entity_id=d.get("idp_entity_id"),
            idp_sso_url=d.get("idp_sso_url"),
            idp_certificate=d.get("idp_certificate"),
            sp_entity_id=d.get("sp_entity_id"),
            sp_acs_url=d.get("sp_acs_url"),
            attribute_mapping=d.get("attribute_mapping"),
            updated_at=d.get("updated_at"),
        )


@dataclass
class CreateSamlConnectionInput:
    name: str
    idp_entity_id: Optional[str] = None
    idp_sso_url: Optional[str] = None
    idp_certificate: Optional[str] = None
    attribute_mapping: Optional[Dict[str, str]] = None
    enabled: Optional[bool] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "name": self.name,
            "idp_entity_id": self.idp_entity_id,
            "idp_sso_url": self.idp_sso_url,
            "idp_certificate": self.idp_certificate,
            "attribute_mapping": self.attribute_mapping,
            "enabled": self.enabled,
        })


@dataclass
class UpdateSamlConnectionInput:
    name: Optional[str] = None
    idp_entity_id: Optional[str] = None
    idp_sso_url: Optional[str] = None
    idp_certificate: Optional[str] = None
    attribute_mapping: Optional[Dict[str, str]] = None
    enabled: Optional[bool] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "name": self.name,
            "idp_entity_id": self.idp_entity_id,
            "idp_sso_url": self.idp_sso_url,
            "idp_certificate": self.idp_certificate,
            "attribute_mapping": self.attribute_mapping,
            "enabled": self.enabled,
        })


class Saml:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(self, tenant_id: str, input: CreateSamlConnectionInput) -> SamlConnection:
        res = self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/saml",
            input._to_json(),
        )
        return SamlConnection._from_json(res or {})

    def get(self, tenant_id: str, id: str) -> SamlConnection:
        res = self._http.get(
            f"/v1/tenants/{quote(tenant_id, safe='')}/saml/{quote(id, safe='')}"
        )
        return SamlConnection._from_json(res or {})

    def update(self, tenant_id: str, id: str, input: UpdateSamlConnectionInput) -> SamlConnection:
        res = self._http.patch(
            f"/v1/tenants/{quote(tenant_id, safe='')}/saml/{quote(id, safe='')}",
            input._to_json(),
        )
        return SamlConnection._from_json(res or {})

    def delete(self, tenant_id: str, id: str) -> None:
        self._http.delete(
            f"/v1/tenants/{quote(tenant_id, safe='')}/saml/{quote(id, safe='')}"
        )

    def test(self, tenant_id: str, id: str) -> Dict[str, Any]:
        return self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/saml/{quote(id, safe='')}/test",
            {},
        ) or {}

    def list(self, tenant_id: str) -> List[SamlConnection]:
        res = self._http.get(f"/v1/tenants/{quote(tenant_id, safe='')}/saml")
        env = res or {}
        items = env.get("items") or env.get("data") or []
        return [SamlConnection._from_json(c) for c in items]
