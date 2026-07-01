"""Tenant branding resource (maps to /v1/tenants/{id}/branding)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import quote

from .client import HttpClient

__all__ = [
    "BrandingSettings",
    "UpdateBrandingInput",
    "Branding",
]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class BrandingSettings:
    tenant_id: str
    logo_url: Optional[str] = None
    primary_color: Optional[str] = None
    secondary_color: Optional[str] = None
    custom_domain: Optional[str] = None
    favicon_url: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "BrandingSettings":
        return cls(
            tenant_id=d.get("tenant_id", ""),
            logo_url=d.get("logo_url"),
            primary_color=d.get("primary_color"),
            secondary_color=d.get("secondary_color"),
            custom_domain=d.get("custom_domain"),
            favicon_url=d.get("favicon_url"),
            updated_at=d.get("updated_at"),
        )


@dataclass
class UpdateBrandingInput:
    logo_url: Optional[str] = None
    primary_color: Optional[str] = None
    secondary_color: Optional[str] = None
    custom_domain: Optional[str] = None
    favicon_url: Optional[str] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "logo_url": self.logo_url,
            "primary_color": self.primary_color,
            "secondary_color": self.secondary_color,
            "custom_domain": self.custom_domain,
            "favicon_url": self.favicon_url,
        })


class Branding:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def get(self, tenant_id: str) -> BrandingSettings:
        res = self._http.get(f"/v1/tenants/{quote(tenant_id, safe='')}/branding")
        return BrandingSettings._from_json(res or {})

    def update(self, tenant_id: str, input: UpdateBrandingInput) -> BrandingSettings:
        res = self._http.request(
            "PUT",
            f"/v1/tenants/{quote(tenant_id, safe='')}/branding",
            body=input._to_json(),
        )
        return BrandingSettings._from_json(res or {})
