"""OIDC client management (maps to /v1/oidc/clients)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import quote

from .client import HttpClient
from .users import ListParams, Page

__all__ = ["OidcClient", "CreateOidcClientInput", "UpdateOidcClientInput", "OidcClients"]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class OidcClient:
    id: str
    name: str
    client_id: str
    redirect_uris: List[str]
    grant_types: List[str]
    scopes: List[str]
    created_at: str
    tenant_id: Optional[str] = None
    token_endpoint_auth_method: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "OidcClient":
        return cls(
            id=d.get("id", ""),
            name=d.get("name", ""),
            client_id=d.get("client_id", ""),
            redirect_uris=d.get("redirect_uris") or [],
            grant_types=d.get("grant_types") or [],
            scopes=d.get("scopes") or [],
            created_at=d.get("created_at", ""),
            tenant_id=d.get("tenant_id"),
            token_endpoint_auth_method=d.get("token_endpoint_auth_method"),
            updated_at=d.get("updated_at"),
        )


@dataclass
class CreateOidcClientInput:
    name: str
    redirect_uris: List[str]
    tenant_id: Optional[str] = None
    grant_types: Optional[List[str]] = None
    scopes: Optional[List[str]] = None
    token_endpoint_auth_method: Optional[str] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "name": self.name,
            "redirect_uris": self.redirect_uris,
            "tenant_id": self.tenant_id,
            "grant_types": self.grant_types,
            "scopes": self.scopes,
            "token_endpoint_auth_method": self.token_endpoint_auth_method,
        })


@dataclass
class UpdateOidcClientInput:
    name: Optional[str] = None
    redirect_uris: Optional[List[str]] = None
    grant_types: Optional[List[str]] = None
    scopes: Optional[List[str]] = None
    token_endpoint_auth_method: Optional[str] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "name": self.name,
            "redirect_uris": self.redirect_uris,
            "grant_types": self.grant_types,
            "scopes": self.scopes,
            "token_endpoint_auth_method": self.token_endpoint_auth_method,
        })


class OidcClients:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(self, input: CreateOidcClientInput) -> OidcClient:
        res = self._http.post("/v1/oidc/clients", input._to_json())
        return OidcClient._from_json(res or {})

    def get(self, id: str) -> OidcClient:
        res = self._http.get(f"/v1/oidc/clients/{quote(id, safe='')}")
        return OidcClient._from_json(res or {})

    def update(self, id: str, input: UpdateOidcClientInput) -> OidcClient:
        res = self._http.patch(f"/v1/oidc/clients/{quote(id, safe='')}", input._to_json())
        return OidcClient._from_json(res or {})

    def delete(self, id: str) -> None:
        self._http.delete(f"/v1/oidc/clients/{quote(id, safe='')}")

    def rotate_secret(self, id: str) -> Dict[str, Any]:
        return self._http.post(f"/v1/oidc/clients/{quote(id, safe='')}/rotate-secret", {}) or {}

    def list(self, params: Optional[ListParams] = None) -> Page[OidcClient]:
        params = params or ListParams()
        res = self._http.get(
            "/v1/oidc/clients",
            query={"tenant": params.tenant, "limit": params.limit, "cursor": params.cursor},
        )
        env = res or {}
        items = env.get("items")
        if items is None:
            items = env.get("data") or []
        return Page(
            data=[OidcClient._from_json(c) for c in items],
            next_cursor=env.get("next_cursor"),
        )
