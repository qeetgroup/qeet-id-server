"""Webhook management resource (maps to /v1/tenants/{id}/webhooks)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from .client import HttpClient

__all__ = ["Webhook", "CreateWebhookInput", "UpdateWebhookInput", "WebhookDelivery", "Webhooks"]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class Webhook:
    id: str
    tenant_id: str
    url: str
    events: List[str]
    enabled: bool
    created_at: str
    secret: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "Webhook":
        return cls(
            id=d.get("id", ""),
            tenant_id=d.get("tenant_id", ""),
            url=d.get("url", ""),
            events=d.get("events") or [],
            enabled=bool(d.get("enabled", False)),
            created_at=d.get("created_at", ""),
            secret=d.get("secret"),
            updated_at=d.get("updated_at"),
        )


@dataclass
class CreateWebhookInput:
    url: str
    events: List[str]
    enabled: Optional[bool] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({"url": self.url, "events": self.events, "enabled": self.enabled})


@dataclass
class UpdateWebhookInput:
    url: Optional[str] = None
    events: Optional[List[str]] = None
    enabled: Optional[bool] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({"url": self.url, "events": self.events, "enabled": self.enabled})


@dataclass
class WebhookDelivery:
    id: str
    webhook_id: str
    event: str
    status: str
    created_at: str
    response_status: Optional[int] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "WebhookDelivery":
        return cls(
            id=d.get("id", ""),
            webhook_id=d.get("webhook_id", ""),
            event=d.get("event", ""),
            status=d.get("status", ""),
            created_at=d.get("created_at", ""),
            response_status=d.get("response_status"),
        )


class Webhooks:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def create(self, tenant_id: str, input: CreateWebhookInput) -> Webhook:
        res = self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/webhooks",
            input._to_json(),
        )
        return Webhook._from_json(res or {})

    def get(self, tenant_id: str, id: str) -> Webhook:
        res = self._http.get(
            f"/v1/tenants/{quote(tenant_id, safe='')}/webhooks/{quote(id, safe='')}"
        )
        return Webhook._from_json(res or {})

    def update(self, tenant_id: str, id: str, input: UpdateWebhookInput) -> Webhook:
        res = self._http.patch(
            f"/v1/tenants/{quote(tenant_id, safe='')}/webhooks/{quote(id, safe='')}",
            input._to_json(),
        )
        return Webhook._from_json(res or {})

    def delete(self, tenant_id: str, id: str) -> None:
        self._http.delete(
            f"/v1/tenants/{quote(tenant_id, safe='')}/webhooks/{quote(id, safe='')}"
        )

    def test(self, tenant_id: str, id: str) -> None:
        self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/webhooks/{quote(id, safe='')}/test",
            {},
        )

    def list(self, tenant_id: str) -> List[Webhook]:
        res = self._http.get(f"/v1/tenants/{quote(tenant_id, safe='')}/webhooks")
        env = res or {}
        items = env.get("items") or env.get("data") or []
        return [Webhook._from_json(w) for w in items]

    def list_deliveries(self, tenant_id: str, webhook_id: str) -> List[WebhookDelivery]:
        res = self._http.get(
            f"/v1/tenants/{quote(tenant_id, safe='')}/webhooks/{quote(webhook_id, safe='')}/deliveries"
        )
        env = res or {}
        items = env.get("items") or env.get("data") or []
        return [WebhookDelivery._from_json(d) for d in items]

    def retry_delivery(self, tenant_id: str, webhook_id: str, delivery_id: str) -> None:
        self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/webhooks/{quote(webhook_id, safe='')}/deliveries/{quote(delivery_id, safe='')}/retry",
            {},
        )
