"""Email template management (maps to /v1/tenants/{id}/email-templates/{type})."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import quote

from .client import HttpClient

__all__ = ["EmailTemplate", "UpdateEmailTemplateInput", "EmailTemplates"]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class EmailTemplate:
    tenant_id: str
    type: str
    subject: str
    html_body: str
    text_body: Optional[str] = None
    from_name: Optional[str] = None
    from_address: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def _from_json(cls, d: Dict[str, Any]) -> "EmailTemplate":
        return cls(
            tenant_id=d.get("tenant_id", ""),
            type=d.get("type", ""),
            subject=d.get("subject", ""),
            html_body=d.get("html_body", ""),
            text_body=d.get("text_body"),
            from_name=d.get("from_name"),
            from_address=d.get("from_address"),
            updated_at=d.get("updated_at"),
        )


@dataclass
class UpdateEmailTemplateInput:
    subject: Optional[str] = None
    html_body: Optional[str] = None
    text_body: Optional[str] = None
    from_name: Optional[str] = None
    from_address: Optional[str] = None

    def _to_json(self) -> Dict[str, Any]:
        return _compact({
            "subject": self.subject,
            "html_body": self.html_body,
            "text_body": self.text_body,
            "from_name": self.from_name,
            "from_address": self.from_address,
        })


class EmailTemplates:
    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def get(self, tenant_id: str, template_type: str) -> EmailTemplate:
        res = self._http.get(
            f"/v1/tenants/{quote(tenant_id, safe='')}/email-templates/{quote(template_type, safe='')}"
        )
        return EmailTemplate._from_json(res or {})

    def update(self, tenant_id: str, template_type: str, input: UpdateEmailTemplateInput) -> EmailTemplate:
        res = self._http.request(
            "PUT",
            f"/v1/tenants/{quote(tenant_id, safe='')}/email-templates/{quote(template_type, safe='')}",
            body=input._to_json(),
        )
        return EmailTemplate._from_json(res or {})

    def preview(self, tenant_id: str, template_type: str, to: str) -> bool:
        res = self._http.post(
            f"/v1/tenants/{quote(tenant_id, safe='')}/email-templates/{quote(template_type, safe='')}/preview",
            {"to": to},
        )
        return bool((res or {}).get("sent", False))
