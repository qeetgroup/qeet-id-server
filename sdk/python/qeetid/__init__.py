"""Qeet ID server-side Python SDK.

Manage users and tenants, run authorization checks, and verify sessions/JWTs
from your backend.

Authenticate with a secret API key (``qk_…``); never embed it in client code.

Example
-------
::

    import os
    from qeetid import Qeetid

    qeetid = Qeetid(api_key=os.environ["QEETID_API_KEY"])

    claims = qeetid.sessions.verify(access_token)
    if qeetid.can(user=claims.user_id, tenant=claims.tenant_id, permission="billing:write"):
        qeetid.users.create(CreateUserInput(email="new@acme.com"))
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import httpx

from .client import DEFAULT_BASE_URL, HttpClient
from .errors import (
    ForbiddenError,
    InvalidCredentialsError,
    NotFoundError,
    QeetidError,
    RateLimitError,
    SessionVerificationError,
)
from .sessions import SessionClaims, Sessions, VerifyOptions
from .tenants import CreateTenantInput, Tenant, Tenants, UpdateTenantInput
from .users import (
    CreateUserInput,
    ListParams,
    Page,
    UpdateUserInput,
    User,
    Users,
)

__all__ = [
    "Qeetid",
    "PermissionCheck",
    # resources
    "Users",
    "Tenants",
    "Sessions",
    "HttpClient",
    # models / inputs
    "User",
    "CreateUserInput",
    "UpdateUserInput",
    "ListParams",
    "Page",
    "Tenant",
    "CreateTenantInput",
    "UpdateTenantInput",
    "SessionClaims",
    "VerifyOptions",
    # errors
    "QeetidError",
    "InvalidCredentialsError",
    "ForbiddenError",
    "NotFoundError",
    "RateLimitError",
    "SessionVerificationError",
]

__version__ = "0.1.0"


@dataclass
class PermissionCheck:
    """A single RBAC permission check (maps to GET /v1/check)."""

    user: str
    tenant: str
    permission: str


class Qeetid:
    """The server-side Qeet ID client.

    Construct it once with an API key and reuse it. Authenticate with your
    ``qk_…`` key — never ship it to a browser.

    Parameters
    ----------
    api_key:
        Server-side API key (``qk_…``). Required.
    base_url:
        API base URL. Defaults to ``https://api.qeetid.com``.
    timeout:
        Per-request timeout in seconds (default 10).
    max_retries:
        Max retries on 429 / 5xx for safe requests (default 2).
    http_client:
        Override the underlying ``httpx.Client`` (e.g. for tests or proxies).
    """

    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 2,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        self._http = HttpClient(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            http_client=http_client,
        )
        self.users = Users(self._http)
        self.tenants = Tenants(self._http)
        # Sessions shares the same httpx client for JWKS fetches.
        self.sessions = Sessions(self._http.base_url, self._http._http)

    def can(
        self,
        *,
        user: str,
        tenant: str,
        permission: str,
    ) -> bool:
        """Resolve a single RBAC permission check."""
        res = self._http.get(
            "/v1/check",
            query={"user_id": user, "tenant_id": tenant, "permission": permission},
        )
        return bool((res or {}).get("allowed") is True)

    def can_all(self, user: str, tenant: str, permissions: List[str]) -> bool:
        """True only if every permission passes."""
        for permission in permissions:
            if not self.can(user=user, tenant=tenant, permission=permission):
                return False
        return True

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "Qeetid":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
