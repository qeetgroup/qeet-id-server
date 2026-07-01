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

from .agents import Agent, AgentTokenResult, Agents, CreateAgentInput
from .api_keys import ApiKey, ApiKeys, CreateApiKeyInput
from .audit_logs import AuditLog, AuditLogListParams, AuditLogs
from .auth_hooks import AuthHookSettings, AuthHooks, UpdateAuthHookInput
from .auth_policy import AuthPolicy, AuthPolicySettings, UpdateAuthPolicyInput
from .branding import Branding, BrandingSettings, UpdateBrandingInput
from .client import DEFAULT_BASE_URL, HttpClient
from .credentials import (
    Credential,
    Credentials,
    IssueCredentialInput,
    IssueCredentialResult,
    VerifyCredentialResult,
)
from .domains import CreateDomainInput, Domain, Domains
from .email_templates import EmailTemplate, EmailTemplates, UpdateEmailTemplateInput
from .oauth_helpers import IntrospectResult, OAuth, TokenExchangeInput, TokenExchangeResult
from .oidc_clients import CreateOidcClientInput, OidcClient, OidcClients, UpdateOidcClientInput
from .saml import CreateSamlConnectionInput, Saml, SamlConnection, UpdateSamlConnectionInput
from .vault import CreateSecretInput, Secret, UpdateSecretInput, Vault
from .errors import (
    ForbiddenError,
    InvalidCredentialsError,
    NotFoundError,
    QeetidError,
    RateLimitError,
    SessionVerificationError,
)
from .groups import CreateGroupInput, Group, GroupMember, Groups, UpdateGroupInput
from .invitations import CreateInvitationInput, Invitation, Invitations
from .ip_rules import CreateIpRuleInput, IpRule, IpRules
from .mfa import MfaAdmin, MfaFactor
from .permissions import CreatePermissionInput, Permission, Permissions
from .roles import CreateRoleInput, Role, Roles, UpdateRoleInput
from .webhooks import CreateWebhookInput, UpdateWebhookInput, Webhook, WebhookDelivery, Webhooks
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
    "Groups",
    "Invitations",
    "Branding",
    "Domains",
    "Roles",
    "Permissions",
    "MfaAdmin",
    "AuthPolicy",
    "IpRules",
    "ApiKeys",
    "Webhooks",
    "AuthHooks",
    "Saml",
    "OidcClients",
    "AuditLogs",
    "EmailTemplates",
    "Agents",
    "Vault",
    "OAuth",
    "Credentials",
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
    "Group",
    "CreateGroupInput",
    "UpdateGroupInput",
    "GroupMember",
    "Invitation",
    "CreateInvitationInput",
    "BrandingSettings",
    "UpdateBrandingInput",
    "Domain",
    "CreateDomainInput",
    "Role",
    "CreateRoleInput",
    "UpdateRoleInput",
    "Permission",
    "CreatePermissionInput",
    "MfaFactor",
    "AuthPolicySettings",
    "UpdateAuthPolicyInput",
    "IpRule",
    "CreateIpRuleInput",
    "Agent",
    "CreateAgentInput",
    "AgentTokenResult",
    "Secret",
    "CreateSecretInput",
    "UpdateSecretInput",
    "TokenExchangeInput",
    "TokenExchangeResult",
    "IntrospectResult",
    "Credential",
    "IssueCredentialInput",
    "IssueCredentialResult",
    "VerifyCredentialResult",
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
        API base URL. Defaults to ``https://api.id.qeet.in``.
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
        self.groups = Groups(self._http)
        self.invitations = Invitations(self._http)
        self.branding = Branding(self._http)
        self.domains = Domains(self._http)
        self.roles = Roles(self._http)
        self.permissions = Permissions(self._http)
        self.mfa = MfaAdmin(self._http)
        self.auth_policy = AuthPolicy(self._http)
        self.ip_rules = IpRules(self._http)
        self.api_keys = ApiKeys(self._http)
        self.webhooks = Webhooks(self._http)
        self.auth_hooks = AuthHooks(self._http)
        self.saml = Saml(self._http)
        self.oidc_clients = OidcClients(self._http)
        self.audit_logs = AuditLogs(self._http)
        self.email_templates = EmailTemplates(self._http)
        self.agents = Agents(self._http)
        self.vault = Vault(self._http)
        self.credentials = Credentials(self._http)
        # Sessions and OAuth share the raw httpx client (no API-key header needed).
        self.sessions = Sessions(self._http.base_url, self._http._http)
        self.oauth = OAuth(self._http.base_url, self._http._http)

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
