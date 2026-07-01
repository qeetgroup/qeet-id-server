import { HttpClient, type QeetIDOptions } from "./client.js";
import { Agents } from "./agents.js";
import { ApiKeys } from "./apiKeys.js";
import { AuditLogs } from "./auditLogs.js";
import { AuthHooks } from "./authHooks.js";
import { AuthPolicy } from "./authPolicy.js";
import { Branding } from "./branding.js";
import { Credentials } from "./credentials.js";
import { Domains } from "./domains.js";
import { EmailTemplates } from "./emailTemplates.js";
import { Groups } from "./groups.js";
import { Invitations } from "./invitations.js";
import { IpRules } from "./ipRules.js";
import { MfaAdmin } from "./mfa.js";
import { OAuth } from "./oauth.js";
import { OidcClients } from "./oidcClients.js";
import { Permissions } from "./permissions.js";
import { Roles } from "./roles.js";
import { Saml } from "./saml.js";
import { Sessions } from "./sessions.js";
import { Tenants } from "./tenants.js";
import { Users } from "./users.js";
import { Vault } from "./vault.js";
import { Webhooks } from "./webhooks.js";

const DEFAULT_BASE_URL = "https://api.id.qeet.in";

/** A single RBAC permission check (maps to GET /v1/check). */
export interface PermissionCheck {
  /** User id. */
  user: string;
  /** Tenant id the permission is evaluated within. */
  tenant: string;
  /** Permission string, e.g. "billing:write". */
  permission: string;
}

/**
 * QeetID is the server-side client. Construct it once with an API key and reuse
 * it. Authenticate to Qeet ID with your `qk_…` key — never ship it to a browser.
 *
 * @example
 * const qeetid = new QeetID({ apiKey: process.env.QEETID_API_KEY! });
 * const claims = await qeetid.sessions.verify(accessToken);
 * if (await qeetid.can({ user: claims.userId, tenant: claims.tenantId!, permission: "billing:write" })) {
 *   await qeetid.users.create({ email: "new@acme.com" });
 * }
 */
export class QeetID {
  readonly users: Users;
  readonly tenants: Tenants;
  readonly sessions: Sessions;
  readonly groups: Groups;
  readonly invitations: Invitations;
  readonly branding: Branding;
  readonly domains: Domains;
  readonly roles: Roles;
  readonly permissions: Permissions;
  readonly mfa: MfaAdmin;
  readonly authPolicy: AuthPolicy;
  readonly ipRules: IpRules;
  readonly apiKeys: ApiKeys;
  readonly webhooks: Webhooks;
  readonly authHooks: AuthHooks;
  readonly saml: Saml;
  readonly oidcClients: OidcClients;
  readonly auditLogs: AuditLogs;
  readonly emailTemplates: EmailTemplates;
  readonly agents: Agents;
  readonly vault: Vault;
  readonly oauth: OAuth;
  readonly credentials: Credentials;
  private readonly http: HttpClient;

  constructor(options: QeetIDOptions) {
    const baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    const fetchImpl = options.fetch ?? globalThis.fetch;
    this.http = new HttpClient(options);
    this.users = new Users(this.http);
    this.tenants = new Tenants(this.http);
    this.groups = new Groups(this.http);
    this.invitations = new Invitations(this.http);
    this.branding = new Branding(this.http);
    this.domains = new Domains(this.http);
    this.roles = new Roles(this.http);
    this.permissions = new Permissions(this.http);
    this.mfa = new MfaAdmin(this.http);
    this.authPolicy = new AuthPolicy(this.http);
    this.ipRules = new IpRules(this.http);
    this.apiKeys = new ApiKeys(this.http);
    this.webhooks = new Webhooks(this.http);
    this.authHooks = new AuthHooks(this.http);
    this.saml = new Saml(this.http);
    this.oidcClients = new OidcClients(this.http);
    this.auditLogs = new AuditLogs(this.http);
    this.emailTemplates = new EmailTemplates(this.http);
    this.agents = new Agents(this.http);
    this.vault = new Vault(this.http);
    this.credentials = new Credentials(this.http);
    this.sessions = new Sessions(baseUrl, fetchImpl);
    this.oauth = new OAuth(baseUrl, fetchImpl);
  }

  /** can resolves a single RBAC permission check. */
  async can(check: PermissionCheck): Promise<boolean> {
    const res = await this.http.get<{ allowed: boolean }>("/v1/check", {
      query: { user_id: check.user, tenant_id: check.tenant, permission: check.permission },
    });
    return res.allowed === true;
  }

  /** canAll is true only if every permission passes (checks run in parallel). */
  async canAll(user: string, tenant: string, permissions: string[]): Promise<boolean> {
    const results = await Promise.all(
      permissions.map((permission) => this.can({ user, tenant, permission })),
    );
    return results.every(Boolean);
  }
}

export { HttpClient } from "./client.js";
export type { QeetIDOptions, FetchLike } from "./client.js";
export { Users } from "./users.js";
export type { User, CreateUserInput, UpdateUserInput, ListParams, Page } from "./users.js";
export { Tenants } from "./tenants.js";
export type { Tenant, CreateTenantInput, UpdateTenantInput } from "./tenants.js";
export { Sessions } from "./sessions.js";
export type { SessionClaims, VerifyOptions } from "./sessions.js";
export { Groups } from "./groups.js";
export type { Group, CreateGroupInput, UpdateGroupInput, GroupMember } from "./groups.js";
export { Invitations } from "./invitations.js";
export type { Invitation, CreateInvitationInput } from "./invitations.js";
export { Branding } from "./branding.js";
export type { BrandingSettings, UpdateBrandingInput } from "./branding.js";
export { Domains } from "./domains.js";
export type { Domain, CreateDomainInput } from "./domains.js";
export { Roles } from "./roles.js";
export type { Role, CreateRoleInput, UpdateRoleInput } from "./roles.js";
export { Permissions } from "./permissions.js";
export type { Permission, CreatePermissionInput } from "./permissions.js";
export { MfaAdmin } from "./mfa.js";
export type { MfaFactor } from "./mfa.js";
export { AuthPolicy } from "./authPolicy.js";
export type { AuthPolicySettings, UpdateAuthPolicyInput } from "./authPolicy.js";
export { IpRules } from "./ipRules.js";
export type { IpRule, CreateIpRuleInput } from "./ipRules.js";
export { ApiKeys } from "./apiKeys.js";
export type { ApiKey, CreateApiKeyInput, RotateApiKeyResult } from "./apiKeys.js";
export { Webhooks } from "./webhooks.js";
export type {
  Webhook,
  CreateWebhookInput,
  UpdateWebhookInput,
  WebhookDelivery,
} from "./webhooks.js";
export { AuthHooks } from "./authHooks.js";
export type { AuthHookSettings, UpdateAuthHookInput } from "./authHooks.js";
export { Saml } from "./saml.js";
export type {
  SamlConnection,
  CreateSamlConnectionInput,
  UpdateSamlConnectionInput,
} from "./saml.js";
export { OidcClients } from "./oidcClients.js";
export type {
  OidcClient,
  CreateOidcClientInput,
  UpdateOidcClientInput,
} from "./oidcClients.js";
export { AuditLogs } from "./auditLogs.js";
export type { AuditLog, AuditLogListParams, AuditLogPage } from "./auditLogs.js";
export { EmailTemplates } from "./emailTemplates.js";
export type {
  EmailTemplate,
  EmailTemplateType,
  UpdateEmailTemplateInput,
} from "./emailTemplates.js";
export { Agents } from "./agents.js";
export type { Agent, CreateAgentInput, AgentTokenResult } from "./agents.js";
export { Vault } from "./vault.js";
export type { Secret, CreateSecretInput, UpdateSecretInput } from "./vault.js";
export { OAuth } from "./oauth.js";
export type {
  TokenExchangeInput,
  TokenExchangeResult,
  IntrospectResult,
} from "./oauth.js";
export { Credentials } from "./credentials.js";
export type {
  Credential,
  IssueCredentialInput,
  IssueCredentialResult,
  VerifyCredentialResult,
} from "./credentials.js";
export {
  QeetIDError,
  InvalidCredentialsError,
  ForbiddenError,
  NotFoundError,
  RateLimitError,
  SessionVerificationError,
} from "./errors.js";
