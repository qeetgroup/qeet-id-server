import { HttpClient, type QeetidOptions } from "./client.js";
import { Sessions } from "./sessions.js";
import { Tenants } from "./tenants.js";
import { Users } from "./users.js";

const DEFAULT_BASE_URL = "https://api.qeetid.com";

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
 * Qeetid is the server-side client. Construct it once with an API key and reuse
 * it. Authenticate to Qeet ID with your `qk_…` key — never ship it to a browser.
 *
 * @example
 * const qeetid = new Qeetid({ apiKey: process.env.QEETID_API_KEY! });
 * const claims = await qeetid.sessions.verify(accessToken);
 * if (await qeetid.can({ user: claims.userId, tenant: claims.tenantId!, permission: "billing:write" })) {
 *   await qeetid.users.create({ email: "new@acme.com" });
 * }
 */
export class Qeetid {
  readonly users: Users;
  readonly tenants: Tenants;
  readonly sessions: Sessions;
  private readonly http: HttpClient;

  constructor(options: QeetidOptions) {
    this.http = new HttpClient(options);
    this.users = new Users(this.http);
    this.tenants = new Tenants(this.http);
    const baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.sessions = new Sessions(baseUrl, options.fetch ?? globalThis.fetch);
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
export type { QeetidOptions, FetchLike } from "./client.js";
export { Users } from "./users.js";
export type { User, CreateUserInput, UpdateUserInput, ListParams, Page } from "./users.js";
export { Tenants } from "./tenants.js";
export type { Tenant, CreateTenantInput, UpdateTenantInput } from "./tenants.js";
export { Sessions } from "./sessions.js";
export type { SessionClaims, VerifyOptions } from "./sessions.js";
export {
  QeetidError,
  InvalidCredentialsError,
  ForbiddenError,
  NotFoundError,
  RateLimitError,
  SessionVerificationError,
} from "./errors.js";
