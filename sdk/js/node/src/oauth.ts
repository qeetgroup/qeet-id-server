import { QeetIDError } from "./errors.js";
import type { FetchLike } from "./client.js";

export interface TokenExchangeInput {
  /** OIDC client_id that has the token_exchange grant. */
  clientId: string;
  /** OIDC client_secret. */
  clientSecret: string;
  /** The access token to exchange. */
  subjectToken: string;
  /** Downscoped space-separated permissions. Omit to inherit all subject scopes. */
  scope?: string;
  /** Actor token for RFC 8693 delegation (`act` claim). */
  actorToken?: string;
  actorTokenType?: string;
}

export interface TokenExchangeResult {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
  issued_token_type?: string;
}

export interface IntrospectResult {
  active: boolean;
  sub?: string;
  scope?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  tenant_id?: string;
  actor_type?: string;
  agent_id?: string;
  act?: Record<string, unknown>;
}

/** OAuth + MCP helpers: token-exchange (RFC 8693), introspect (RFC 7662), and an MCP token guard. */
export class OAuth {
  constructor(private readonly baseUrl: string, private readonly fetchImpl: FetchLike) {}

  /** RFC 8693 token exchange — downscope or add an `act` delegation claim. */
  async tokenExchange(input: TokenExchangeInput): Promise<TokenExchangeResult> {
    const params = new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: input.subjectToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
    });
    if (input.scope) params.set("scope", input.scope);
    if (input.actorToken) params.set("actor_token", input.actorToken);
    if (input.actorTokenType) {
      params.set("actor_token_type", input.actorTokenType);
    }
    const credentials = btoa(`${input.clientId}:${input.clientSecret}`);
    const res = await this.fetchImpl(`${this.baseUrl}/v1/oauth/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${credentials}`,
        Accept: "application/json",
      },
      body: params.toString(),
    });
    const data = await res.json() as Record<string, unknown>;
    if (!res.ok) {
      throw new QeetIDError(
        res.status,
        (data["error"] as string) ?? "token_exchange_failed",
        (data["error_description"] as string) ?? "Token exchange failed",
      );
    }
    return data as unknown as TokenExchangeResult;
  }

  /** RFC 7662 token introspection — check active state, scopes, and MCP actor claims. */
  async introspect(token: string): Promise<IntrospectResult> {
    const res = await this.fetchImpl(`${this.baseUrl}/v1/oauth/introspect`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({ token }).toString(),
    });
    if (!res.ok) {
      throw new QeetIDError(res.status, "introspect_failed", "Token introspection failed");
    }
    return res.json() as Promise<IntrospectResult>;
  }

  /**
   * MCP token guard — verify a token is active and optionally has a required scope.
   * Throws QeetIDError(401) if inactive, QeetIDError(403) if scope is missing.
   * Use this in your MCP tool handlers to enforce authentication.
   */
  async verify(token: string, requiredScope?: string): Promise<IntrospectResult> {
    const result = await this.introspect(token);
    if (!result.active) {
      throw new QeetIDError(401, "token_inactive", "Token is not active");
    }
    if (requiredScope) {
      const scopes = (result.scope ?? "").split(" ").filter(Boolean);
      if (!scopes.includes(requiredScope)) {
        throw new QeetIDError(
          403,
          "insufficient_scope",
          `Required scope: ${requiredScope}`,
        );
      }
    }
    return result;
  }
}
