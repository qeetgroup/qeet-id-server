import { createPublicKey, verify as verifySignature, type KeyObject } from "node:crypto";

import type { FetchLike } from "./client.js";
import { SessionVerificationError } from "./errors.js";

export interface SessionClaims {
  userId: string;
  tenantId?: string;
  sessionId?: string;
  scope?: string;
  subject: string;
  issuer?: string;
  audience?: string | string[];
  /** Expiry, unix seconds. */
  expiresAt: number;
  issuedAt?: number;
  /** All raw claims, for anything not surfaced above. */
  raw: Record<string, unknown>;
}

export interface VerifyOptions {
  /** Require this `iss` claim. */
  issuer?: string;
  /** Require this value to appear in `aud`. */
  audience?: string;
  /** Allowed clock skew in seconds (default 30). */
  clockToleranceSeconds?: number;
}

interface Jwk {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  kid?: string;
  use?: string;
}

const JWKS_TTL_MS = 5 * 60 * 1000;

// Sessions verifies Qeet-issued ES256 tokens against the published JWKS. After
// the keys are cached it is fully local, so it's cheap to call on every request
// — the hosted-aligned way to answer "who is this request from?" without a
// round-trip per call.
export class Sessions {
  private jwks?: { keys: Jwk[] };
  private fetchedAt = 0;

  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: FetchLike,
  ) {}

  async verify(token: string, opts: VerifyOptions = {}): Promise<SessionClaims> {
    const parts = token.split(".");
    if (parts.length !== 3) throw new SessionVerificationError("malformed token");
    const [h, p, s] = parts;
    if (h === undefined || p === undefined || s === undefined) {
      throw new SessionVerificationError("malformed token");
    }

    const header = decodeSegment(h);
    if (header.alg !== "ES256") {
      throw new SessionVerificationError(`unsupported alg ${String(header.alg)}`);
    }
    const kid = typeof header.kid === "string" ? header.kid : undefined;

    const key = await this.resolveKey(kid);
    const ok = verifySignature(
      "sha256",
      Buffer.from(`${h}.${p}`),
      { key, dsaEncoding: "ieee-p1363" },
      base64urlToBuffer(s),
    );
    if (!ok) throw new SessionVerificationError("signature verification failed");

    const payload = decodeSegment(p);
    const now = Math.floor(Date.now() / 1000);
    const skew = opts.clockToleranceSeconds ?? 30;

    const exp = numClaim(payload.exp);
    if (exp === undefined || now > exp + skew) throw new SessionVerificationError("token expired");
    const nbf = numClaim(payload.nbf);
    if (nbf !== undefined && now + skew < nbf) throw new SessionVerificationError("token not yet valid");
    if (opts.issuer && payload.iss !== opts.issuer) throw new SessionVerificationError("issuer mismatch");
    if (opts.audience && !audienceMatches(payload.aud, opts.audience)) {
      throw new SessionVerificationError("audience mismatch");
    }

    return {
      userId: strClaim(payload.user_id) ?? strClaim(payload.sub) ?? "",
      tenantId: strClaim(payload.tenant_id),
      sessionId: strClaim(payload.sid),
      scope: strClaim(payload.scope),
      subject: strClaim(payload.sub) ?? "",
      issuer: strClaim(payload.iss),
      audience: payload.aud as string | string[] | undefined,
      expiresAt: exp,
      issuedAt: numClaim(payload.iat),
      raw: payload,
    };
  }

  private async resolveKey(kid: string | undefined): Promise<KeyObject> {
    let jwks = await this.getJWKS(false);
    let jwk = findKey(jwks.keys, kid);
    if (!jwk) {
      // Unknown kid — keys may have rotated; refresh once and retry.
      jwks = await this.getJWKS(true);
      jwk = findKey(jwks.keys, kid);
    }
    if (!jwk) {
      throw new SessionVerificationError(kid ? `no JWKS key for kid ${kid}` : "no usable JWKS key");
    }
    try {
      // Import the EC JWK directly. Cast to createPublicKey's input type so we
      // don't depend on the DOM-only `JsonWebKey` global.
      const keyInput = { key: jwk, format: "jwk" } as unknown as Parameters<typeof createPublicKey>[0];
      return createPublicKey(keyInput);
    } catch (e) {
      throw new SessionVerificationError(`invalid JWK: ${(e as Error).message}`);
    }
  }

  private async getJWKS(force: boolean): Promise<{ keys: Jwk[] }> {
    if (!force && this.jwks && Date.now() - this.fetchedAt < JWKS_TTL_MS) {
      return this.jwks;
    }
    const res = await this.fetchImpl(`${this.baseUrl}/.well-known/jwks.json`, {
      headers: { Accept: "application/json" },
    });
    if (!res.ok) throw new SessionVerificationError(`JWKS fetch failed: ${res.status}`);
    const body = (await res.json()) as { keys?: Jwk[] };
    this.jwks = { keys: body.keys ?? [] };
    this.fetchedAt = Date.now();
    return this.jwks;
  }
}

function decodeSegment(seg: string): Record<string, unknown> {
  try {
    return JSON.parse(base64urlToBuffer(seg).toString("utf8")) as Record<string, unknown>;
  } catch {
    throw new SessionVerificationError("malformed token segment");
  }
}

function base64urlToBuffer(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

function findKey(keys: Jwk[], kid?: string): Jwk | undefined {
  if (kid) return keys.find((k) => k.kid === kid);
  return keys.find((k) => k.kty === "EC" && (k.use === "sig" || k.use === undefined));
}

function audienceMatches(aud: unknown, want: string): boolean {
  if (typeof aud === "string") return aud === want;
  if (Array.isArray(aud)) return aud.includes(want);
  return false;
}

function numClaim(v: unknown): number | undefined {
  return typeof v === "number" ? v : undefined;
}

function strClaim(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}
