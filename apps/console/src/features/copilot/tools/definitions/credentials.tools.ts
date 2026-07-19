// Credentials tools — create_oauth_client, rotate_oauth_client_secret,
// rotate_signing_keys. All three are secret-bearing: any secret material
// (client_secret, private_key_pem) goes into ToolResult.sensitiveArtifact and
// is NEVER included in summary/data or sent back to the model.
//
// Endpoints:
//   POST /v1/oidc/clients                                          — create_oauth_client
//   POST /v1/tenants/{id}/oidc/clients/{cid}/rotate-secret        — rotate_oauth_client_secret
//   POST /v1/oidc/signing-keys/rotate                             — rotate_signing_keys

import { z } from "zod";

import { api } from "@/lib/api";
import type { ToolDefinition } from "../tool-types";

// ── create_oauth_client ───────────────────────────────────────────────────────

const createOAuthClientInput = z.object({
  name: z.string(),
  type: z.enum(["public", "confidential"]),
  redirect_uris: z.array(z.string()).optional(),
  grant_types: z.array(z.string()).optional(),
  scopes: z.array(z.string()).optional(),
});
type CreateOAuthClientInput = z.infer<typeof createOAuthClientInput>;

interface CreateOidcResponse {
  client: {
    id: string;
    client_id: string;
    name: string;
    type: string;
  };
  client_secret: string;
  warning: string;
}

export const createOAuthClientTool: ToolDefinition<CreateOAuthClientInput> = {
  name: "create_oauth_client",
  category: "credentials",
  title: "Create OAuth client",
  description:
    "Register a new OAuth/OIDC client application. Confidential clients return a client_secret exactly once — it is shown to the operator only and is never sent to the model.",
  input: createOAuthClientInput,
  requiredCapability: "connection.write",
  destructive: false,
  auditLabel: "copilot.create_oauth_client",
  async run(ctx, input) {
    const res = await api<CreateOidcResponse>("/v1/oidc/clients", {
      method: "POST",
      body: { tenant_id: ctx.tenantId, ...input },
      signal: ctx.signal,
    });
    ctx.queryClient.invalidateQueries({ queryKey: ["oidc-clients"] });

    // Redact: secret never in summary or data — goes to sensitiveArtifact only.
    return {
      ok: true,
      summary: `OAuth client "${res.client.name}" registered (client_id: ${res.client.client_id}, type: ${res.client.type}).${input.type === "confidential" ? " The client secret has been shown to the operator separately and cannot be retrieved again." : ""}`,
      data: {
        id: res.client.id,
        client_id: res.client.client_id,
        name: res.client.name,
        type: res.client.type,
      },
      sensitiveArtifact:
        input.type === "confidential" && res.client_secret
          ? {
              kind: "secret" as const,
              label: `Client secret for "${res.client.name}"`,
              value: res.client_secret,
            }
          : undefined,
    };
  },
};

// ── rotate_oauth_client_secret ────────────────────────────────────────────────

const rotateOAuthClientSecretInput = z.object({ client_id: z.string() });
type RotateOAuthClientSecretInput = z.infer<typeof rotateOAuthClientSecretInput>;

interface RotateSecretResponse {
  client_secret: string;
  warning: string;
}

export const rotateOAuthClientSecretTool: ToolDefinition<RotateOAuthClientSecretInput> = {
  name: "rotate_oauth_client_secret",
  category: "credentials",
  title: "Rotate OAuth client secret",
  description:
    "Rotate a confidential OAuth client's secret. The old secret stops working. The new secret is shown to the operator once and never sent to the model. Destructive: requires confirmation.",
  input: rotateOAuthClientSecretInput,
  requiredCapability: "connection.write",
  destructive: true,
  confirm: (input) => ({
    title: "Rotate client secret",
    body: "The existing client secret will stop working immediately. Update your application before confirming. The new secret is shown once only.",
    affected: [{ label: "Client ID", value: input.client_id }],
    confirmText: "Rotate",
    tone: "destructive",
  }),
  auditLabel: "copilot.rotate_oauth_client_secret",
  async run(ctx, input) {
    const res = await api<RotateSecretResponse>(
      `/v1/tenants/${ctx.tenantId}/oidc/clients/${input.client_id}/rotate-secret`,
      {
        method: "POST",
        signal: ctx.signal,
      },
    );
    ctx.queryClient.invalidateQueries({ queryKey: ["oidc-clients"] });

    // Redact: new secret goes to sensitiveArtifact only, never in summary/data.
    return {
      ok: true,
      summary: `Client secret rotated for client ${input.client_id}. The new secret has been shown to the operator separately and cannot be retrieved again.`,
      data: { client_id: input.client_id },
      sensitiveArtifact: res.client_secret
        ? {
            kind: "secret" as const,
            label: `New client secret for ${input.client_id}`,
            value: res.client_secret,
          }
        : undefined,
    };
  },
};

// ── rotate_signing_keys ───────────────────────────────────────────────────────

const rotateSigningKeysInput = z.object({});
type RotateSigningKeysInput = z.infer<typeof rotateSigningKeysInput>;

interface RotateKeyResult {
  kid: string;
  alg: string;
  private_key_pem: string;
  warning: string;
}

export const rotateSigningKeysTool: ToolDefinition<RotateSigningKeysInput> = {
  name: "rotate_signing_keys",
  category: "credentials",
  title: "Rotate signing keys",
  description:
    "Rotate the tenant's OIDC token-signing keys. The current key is invalidated after the grace window. Returns key material shown to the operator only, never to the model. Destructive: requires confirmation.",
  input: rotateSigningKeysInput,
  requiredCapability: "connection.write",
  destructive: true,
  confirm: () => ({
    title: "Rotate signing keys",
    body: "Rotating invalidates the current signing key after the grace window. Active sessions using the old key may be affected. The private key is shown to the operator once and cannot be retrieved again.",
    affected: [{ label: "Action", value: "Rotate all tenant OIDC signing keys" }],
    confirmText: "Rotate keys",
    tone: "destructive",
  }),
  auditLabel: "copilot.rotate_signing_keys",
  async run(ctx, input) {
    // input is {} — satisfy linter
    void input;
    const res = await api<RotateKeyResult>("/v1/oidc/signing-keys/rotate", {
      method: "POST",
      signal: ctx.signal,
    });
    ctx.queryClient.invalidateQueries({ queryKey: ["signing-keys"] });

    // Redact: private key goes to sensitiveArtifact only, never in summary/data.
    return {
      ok: true,
      summary: `Signing keys rotated. New key id: ${res.kid} (${res.alg}). The private key has been shown to the operator separately.${res.warning ? ` Note: ${res.warning}` : ""}`,
      data: { kid: res.kid, alg: res.alg },
      sensitiveArtifact: res.private_key_pem
        ? {
            kind: "private_key" as const,
            label: `Private key for signing key ${res.kid}`,
            value: res.private_key_pem,
          }
        : undefined,
    };
  },
};
