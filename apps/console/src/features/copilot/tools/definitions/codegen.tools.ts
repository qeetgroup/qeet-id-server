// Code-generation tools — generate_terraform, generate_sdk_snippet,
// generate_api_example. All are pure client-side templating; nothing is applied
// or mutated. They reuse the authz-codegen.ts patterns where applicable.
//
// generate_terraform: reads live resource config via api() then emits HCL.
// generate_sdk_snippet: templated snippet for a known endpoint (no network call).
// generate_api_example: example request/response from the OpenAPI shape (no call).

import { z } from "zod";

import { api } from "@/lib/api";
import type { ToolDefinition } from "../tool-types";

// ── Helpers ───────────────────────────────────────────────────────────────────

function hclString(value: string | null | undefined): string {
  if (!value) return '""';
  return JSON.stringify(value);
}

function hclList(items: string[] | null | undefined): string {
  if (!items || items.length === 0) return "[]";
  return `[${items.map((v) => JSON.stringify(v)).join(", ")}]`;
}

// ── generate_terraform ────────────────────────────────────────────────────────

const generateTerraformInput = z.object({
  resource_type: z.enum(["oidc_client", "tenant", "role"]),
  resource_id: z.string().optional(),
});
type GenerateTerraformInput = z.infer<typeof generateTerraformInput>;

interface OidcClient {
  id: string;
  client_id: string;
  name: string;
  type: string;
  redirect_uris: string[];
  grant_types: string[];
  scopes: string[];
}

interface Tenant {
  id: string;
  name: string;
  slug: string;
}

interface Role {
  id: string;
  name: string;
  description: string;
  is_system: boolean;
}

function oidcClientHcl(client: OidcClient): string {
  const label = client.name.toLowerCase().replace(/[^a-z0-9_]/g, "_");
  return [
    `resource "qeetid_oidc_client" ${hclString(label)} {`,
    `  name          = ${hclString(client.name)}`,
    `  type          = ${hclString(client.type)}`,
    `  redirect_uris = ${hclList(client.redirect_uris)}`,
    `  grant_types   = ${hclList(client.grant_types)}`,
    `  scopes        = ${hclList(client.scopes)}`,
    "}",
  ].join("\n");
}

function tenantHcl(tenant: Tenant): string {
  const label = tenant.slug || tenant.name.toLowerCase().replace(/[^a-z0-9_]/g, "_");
  return [
    `resource "qeetid_tenant" ${hclString(label)} {`,
    `  name = ${hclString(tenant.name)}`,
    `  slug = ${hclString(tenant.slug)}`,
    "}",
  ].join("\n");
}

function roleHcl(role: Role): string {
  const label = role.name.toLowerCase().replace(/[^a-z0-9_]/g, "_");
  return [
    `resource "qeetid_role" ${hclString(label)} {`,
    `  name        = ${hclString(role.name)}`,
    `  description = ${hclString(role.description)}`,
    "}",
  ].join("\n");
}

export const generateTerraformTool: ToolDefinition<GenerateTerraformInput> = {
  name: "generate_terraform",
  category: "codegen",
  title: "Generate Terraform",
  description:
    "Generate Terraform (HCL) for an existing resource by reading its live configuration. Client-side templating; nothing is applied.",
  input: generateTerraformInput,
  requiredCapability: "connection.read",
  destructive: false,
  auditLabel: "copilot.generate_terraform",
  async run(ctx, input) {
    let hcl = "";

    if (input.resource_type === "oidc_client") {
      if (input.resource_id) {
        const client = await api<OidcClient>(
          `/v1/tenants/${ctx.tenantId}/oidc/clients/${input.resource_id}`,
          { signal: ctx.signal },
        );
        hcl = oidcClientHcl(client);
      } else {
        const data = await api<{ items: OidcClient[] }>(
          `/v1/tenants/${ctx.tenantId}/oidc/clients`,
          { signal: ctx.signal },
        );
        hcl = (data.items ?? []).map(oidcClientHcl).join("\n\n");
      }
    } else if (input.resource_type === "tenant") {
      if (input.resource_id) {
        const tenant = await api<Tenant>(`/v1/tenants/${input.resource_id}`, {
          signal: ctx.signal,
        });
        hcl = tenantHcl(tenant);
      } else {
        // Generate for the current tenant.
        const tenant = await api<Tenant>(`/v1/tenants/${ctx.tenantId}`, { signal: ctx.signal });
        hcl = tenantHcl(tenant);
      }
    } else if (input.resource_type === "role") {
      if (input.resource_id) {
        const role = await api<Role>(`/v1/tenants/${ctx.tenantId}/roles/${input.resource_id}`, {
          signal: ctx.signal,
        });
        hcl = roleHcl(role);
      } else {
        const data = await api<{ items: Role[] }>(`/v1/tenants/${ctx.tenantId}/roles`, {
          signal: ctx.signal,
        });
        hcl =
          (data.items ?? [])
            .filter((r) => !r.is_system)
            .map(roleHcl)
            .join("\n\n") || "# No custom roles found.";
      }
    }

    return {
      ok: true,
      summary: `Terraform HCL generated for ${input.resource_type}${input.resource_id ? ` (${input.resource_id})` : "s"}.`,
      data: { hcl, resource_type: input.resource_type, resource_id: input.resource_id },
    };
  },
};

// ── generate_sdk_snippet ──────────────────────────────────────────────────────

const generateSdkSnippetInput = z.object({
  endpoint: z.string(),
  language: z.enum(["curl", "typescript", "go", "python"]),
});
type GenerateSdkSnippetInput = z.infer<typeof generateSdkSnippetInput>;

function curlSnippet(endpoint: string): string {
  return `curl -X GET \\
  "https://api.qeet.id${endpoint}" \\
  -H "Authorization: Bearer $QEET_ACCESS_TOKEN" \\
  -H "X-Tenant-ID: $QEET_TENANT_ID"`;
}

function typescriptSnippet(endpoint: string): string {
  return `import { QeetIdClient } from "@qeet-id/sdk";

const client = new QeetIdClient({
  accessToken: process.env.QEET_ACCESS_TOKEN!,
  tenantId: process.env.QEET_TENANT_ID!,
});

const result = await client.fetch("${endpoint}");
console.log(result);`;
}

function goSnippet(endpoint: string): string {
  return `package main

import (
  "context"
  "fmt"

  qeetid "github.com/qeetgroup/qeet-id-go"
)

func main() {
  client := qeetid.NewClient(qeetid.WithBearerToken(os.Getenv("QEET_ACCESS_TOKEN")))
  ctx := context.Background()
  result, err := client.Get(ctx, "${endpoint}")
  if err != nil {
    panic(err)
  }
  fmt.Printf("%+v\\n", result)
}`;
}

function pythonSnippet(endpoint: string): string {
  return `import os
from qeet_id import QeetIdClient

client = QeetIdClient(
    access_token=os.environ["QEET_ACCESS_TOKEN"],
    tenant_id=os.environ["QEET_TENANT_ID"],
)

result = client.get("${endpoint}")
print(result)`;
}

export const generateSdkSnippetTool: ToolDefinition<GenerateSdkSnippetInput> = {
  name: "generate_sdk_snippet",
  category: "codegen",
  title: "Generate SDK snippet",
  description:
    "Generate a client code snippet (curl/TypeScript/Go/Python) for a known Qeet ID endpoint. Informational; client-side.",
  input: generateSdkSnippetInput,
  // No requiredCapability — informational
  destructive: false,
  auditLabel: "copilot.generate_sdk_snippet",
  async run(_ctx, input) {
    let snippet = "";
    switch (input.language) {
      case "curl":
        snippet = curlSnippet(input.endpoint);
        break;
      case "typescript":
        snippet = typescriptSnippet(input.endpoint);
        break;
      case "go":
        snippet = goSnippet(input.endpoint);
        break;
      case "python":
        snippet = pythonSnippet(input.endpoint);
        break;
    }
    return {
      ok: true,
      summary: `Generated ${input.language} snippet for ${input.endpoint}.`,
      data: { snippet, language: input.language, endpoint: input.endpoint },
    };
  },
};

// ── generate_api_example ──────────────────────────────────────────────────────

const generateApiExampleInput = z.object({
  endpoint: z.string(),
  method: z.enum(["GET", "POST", "PATCH", "PUT", "DELETE"]),
});
type GenerateApiExampleInput = z.infer<typeof generateApiExampleInput>;

function buildApiExample(endpoint: string, method: string): { request: string; response: string } {
  const hasBody = ["POST", "PATCH", "PUT"].includes(method);
  const request = [
    `${method} ${endpoint} HTTP/1.1`,
    "Host: api.qeet.id",
    "Authorization: Bearer <access_token>",
    "X-Tenant-ID: <tenant_id>",
    ...(hasBody ? ["Content-Type: application/json", "", '{ "example": "body" }'] : [""]),
  ].join("\n");

  const isDelete = method === "DELETE";
  const response = isDelete
    ? ["HTTP/1.1 204 No Content", ""].join("\n")
    : [
        "HTTP/1.1 200 OK",
        "Content-Type: application/json",
        "",
        JSON.stringify({ example: "response", endpoint, method }, null, 2),
      ].join("\n");

  return { request, response };
}

export const generateApiExampleTool: ToolDefinition<GenerateApiExampleInput> = {
  name: "generate_api_example",
  category: "codegen",
  title: "Generate API example",
  description:
    "Generate an example request/response for a Qeet ID endpoint derived from its OpenAPI shape. Informational; client-side.",
  input: generateApiExampleInput,
  // No requiredCapability — informational
  destructive: false,
  auditLabel: "copilot.generate_api_example",
  async run(_ctx, input) {
    const example = buildApiExample(input.endpoint, input.method);
    return {
      ok: true,
      summary: `Generated ${input.method} ${input.endpoint} example.`,
      data: {
        request: example.request,
        response: example.response,
        endpoint: input.endpoint,
        method: input.method,
      },
    };
  },
};
