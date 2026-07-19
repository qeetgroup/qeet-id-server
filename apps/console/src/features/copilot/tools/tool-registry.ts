// Tool registry: assembles a Map<name, ToolDefinition> from all definitions
// and exposes the three primary access points consumed by the execution engine
// and the UI.
//
// getTool(name)    — look up a single definition by its manifest name.
// listTools()      — all 21 definitions in insertion order.
// enabledTools(can) — subset visible to the current operator (capability gate).
//
// The registry name-set is parity-checked against api/copilot/tools.manifest.json
// by the qa parity test (vitest). Every name here MUST equal a manifest entry and
// vice-versa.

import type { Capability } from "@/features/access-control/capability-model";
import type { ToolDefinition } from "./tool-types";

// ── Import all definitions ────────────────────────────────────────────────────

import { searchAuditLogsTool, searchSessionsTool } from "./definitions/audit.tools";
import { setStrictMfaTool, simulateAuthorizationTool } from "./definitions/authz.tools";
import {
  generateApiExampleTool,
  generateSdkSnippetTool,
  generateTerraformTool,
} from "./definitions/codegen.tools";
import {
  createOAuthClientTool,
  rotateOAuthClientSecretTool,
  rotateSigningKeysTool,
} from "./definitions/credentials.tools";
import { createOrganizationTool } from "./definitions/org.tools";
import { assignRoleTool, createRoleTool, grantPermissionTool } from "./definitions/role.tools";
import {
  createUserTool,
  deleteUserTool,
  disableUserTool,
  enableUserTool,
  resetUserMfaTool,
  searchUsersTool,
  updateUserTool,
} from "./definitions/user.tools";

// ── Assemble registry ─────────────────────────────────────────────────────────

// Order matches §B of the spec (directory → credentials → audit → authz → codegen).
// ToolDefinition<any>: the registry is a heterogeneous map; the execution engine
// re-validates each input via the tool's own Zod schema before dispatch, so
// `any` here is safe and avoids the contravariant `confirm` function mismatch.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ALL_TOOLS: ToolDefinition<any>[] = [
  // Directory — user
  searchUsersTool,
  createUserTool,
  updateUserTool,
  disableUserTool,
  enableUserTool,
  deleteUserTool,
  resetUserMfaTool,
  // Directory — org
  createOrganizationTool,
  // Directory — role
  createRoleTool,
  assignRoleTool,
  grantPermissionTool,
  // Authz (non-directory)
  setStrictMfaTool,
  // Credentials
  createOAuthClientTool,
  rotateOAuthClientSecretTool,
  rotateSigningKeysTool,
  // Audit
  searchAuditLogsTool,
  searchSessionsTool,
  // Authz — simulation
  simulateAuthorizationTool,
  // Codegen
  generateTerraformTool,
  generateSdkSnippetTool,
  generateApiExampleTool,
];

const REGISTRY = new Map<string, ToolDefinition>(ALL_TOOLS.map((t) => [t.name, t]));

// ── Public API ────────────────────────────────────────────────────────────────

/** Look up a tool definition by its exact manifest name. */
export function getTool(name: string): ToolDefinition | undefined {
  return REGISTRY.get(name);
}

/** All 21 tool definitions in canonical order. */
export function listTools(): ToolDefinition[] {
  return ALL_TOOLS;
}

/**
 * Subset of tools the current operator can see: filters out any tool whose
 * `requiredCapability` the `can` predicate returns false for.
 *
 * This is a UX gate (defense-in-depth); the backend endpoints each tool calls
 * remain the real authorization boundary. Never use this as a security check.
 */
export function enabledTools(can: (c?: Capability) => boolean): ToolDefinition[] {
  return ALL_TOOLS.filter((t) => can(t.requiredCapability));
}
