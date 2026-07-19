// Static route → suggestion map. Each entry is keyed by a route pattern
// (exact path or prefix) and lists Suggestion objects that make sense on that
// page. Suggestions may reference a tool name + prefilled input (so the engine
// can run them directly) or a prompt string (so the model replies naturally).
//
// Rules:
//   • tool reference: { type: "tool", toolName, prefillInput? } — matched against
//     the canonical tool name from tools.manifest.json.
//   • prompt reference: { type: "prompt", text } — opened as a new chat message.
//   • group: optional visual grouping (shown as section headers in the UI).

import type { Capability } from "@/features/access-control/capability-model";

export interface ToolSuggestion {
  type: "tool";
  toolName: string;
  label: string;
  description?: string;
  prefillInput?: Record<string, unknown>;
  /** Minimum capability the operator must hold for this suggestion to appear. */
  requiredCapability?: Capability;
}

export interface PromptSuggestion {
  type: "prompt";
  label: string;
  text: string;
  description?: string;
  requiredCapability?: Capability;
}

export type Suggestion = ToolSuggestion | PromptSuggestion;

export interface RouteSuggestionEntry {
  /** Ordered list of suggestions for this route. */
  suggestions: Suggestion[];
}

// Exact match wins; prefix match (pattern ending with /*) is the fallback.
type RoutePattern = string;
type SuggestionMap = Record<RoutePattern, RouteSuggestionEntry>;

export const ROUTE_SUGGESTIONS: SuggestionMap = {
  // ── Users list ────────────────────────────────────────────────────────────
  "/users": {
    suggestions: [
      {
        type: "tool",
        toolName: "search_users",
        label: "Search users",
        description: "Find users by name, email or status",
        requiredCapability: "user.read",
      },
      {
        type: "tool",
        toolName: "create_user",
        label: "Create a user",
        requiredCapability: "user.write",
      },
      {
        type: "prompt",
        label: "Show suspended users",
        text: "List all suspended users in this tenant.",
        requiredCapability: "user.read",
      },
      {
        type: "prompt",
        label: "Summarize user activity",
        text: "Summarize recent user activity and any anomalies in the audit log.",
        requiredCapability: "audit.read",
      },
    ],
  },

  // ── User detail ───────────────────────────────────────────────────────────
  "/users/$userId": {
    suggestions: [
      {
        type: "tool",
        toolName: "reset_user_mfa",
        label: "Reset MFA",
        description: "Force the user to re-enroll MFA at next sign-in",
        requiredCapability: "user.write",
      },
      {
        type: "tool",
        toolName: "disable_user",
        label: "Disable this user",
        requiredCapability: "user.write",
      },
      {
        type: "tool",
        toolName: "search_audit_logs",
        label: "View audit events for this user",
        description: "Search the audit log filtered to this user",
        requiredCapability: "audit.read",
      },
      {
        type: "tool",
        toolName: "search_sessions",
        label: "View active sessions",
        requiredCapability: "user.read",
      },
      {
        type: "prompt",
        label: "Summarize this user's recent activity",
        text: "Summarize the most recent audit events for the currently selected user.",
        requiredCapability: "audit.read",
      },
    ],
  },

  // ── Roles ─────────────────────────────────────────────────────────────────
  "/authorization/roles": {
    suggestions: [
      {
        type: "tool",
        toolName: "create_role",
        label: "Create a role",
        requiredCapability: "role.write",
      },
      {
        type: "tool",
        toolName: "grant_permission",
        label: "Grant permission to a role",
        requiredCapability: "role.write",
      },
      {
        type: "tool",
        toolName: "simulate_authorization",
        label: "Simulate authorization",
        description: "Test whether a user can perform an action",
        requiredCapability: "role.read",
      },
      {
        type: "prompt",
        label: "Explain the current role model",
        text: "Explain the roles and their assigned permissions in plain English.",
        requiredCapability: "role.read",
      },
    ],
  },

  // ── Authorization — policies ───────────────────────────────────────────────
  "/authorization/policies": {
    suggestions: [
      {
        type: "tool",
        toolName: "simulate_authorization",
        label: "Simulate authorization",
        description: "Evaluate an ABAC/RBAC/ReBAC decision",
        requiredCapability: "policy.read",
      },
      {
        type: "prompt",
        label: "Summarize active policies",
        text: "List and summarize the active ABAC policies for this tenant.",
        requiredCapability: "policy.read",
      },
    ],
  },

  // ── Authorization — general ────────────────────────────────────────────────
  "/authorization/*": {
    suggestions: [
      {
        type: "tool",
        toolName: "simulate_authorization",
        label: "Simulate authorization",
        requiredCapability: "role.read",
      },
      {
        type: "tool",
        toolName: "generate_terraform",
        label: "Generate Terraform for roles",
        prefillInput: { resource_type: "role" },
        requiredCapability: "connection.read",
      },
    ],
  },

  // ── Security / Audit logs ─────────────────────────────────────────────────
  "/security/audit-logs": {
    suggestions: [
      {
        type: "tool",
        toolName: "search_audit_logs",
        label: "Search audit logs",
        requiredCapability: "audit.read",
      },
      {
        type: "prompt",
        label: "Summarize anomalies",
        text: "Summarize any unusual or high-risk events in the recent audit log.",
        requiredCapability: "audit.read",
      },
      {
        type: "prompt",
        label: "Show failed login attempts",
        text: "Search the audit log for failed authentication events in the last 24 hours.",
        requiredCapability: "audit.read",
      },
      {
        type: "prompt",
        label: "List recent admin actions",
        text: "List the most recent administrative actions by all operators in this tenant.",
        requiredCapability: "audit.read",
      },
    ],
  },

  // ── Security — general ────────────────────────────────────────────────────
  "/security/*": {
    suggestions: [
      {
        type: "tool",
        toolName: "search_audit_logs",
        label: "Search audit logs",
        requiredCapability: "audit.read",
      },
      {
        type: "tool",
        toolName: "set_strict_mfa",
        label: "Set strict MFA policy",
        requiredCapability: "policy.write",
      },
    ],
  },

  // ── Applications / OIDC ───────────────────────────────────────────────────
  "/applications": {
    suggestions: [
      {
        type: "tool",
        toolName: "create_oauth_client",
        label: "Register an OAuth client",
        requiredCapability: "connection.write",
      },
      {
        type: "tool",
        toolName: "generate_terraform",
        label: "Generate Terraform for clients",
        prefillInput: { resource_type: "oidc_client" },
        requiredCapability: "connection.read",
      },
      {
        type: "prompt",
        label: "Explain OAuth flows",
        text: "Explain the OAuth 2.0 grant types available in Qeet ID and when to use each.",
      },
    ],
  },

  // ── Settings / Signing keys ───────────────────────────────────────────────
  "/settings/signing-keys": {
    suggestions: [
      {
        type: "tool",
        toolName: "rotate_signing_keys",
        label: "Rotate signing keys",
        requiredCapability: "connection.write",
      },
    ],
  },

  // ── Settings — general ────────────────────────────────────────────────────
  "/settings/*": {
    suggestions: [
      {
        type: "tool",
        toolName: "set_strict_mfa",
        label: "Configure strict MFA",
        requiredCapability: "policy.write",
      },
      {
        type: "prompt",
        label: "Explain security settings",
        text: "Explain the current authentication policy and its security implications.",
        requiredCapability: "policy.read",
      },
    ],
  },

  // ── Organizations ─────────────────────────────────────────────────────────
  "/organizations": {
    suggestions: [
      {
        type: "tool",
        toolName: "create_organization",
        label: "Create an organization",
        requiredCapability: "tenant.write",
      },
      {
        type: "tool",
        toolName: "generate_terraform",
        label: "Generate Terraform for tenant",
        prefillInput: { resource_type: "tenant" },
        requiredCapability: "connection.read",
      },
    ],
  },

  // ── Codegen / Developer ────────────────────────────────────────────────────
  "/developer/*": {
    suggestions: [
      {
        type: "tool",
        toolName: "generate_sdk_snippet",
        label: "Generate a code snippet",
        prefillInput: { language: "typescript", endpoint: "/v1/users" },
      },
      {
        type: "tool",
        toolName: "generate_api_example",
        label: "Generate an API example",
        prefillInput: { endpoint: "/v1/users", method: "GET" },
      },
    ],
  },

  // ── AI Copilot landing page ────────────────────────────────────────────────
  "/authorization/assistant": {
    suggestions: [
      {
        type: "prompt",
        label: "Simulate an authorization check",
        text: "Simulate whether a user with the Editor role can delete a document resource.",
        requiredCapability: "role.read",
      },
      {
        type: "prompt",
        label: "Explain my authorization model",
        text: "Explain the current tenant's authorization model (roles, policies, groups) in plain English.",
        requiredCapability: "role.read",
      },
      {
        type: "prompt",
        label: "Find over-privileged users",
        text: "Identify any users who appear to have more permissions than their role requires.",
        requiredCapability: "audit.read",
      },
      {
        type: "tool",
        toolName: "generate_terraform",
        label: "Export roles as Terraform",
        prefillInput: { resource_type: "role" },
        requiredCapability: "connection.read",
      },
    ],
  },
};
