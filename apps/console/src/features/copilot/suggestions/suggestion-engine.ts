// Suggestion engine: given the current ConsoleContext and a capability predicate,
// returns the ranked, capability-visible suggestions for the current route.
//
// Ranking strategy:
//   1. Exact route match → prefix match → global fallback.
//   2. Within each source, preserve the declaration order from route-suggestions.ts.
//   3. Filter out suggestions whose `requiredCapability` the operator lacks.
//   4. If a context selection is active, boost tool suggestions that accept a
//      matching `user_id` / `role_id` / `client_id` prefill (they float to top).

import type { Capability } from "@/features/access-control/capability-model";
import type { ConsoleContext } from "../context/context-types";
import { ROUTE_SUGGESTIONS, type Suggestion } from "./route-suggestions";

// ── Matcher ───────────────────────────────────────────────────────────────────

/**
 * Resolve suggestions for a given pathname.
 * Exact match wins; then the longest matching prefix ending in `/*`; then null.
 */
function matchSuggestions(pathname: string): Suggestion[] {
  // Exact match.
  if (pathname in ROUTE_SUGGESTIONS) {
    return ROUTE_SUGGESTIONS[pathname].suggestions;
  }

  // Prefix match: collect all patterns ending in /* that match, keep longest.
  let bestLen = -1;
  let bestSuggestions: Suggestion[] = [];

  for (const pattern of Object.keys(ROUTE_SUGGESTIONS)) {
    if (!pattern.endsWith("/*")) continue;
    const prefix = pattern.slice(0, -2); // strip /*
    if (pathname.startsWith(prefix)) {
      if (prefix.length > bestLen) {
        bestLen = prefix.length;
        bestSuggestions = ROUTE_SUGGESTIONS[pattern].suggestions;
      }
    }
  }

  return bestSuggestions;
}

// ── Selection boosting ────────────────────────────────────────────────────────

/**
 * Returns true if a tool suggestion should be boosted to the top because it
 * maps naturally to the current selection (e.g. `disable_user` when looking
 * at a user detail page).
 */
function matchesSelection(suggestion: Suggestion, selection: ConsoleContext["selection"]): boolean {
  if (!selection || suggestion.type !== "tool") return false;

  const { kind } = selection;
  const { toolName } = suggestion;

  if (kind === "user") {
    return [
      "disable_user",
      "enable_user",
      "delete_user",
      "reset_user_mfa",
      "update_user",
      "assign_role",
    ].includes(toolName);
  }
  if (kind === "role") {
    return ["grant_permission", "assign_role"].includes(toolName);
  }
  if (kind === "oidc_client") {
    return ["rotate_oauth_client_secret"].includes(toolName);
  }
  return false;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Rank and filter suggestions for the current console context.
 *
 * @param ctx  - The ConsoleContext from `useConsoleContext`.
 * @param can  - The capability predicate from `useCapabilities().can`.
 * @returns    - Ordered, capability-visible suggestions (max 8).
 */
export function rankSuggestions(
  ctx: ConsoleContext,
  can: (c?: Capability) => boolean,
): Suggestion[] {
  const raw = matchSuggestions(ctx.route.pathname);

  // Filter by capability.
  const visible = raw.filter((s) => {
    if (!s.requiredCapability) return true;
    return can(s.requiredCapability);
  });

  // Separate boosted (selection-matched) from the rest.
  const boosted: Suggestion[] = [];
  const rest: Suggestion[] = [];

  for (const s of visible) {
    if (matchesSelection(s, ctx.selection)) {
      // Prefill with the selection id where it fits.
      if (s.type === "tool" && ctx.selection) {
        const { id } = ctx.selection;
        const selectionPrefill: Record<string, unknown> = { ...s.prefillInput };
        if (ctx.selection.kind === "user") selectionPrefill.user_id = id;
        if (ctx.selection.kind === "role") selectionPrefill.role_id = id;
        if (ctx.selection.kind === "oidc_client") selectionPrefill.client_id = id;
        boosted.push({ ...s, prefillInput: selectionPrefill });
      } else {
        boosted.push(s);
      }
    } else {
      rest.push(s);
    }
  }

  // Boosted first, then the rest, capped at 8 to keep the strip compact.
  return [...boosted, ...rest].slice(0, 8);
}
