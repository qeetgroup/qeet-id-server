// Access "explain" check. Wraps GET /v1/check?explain=true into a mutation so
// the Access Tester screen can run an on-demand evaluation: given a user,
// tenant and permission, the backend returns whether access is allowed plus
// the full grant-path trace (which role granted it, and whether the grant came
// directly or via a group). Modelled as a mutation rather than a query because
// it's a user-triggered, parameterised one-shot — not something to cache or
// refetch in the background.

import { useMutation } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface ExplainPath {
  permission: string;
  granted_by: string;
  /** "direct" for a directly-assigned role, or "group:<name>" when inherited. */
  via: string;
  group_id?: string;
  role_id: string;
}

export interface ExplainResult {
  allowed: boolean;
  paths: ExplainPath[];
  reason: string;
}

export interface ExplainInput {
  user_id: string;
  permission: string;
}

export function useExplainCheck() {
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: ({ user_id, permission }: ExplainInput) =>
      api<ExplainResult>("/v1/check", {
        query: {
          user_id,
          tenant_id: tenantId ?? undefined,
          permission,
          explain: "true",
        },
      }),
    // The screen renders both allow and deny inline; no global toast.
    meta: { silent: true },
  });
}
