// OIDC token-signing keys. Read-only from the dashboard: the JWKS the verifier
// fetches is published from these keys, and rotation is an operational task
// (run from the deploy runbook), not a console action. The list is a platform
// resource, not tenant-scoped — every tenant's tokens are signed by the same
// keyset.

import { useQuery } from "@tanstack/react-query";

import { api } from "./api";

export interface SigningKey {
  kid: string;
  alg: string;
  use: string;
  status: "active" | "retired";
}

export function useSigningKeys() {
  return useQuery({
    queryKey: ["signing-keys"],
    queryFn: () => api<{ keys: SigningKey[] }>("/v1/oidc/signing-keys"),
  });
}
