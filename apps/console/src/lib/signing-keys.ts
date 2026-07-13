import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";

export interface SigningKey {
  kid: string;
  alg: string;
  use: string;
  status: "active" | "retired";
}

export interface RotateKeyResult {
  kid: string;
  alg: string;
  private_key_pem: string;
  warning: string;
}

export function useSigningKeys() {
  return useQuery({
    queryKey: ["signing-keys"],
    queryFn: () => api<{ keys: SigningKey[] }>("/v1/oidc/signing-keys"),
  });
}

export function useRotateKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api<RotateKeyResult>("/v1/oidc/signing-keys/rotate", { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["signing-keys"] }),
  });
}
