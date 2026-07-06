// Passkey data layer. The full WebAuthn flow is implemented backend-side —
// list/delete plus register and login ceremonies (register/begin+finish,
// login/begin+finish via go-webauthn). list still returns [] gracefully if the
// endpoint isn't deployed, so the UI can render the "you have no passkeys yet"
// nudge without erroring out.

import { useQuery } from "@tanstack/react-query";

import { ApiError, api } from "./api";

export interface Passkey {
  id: string;
  user_id: string;
  credential_id: string;
  device_label?: string | null;
  created_at: string;
  last_used_at?: string | null;
}

export function usePasskeys() {
  return useQuery({
    queryKey: ["passkeys"],
    queryFn: async (): Promise<{ items: Passkey[] }> => {
      try {
        return await api<{ items: Passkey[] }>("/v1/passkeys");
      } catch (err) {
        // 404 = endpoint not deployed; 501 = endpoint stubbed (ceremony
        // missing); treat both as "no passkeys" so the prompt-card
        // surface remains usable.
        if (err instanceof ApiError && (err.status === 404 || err.status === 501)) {
          return { items: [] };
        }
        throw err;
      }
    },
    staleTime: 60_000,
    meta: { silent: true },
    retry: false,
  });
}
