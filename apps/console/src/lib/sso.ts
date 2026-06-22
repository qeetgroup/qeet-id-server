// Email-domain SSO discovery. The endpoint is part of the §8.4 frontend
// scope; backend implementation is forthcoming. We surface SSO redirect
// hints to the sign-in form so corporate emails skip password entry and
// jump straight to their IdP.

import { useQuery } from "@tanstack/react-query";

import { ApiError, api } from "./api";

export interface SSODiscoveryHit {
  kind: "saml" | "oidc";
  provider_name: string;
  redirect_url: string;
}

const EMAIL_RE = /^[^\s@]+@[^\s@.]+\.[^\s@]+$/;

function emailLooksValid(email: string): boolean {
  return EMAIL_RE.test(email.trim());
}

/**
 * Look up whether a given email's domain has SSO configured. Returns
 * `null` when no SSO is configured for the domain (404 from backend or
 * endpoint not deployed yet); throws for transport / 5xx errors so
 * callers can decide whether to fall back silently.
 *
 * Caller is expected to debounce — pass the value already debounced so
 * we don't hammer the discovery endpoint on every keystroke.
 */
export function useSSODiscovery(email: string) {
  const trimmed = email.trim().toLowerCase();
  const enabled = emailLooksValid(trimmed);

  return useQuery({
    queryKey: ["sso-discovery", trimmed],
    enabled,
    queryFn: async (): Promise<SSODiscoveryHit | null> => {
      try {
        return await api<SSODiscoveryHit>("/v1/sso/discovery", {
          query: { email: trimmed },
          anonymous: true,
        });
      } catch (err) {
        // 404 → no SSO configured. 501 → endpoint not deployed yet.
        // Either way return null and let the form keep its
        // password-based code path.
        if (err instanceof ApiError && (err.status === 404 || err.status === 501)) {
          return null;
        }
        throw err;
      }
    },
    staleTime: 60_000,
    meta: { silent: true },
    retry: false,
  });
}
