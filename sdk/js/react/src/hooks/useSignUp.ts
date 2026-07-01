"use client";

import { useState, useCallback } from "react";

import { useQeetIDClient } from "../context.js";

export type SignUpStatus =
  | { step: "idle" }
  | { step: "loading" }
  | { step: "complete" }
  | { step: "error"; error: string };

export interface UseSignUpReturn {
  status: SignUpStatus;
  signUp(params: { email: string; password: string; displayName?: string; tenantId?: string }): Promise<void>;
  reset(): void;
}

/**
 * useSignUp drives a new-account registration flow.
 * Requires `apiUrl` on <QeetIDProvider> (embedded mode).
 *
 *   const { status, signUp } = useSignUp();
 *   await signUp({ email, password, displayName });
 */
export function useSignUp(): UseSignUpReturn {
  const client = useQeetIDClient();
  const [status, setStatus] = useState<SignUpStatus>({ step: "idle" });

  const signUp = useCallback(
    async ({
      email,
      password,
      displayName,
      tenantId,
    }: {
      email: string;
      password: string;
      displayName?: string;
      tenantId?: string;
    }) => {
      if (!client) throw new Error("useSignUp requires apiUrl on <QeetIDProvider>");
      setStatus({ step: "loading" });
      try {
        await client.signUp({ email, password, displayName, tenantId: tenantId ?? "" });
        setStatus({ step: "complete" });
      } catch (e) {
        const msg = e instanceof Error ? e.message : "Sign up failed";
        setStatus({ step: "error", error: msg });
      }
    },
    [client],
  );

  const reset = useCallback(() => setStatus({ step: "idle" }), []);

  return { status, signUp, reset };
}
