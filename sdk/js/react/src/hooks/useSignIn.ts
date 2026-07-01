"use client";

import { useState, useCallback } from "react";

import { useQeetIDClient } from "../context.js";

export type SignInStatus =
  | { step: "idle" }
  | { step: "loading" }
  | { step: "needs_mfa"; mfaToken: string }
  | { step: "complete" }
  | { step: "error"; error: string };

export interface UseSignInReturn {
  status: SignInStatus;
  signIn(params: { email: string; password: string }): Promise<void>;
  verifyMfa(params: { code: string; remember?: boolean }): Promise<void>;
  reset(): void;
}

/**
 * useSignIn drives an email+password sign-in flow with optional MFA.
 * Requires `apiUrl` on <QeetIDProvider> (embedded mode).
 *
 *   const { status, signIn, verifyMfa } = useSignIn();
 *   await signIn({ email, password });
 *   if (status.step === "needs_mfa") await verifyMfa({ code });
 */
export function useSignIn(): UseSignInReturn {
  const client = useQeetIDClient();
  const [status, setStatus] = useState<SignInStatus>({ step: "idle" });

  const signIn = useCallback(
    async ({ email, password }: { email: string; password: string }) => {
      if (!client) throw new Error("useSignIn requires apiUrl on <QeetIDProvider>");
      setStatus({ step: "loading" });
      try {
        const result = await client.signIn({ email, password });
        if (result.status === "needs_mfa") {
          setStatus({ step: "needs_mfa", mfaToken: result.mfaToken });
        } else {
          setStatus({ step: "complete" });
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : "Sign in failed";
        setStatus({ step: "error", error: msg });
      }
    },
    [client],
  );

  const verifyMfa = useCallback(
    async ({ code, remember }: { code: string; remember?: boolean }) => {
      if (!client) throw new Error("useSignIn requires apiUrl on <QeetIDProvider>");
      if (status.step !== "needs_mfa") return;
      setStatus({ step: "loading" });
      try {
        await client.verifyMfa({ mfaToken: status.mfaToken, code, remember });
        setStatus({ step: "complete" });
      } catch (e) {
        const msg = e instanceof Error ? e.message : "MFA verification failed";
        setStatus({ step: "error", error: msg });
      }
    },
    [client, status],
  );

  const reset = useCallback(() => setStatus({ step: "idle" }), []);

  return { status, signIn, verifyMfa, reset };
}
