// MFA data layer. These endpoints are scoped to the authenticated user (the
// API derives the user from the JWT), so no tenant id is needed in the path.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ApiError, api } from "./api";

// ---- Recovery codes ----

export interface RecoveryStatus {
  enrolled: boolean;
  total: number;
  remaining: number;
}

export function useRecoveryStatus() {
  return useQuery({
    queryKey: ["mfa", "recovery-codes"],
    queryFn: () => api<RecoveryStatus>("/v1/mfa/recovery-codes"),
  });
}

export function useRegenerateRecoveryCodes() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api<{ recovery_codes: string[]; warning: string }>("/v1/mfa/recovery-codes/regenerate", {
        method: "POST",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["mfa", "recovery-codes"] }),
    // silent: a 403 step_up_required is handled locally by opening the step-up
    // dialog rather than surfacing a dead-end toast (QID-17). The success toast
    // is emitted by the screen after the (possibly re-run) mutation resolves.
    meta: { silent: true },
  });
}

// ---- Step-up verification ----
//
// Sensitive MFA actions (regenerate recovery codes, disable TOTP) are gated
// server-side by RequireRecentMFA and return 403 `step_up_required` when the
// session hasn't verified a factor recently. useStepUpVerify re-verifies a
// TOTP or recovery code (refreshing that window) so the caller can retry.
export function useStepUpVerify() {
  return useMutation({
    mutationFn: (code: string) =>
      api<{ verified: boolean }>("/v1/mfa/totp/verify", {
        method: "POST",
        body: { code },
      }),
    meta: { silent: true },
  });
}

/** True when an error is the backend's step-up-required signal. */
export function isStepUpRequired(err: unknown): boolean {
  return err instanceof ApiError && err.code === "step_up_required";
}

// ---- Email / SMS OTP factors ----

export type OtpChannel = "email" | "sms";

export interface OtpFactor {
  id: string;
  channel: OtpChannel;
  destination: string; // masked
  verified: boolean;
  created_at: string;
}

export function useOtpFactors() {
  return useQuery({
    queryKey: ["mfa", "otp-factors"],
    queryFn: () => api<{ items: OtpFactor[] }>("/v1/mfa/otp/factors"),
  });
}

export function useEnrollOtpStart() {
  return useMutation({
    mutationFn: (body: { channel: OtpChannel; destination: string }) =>
      api<{ factor_id: string; message: string }>("/v1/mfa/otp/factors", {
        method: "POST",
        body,
      }),
    meta: { successMessage: "Verification code sent" },
  });
}

export function useConfirmOtpFactor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, code }: { id: string; code: string }) =>
      api<{ verified: boolean }>(`/v1/mfa/otp/factors/${id}/confirm`, {
        method: "POST",
        body: { code },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["mfa", "otp-factors"] }),
    meta: { successMessage: "Factor confirmed" },
  });
}

export function useChallengeOtpFactor() {
  return useMutation({
    mutationFn: (id: string) =>
      api<{ message: string }>(`/v1/mfa/otp/factors/${id}/challenge`, {
        method: "POST",
      }),
    meta: { successMessage: "Test code sent" },
  });
}

export function useDeleteOtpFactor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<void>(`/v1/mfa/otp/factors/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["mfa", "otp-factors"] }),
    meta: { successMessage: "Factor removed" },
  });
}
