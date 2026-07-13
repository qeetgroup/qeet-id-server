import {
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Field,
  FieldError,
  OTPInput,
  Spinner,
} from "@qeetrix/ui";
import { ShieldCheckIcon } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { ApiError } from "@/lib/api";
import { useStepUpVerify } from "@/lib/mfa";

type StepUpDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Called after a successful step-up verification — retry the gated action here. */
  onVerified: () => void;
  /** What the user is about to do, e.g. "regenerate your recovery codes". */
  actionLabel?: string;
};

/**
 * StepUpDialog satisfies a `step_up_required` (403) gate: it re-verifies a TOTP
 * or recovery code via /v1/mfa/totp/verify, refreshing the recent-verification
 * window, then invokes onVerified so the caller can retry the sensitive action.
 * Reusable across every RequireRecentMFA-gated console action (QID-17).
 */
export function StepUpDialog({ open, onOpenChange, onVerified, actionLabel }: StepUpDialogProps) {
  const [code, setCode] = useState("");
  const verifyM = useStepUpVerify();
  // Focus the first OTP digit input when the dialog opens. Replaces the
  // autoFocus prop (which jsx-a11y/no-autofocus flags) with an explicit
  // useEffect that fires after the dialog animation completes — the correct
  // moment for screen readers to announce the new context.
  const otpWrapperRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const id = setTimeout(() => {
      otpWrapperRef.current?.querySelector<HTMLInputElement>("input:not([disabled])")?.focus();
    }, 50);
    return () => clearTimeout(id);
  }, [open]);

  function reset() {
    setCode("");
    verifyM.reset();
  }

  function submit(value: string) {
    verifyM.mutate(value, {
      onSuccess: () => {
        reset();
        onOpenChange(false);
        onVerified();
      },
    });
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) reset();
        onOpenChange(o);
      }}
    >
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheckIcon className="size-4 text-muted-foreground" />
            Confirm it&apos;s you
          </DialogTitle>
          <DialogDescription>
            {actionLabel ? `To ${actionLabel}, ` : "This action needs a fresh check. "}
            enter a 6-digit code from your authenticator app (or a recovery code).
          </DialogDescription>
        </DialogHeader>

        <Field>
          <div ref={otpWrapperRef}>
            <OTPInput
              value={code}
              onChange={setCode}
              onComplete={submit}
              aria-label="Verification code"
              aria-invalid={verifyM.isError}
            />
          </div>
          {verifyM.isError && (
            <FieldError>
              {verifyM.error instanceof ApiError
                ? verifyM.error.message
                : "Verification failed. Try again."}
            </FieldError>
          )}
        </Field>

        <DialogFooter className="flex-row justify-end gap-2">
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={verifyM.isPending}
          >
            Cancel
          </Button>
          <Button onClick={() => submit(code)} disabled={verifyM.isPending || code.length !== 6}>
            {verifyM.isPending && <Spinner size="sm" className="mr-2" />}
            {verifyM.isPending ? "Verifying…" : "Verify"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
