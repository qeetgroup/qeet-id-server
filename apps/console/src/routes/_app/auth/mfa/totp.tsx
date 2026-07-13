import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CopyableSecret,
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  OTPInput,
} from "@qeetrix/ui";
import { useMutation } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { CheckIcon, CopyIcon, FingerprintIcon, Loader2Icon, ShieldCheckIcon } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { StepUpDialog } from "@/components/step-up-dialog";
import { ApiError, api } from "@/lib/api";
import { isStepUpRequired } from "@/lib/mfa";

export const Route = createFileRoute("/_app/auth/mfa/totp")({
  component: MfaTotpPage,
});

type EnrollStart = { secret: string; provisioning_url: string };
type ConfirmResult = { recovery_codes: string[] };

type Stage = "idle" | "enrolling" | "confirmed";

function MfaTotpPage() {
  const { t } = useTranslation("auth");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const [stage, setStage] = useState<Stage>("idle");
  const [enrollment, setEnrollment] = useState<EnrollStart | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState("");
  // Focus the OTP input when the enrolling stage becomes active.
  // Replaces autoFocus (flagged by jsx-a11y/no-autofocus) with an explicit
  // effect so focus transfers after the card animation settles.
  const otpWrapperRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (stage === "enrolling") {
      const id = setTimeout(() => {
        otpWrapperRef.current?.querySelector<HTMLInputElement>("input:not([disabled])")?.focus();
      }, 50);
      return () => clearTimeout(id);
    }
  }, [stage]);

  const startM = useMutation({
    mutationFn: () =>
      api<EnrollStart>("/v1/mfa/totp/enroll/start", {
        method: "POST",
        body: {},
      }),
    onSuccess: (res) => {
      setEnrollment(res);
      setStage("enrolling");
    },
  });

  const confirmM = useMutation({
    mutationFn: (otpCode: string) =>
      api<ConfirmResult>("/v1/mfa/totp/enroll/confirm", {
        method: "POST",
        body: { code: otpCode },
      }),
    onSuccess: (res) => {
      setRecoveryCodes(res.recovery_codes);
      setStage("confirmed");
    },
  });

  const [stepUpOpen, setStepUpOpen] = useState(false);

  const disableM = useMutation({
    mutationFn: () => api<void>("/v1/mfa/totp", { method: "DELETE" }),
    onSuccess: () => {
      setStage("idle");
      setEnrollment(null);
      setRecoveryCodes(null);
    },
    // silent: a 403 step_up_required opens the step-up dialog instead of a
    // dead-end toast (QID-17); success/other errors are toasted below.
    meta: { silent: true },
  });

  // Disabling TOTP is RequireRecentMFA-gated — retry after step-up on a 403.
  function disableTotp() {
    disableM.mutate(undefined, {
      onSuccess: () => toast.success(t("mfa.totp.toastDisabled")),
      onError: (err) => {
        if (isStepUpRequired(err)) setStepUpOpen(true);
        else toast.error(err instanceof ApiError ? err.message : t("mfa.totp.toastError"));
      },
    });
  }

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {confirmDialog}
      <PageHeader description={t("mfa.totp.description")} />

      {stage === "idle" && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base">{t("mfa.totp.idle.title")}</CardTitle>
                <CardDescription>{t("mfa.totp.idle.subtitle")}</CardDescription>
              </div>
              <FingerprintIcon className="size-6 text-muted-foreground" />
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>{t("mfa.totp.idle.bullet1")}</li>
              <li>{t("mfa.totp.idle.bullet2")}</li>
              <li>{t("mfa.totp.idle.bullet3")}</li>
            </ul>
            {startM.error && <FieldError>{(startM.error as ApiError).message}</FieldError>}
            <Button onClick={() => startM.mutate()} disabled={startM.isPending}>
              {startM.isPending && <Loader2Icon className="animate-spin" />}
              {startM.isPending ? t("mfa.totp.idle.generatingBtn") : t("mfa.totp.idle.beginBtn")}
            </Button>
          </CardContent>
        </Card>
      )}

      {stage === "enrolling" && enrollment && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("mfa.totp.enrolling.title")}</CardTitle>
            <CardDescription>{t("mfa.totp.enrolling.subtitle")}</CardDescription>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <Field>
                <FieldLabel>{t("mfa.totp.enrolling.uriLabel")}</FieldLabel>
                <CopyableSecret value={enrollment.provisioning_url} size="sm" />
                <FieldDescription>
                  Most authenticators support pasting this URL. Or generate a QR from it via your
                  password manager.
                </FieldDescription>
              </Field>
              <Field>
                <FieldLabel>{t("mfa.totp.enrolling.secretLabel")}</FieldLabel>
                <CopyableSecret value={enrollment.secret} size="sm" />
                <FieldDescription>
                  Use this if your app asks for a raw shared secret instead.
                </FieldDescription>
              </Field>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (code.length === 6) confirmM.mutate(code);
                }}
                className="contents"
              >
                <Field>
                  <FieldLabel>{t("mfa.totp.enrolling.codeLabel")}</FieldLabel>
                  <div ref={otpWrapperRef}>
                    <OTPInput
                      value={code}
                      onChange={setCode}
                      onComplete={(v) => confirmM.mutate(v)}
                      aria-label={t("mfa.totp.enrolling.codeAriaLabel")}
                      aria-invalid={!!confirmM.error}
                    />
                  </div>
                  <FieldDescription>
                    Six digits — paste the full code or type one digit at a time.
                  </FieldDescription>
                </Field>
                {confirmM.error && (
                  <Field>
                    <FieldError>{(confirmM.error as ApiError).message}</FieldError>
                  </Field>
                )}
                <Field className="flex flex-row justify-end gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      setStage("idle");
                      setCode("");
                    }}
                  >
                    {t("mfa.totp.enrolling.cancelBtn")}
                  </Button>
                  <Button type="submit" disabled={confirmM.isPending || code.length !== 6}>
                    {confirmM.isPending && <Loader2Icon className="animate-spin" />}
                    {confirmM.isPending
                      ? t("mfa.totp.enrolling.verifyingBtn")
                      : t("mfa.totp.enrolling.confirmBtn")}
                  </Button>
                </Field>
              </form>
            </FieldGroup>
          </CardContent>
        </Card>
      )}

      {stage === "confirmed" && recoveryCodes && (
        <>
          <Card className="border-emerald-500/40 bg-emerald-50/50 dark:bg-emerald-950/20">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base">
                    {t("mfa.totp.confirmed.title")}{" "}
                    <Badge variant="success" className="ml-2">
                      {t("mfa.totp.confirmed.activeBadge")}
                    </Badge>
                  </CardTitle>
                  <CardDescription>{t("mfa.totp.confirmed.subtitle")}</CardDescription>
                </div>
                <ShieldCheckIcon className="size-6 text-emerald-600 dark:text-emerald-400" />
              </div>
            </CardHeader>
          </Card>
          <Card className="border-amber-500/40 bg-amber-50/30 dark:bg-amber-950/20">
            <CardHeader>
              <CardTitle className="text-base">{t("mfa.totp.confirmed.recoveryTitle")}</CardTitle>
              <CardDescription>{t("mfa.totp.confirmed.recoveryDescription")}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                {recoveryCodes.map((rc) => (
                  <code key={rc} className="rounded-md border bg-background px-3 py-2 text-center">
                    {rc}
                  </code>
                ))}
              </div>
              <div className="mt-4 flex gap-2">
                <Button
                  variant="outline"
                  onClick={() => navigator.clipboard.writeText(recoveryCodes.join("\n"))}
                >
                  <CopyIcon /> {t("mfa.totp.confirmed.copyAllBtn")}
                </Button>
                <Button
                  variant="outline"
                  onClick={() =>
                    openConfirm({
                      title: t("mfa.totp.confirmed.disableConfirmTitle"),
                      description: t("mfa.totp.confirmed.disableConfirmDescription"),
                      variant: "destructive",
                      confirmLabel: t("mfa.totp.confirmed.disableConfirmLabel"),
                      onConfirm: disableTotp,
                    })
                  }
                  disabled={disableM.isPending}
                >
                  {disableM.isPending && <Loader2Icon className="animate-spin" />}
                  {t("mfa.totp.confirmed.disableBtn")}
                </Button>
              </div>
            </CardContent>
          </Card>
        </>
      )}

      {stage === "confirmed" && <CheckIcon className="hidden" />}

      <StepUpDialog
        open={stepUpOpen}
        onOpenChange={setStepUpOpen}
        actionLabel={t("mfa.totp.stepUpLabel")}
        onVerified={disableTotp}
      />
    </div>
  );
}
