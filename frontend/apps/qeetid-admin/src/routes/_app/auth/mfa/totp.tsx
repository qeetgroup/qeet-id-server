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
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { CheckIcon, CopyIcon, FingerprintIcon, Loader2Icon, ShieldCheckIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";

export const Route = createFileRoute("/_app/auth/mfa/totp")({ component: MfaTotpPage });

type EnrollStart = { secret: string; provisioning_url: string };
type ConfirmResult = { recovery_codes: string[] };

type Stage = "idle" | "enrolling" | "confirmed";

function MfaTotpPage() {
  const [stage, setStage] = useState<Stage>("idle");
  const [enrollment, setEnrollment] = useState<EnrollStart | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState("");

  const startM = useMutation({
    mutationFn: () => api<EnrollStart>("/v1/mfa/totp/enroll/start", { method: "POST", body: {} }),
    onSuccess: (res) => {
      setEnrollment(res);
      setStage("enrolling");
    },
  });

  const confirmM = useMutation({
    mutationFn: (code: string) =>
      api<ConfirmResult>("/v1/mfa/totp/enroll/confirm", { method: "POST", body: { code } }),
    onSuccess: (res) => {
      setRecoveryCodes(res.recovery_codes);
      setStage("confirmed");
    },
  });

  const disableM = useMutation({
    mutationFn: () => api<void>("/v1/mfa/totp", { method: "DELETE" }),
    onSuccess: () => {
      setStage("idle");
      setEnrollment(null);
      setRecoveryCodes(null);
    },
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="Time-based One-Time Password (RFC 6238). Use any TOTP authenticator: 1Password, Authy, Google Authenticator, Microsoft Authenticator, etc." />

      {stage === "idle" && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base">TOTP authenticator</CardTitle>
                <CardDescription>Not enrolled yet on this account.</CardDescription>
              </div>
              <FingerprintIcon className="size-6 text-muted-foreground" />
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>• Six-digit codes generated locally on your device every 30 seconds.</li>
              <li>• You&apos;ll get 10 single-use recovery codes after enrollment.</li>
              <li>• HMAC-SHA1, 30-second time step, ±1 step clock-drift tolerance.</li>
            </ul>
            {startM.error && <FieldError>{(startM.error as ApiError).message}</FieldError>}
            <Button onClick={() => startM.mutate()} disabled={startM.isPending}>
              {startM.isPending && <Loader2Icon className="animate-spin" />}
              {startM.isPending ? "Generating secret…" : "Begin enrollment"}
            </Button>
          </CardContent>
        </Card>
      )}

      {stage === "enrolling" && enrollment && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Scan or paste into your authenticator</CardTitle>
            <CardDescription>
              Add this entry, then enter the 6-digit code your app shows to confirm.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <Field>
                <FieldLabel>otpauth:// URI</FieldLabel>
                <CopyableSecret value={enrollment.provisioning_url} size="sm" />
                <FieldDescription>
                  Most authenticators support pasting this URL. Or generate a QR from it via your password manager.
                </FieldDescription>
              </Field>
              <Field>
                <FieldLabel>Manual secret (base32)</FieldLabel>
                <CopyableSecret value={enrollment.secret} size="sm" />
                <FieldDescription>Use this if your app asks for a raw shared secret instead.</FieldDescription>
              </Field>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (code.length === 6) confirmM.mutate(code);
                }}
                className="contents"
              >
                <Field>
                  <FieldLabel>Verification code</FieldLabel>
                  <OTPInput
                    value={code}
                    onChange={setCode}
                    onComplete={(v) => confirmM.mutate(v)}
                    autoFocus
                    aria-label="TOTP verification code"
                    aria-invalid={!!confirmM.error}
                  />
                  <FieldDescription>
                    Six digits — paste the full code or type one digit at a time.
                  </FieldDescription>
                </Field>
                {confirmM.error && <Field><FieldError>{(confirmM.error as ApiError).message}</FieldError></Field>}
                <Field className="flex flex-row justify-end gap-2">
                  <Button type="button" variant="outline" onClick={() => { setStage("idle"); setCode(""); }}>
                    Cancel
                  </Button>
                  <Button type="submit" disabled={confirmM.isPending || code.length !== 6}>
                    {confirmM.isPending && <Loader2Icon className="animate-spin" />}
                    {confirmM.isPending ? "Verifying…" : "Confirm"}
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
                  <CardTitle className="text-base">TOTP enrolled <Badge variant="success" className="ml-2">Active</Badge></CardTitle>
                  <CardDescription>You&apos;ll be asked for a code on every future sign-in.</CardDescription>
                </div>
                <ShieldCheckIcon className="size-6 text-emerald-600 dark:text-emerald-400" />
              </div>
            </CardHeader>
          </Card>
          <Card className="border-amber-500/40 bg-amber-50/30 dark:bg-amber-950/20">
            <CardHeader>
              <CardTitle className="text-base">Save these recovery codes</CardTitle>
              <CardDescription>
                Each code is single-use. We&apos;ll never show them again — store them in your password manager.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                {recoveryCodes.map((c) => (
                  <code key={c} className="rounded-md border bg-background px-3 py-2 text-center">{c}</code>
                ))}
              </div>
              <div className="mt-4 flex gap-2">
                <Button
                  variant="outline"
                  onClick={() => navigator.clipboard.writeText(recoveryCodes.join("\n"))}
                >
                  <CopyIcon /> Copy all
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    if (confirm("Disable TOTP for your account? Recovery codes will be wiped.")) {
                      disableM.mutate();
                    }
                  }}
                  disabled={disableM.isPending}
                >
                  {disableM.isPending && <Loader2Icon className="animate-spin" />}
                  Disable TOTP
                </Button>
              </div>
            </CardContent>
          </Card>
        </>
      )}

      {stage === "confirmed" && <CheckIcon className="hidden" />}
    </div>
  );
}
