import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  StatusPill,
  buttonVariants,
} from "@qeetrix/ui";
import { Link, createFileRoute } from "@tanstack/react-router";
import { CheckIcon, CopyIcon, DownloadIcon, KeyRoundIcon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { StepUpDialog } from "@/components/step-up-dialog";
import { ApiError } from "@/lib/api";
import { isStepUpRequired, useRecoveryStatus, useRegenerateRecoveryCodes } from "@/lib/mfa";

export const Route = createFileRoute("/_app/auth/mfa/recovery-codes")({ component: RecoveryCodesPage });

function RecoveryCodesPage() {
  const { t } = useTranslation("auth");
  const statusQ = useRecoveryStatus();
  const regenM = useRegenerateRecoveryCodes();
  const [copied, setCopied] = useState(false);
  const [stepUpOpen, setStepUpOpen] = useState(false);

  // Regenerating recovery codes is RequireRecentMFA-gated. On a 403
  // step_up_required, open the step-up dialog and retry after re-verification
  // (QID-17) instead of dead-ending on a toast.
  function regenerate() {
    regenM.mutate(undefined, {
      onSuccess: () => toast.success(t("mfa.recoveryCodes.toastSuccess")),
      onError: (err) => {
        if (isStepUpRequired(err)) setStepUpOpen(true);
        else toast.error(err instanceof ApiError ? err.message : t("mfa.recoveryCodes.toastError"));
      },
    });
  }

  const status = statusQ.data;
  const fresh = regenM.data?.recovery_codes;
  const low = (status?.remaining ?? 0) <= 3;

  const copyAll = (codes: string[]) => {
    void navigator.clipboard?.writeText(codes.join("\n"));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  const download = (codes: string[]) => {
    const blob = new Blob([codes.join("\n") + "\n"], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "qeet-id-recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description={t("mfa.recoveryCodes.description")} />

      <DataState
        isLoading={statusQ.isLoading}
        isError={statusQ.isError}
        error={statusQ.error}
        isEmpty={false}
        skeletonRows={2}
      >
        {!status?.enrolled ? (
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t("mfa.recoveryCodes.notEnrolled.title")}</CardTitle>
              <CardDescription>
                {t("mfa.recoveryCodes.notEnrolled.description")}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Link to="/auth/mfa/totp" className={buttonVariants({ variant: "default", size: "sm" })}>
                <KeyRoundIcon /> {t("mfa.recoveryCodes.notEnrolled.setupBtn")}
              </Link>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardDescription>{t("mfa.recoveryCodes.stats.remaining")}</CardDescription>
                <KeyRoundIcon className="size-4 text-muted-foreground" />
              </CardHeader>
              <CardContent className="flex items-center gap-3">
                <div className="text-2xl font-semibold tracking-tight">
                  {status.remaining}
                  <span className="text-base font-normal text-muted-foreground">
                    {" "}
                    / {status.total || 10}
                  </span>
                </div>
                <StatusPill kind={low ? "warning" : "success"}>
                  {low ? t("mfa.recoveryCodes.stats.low") : t("mfa.recoveryCodes.stats.healthy")}
                </StatusPill>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-base">{t("mfa.recoveryCodes.generate.title")}</CardTitle>
                <CardDescription>{t("mfa.recoveryCodes.generate.description")}</CardDescription>
              </CardHeader>
              <CardContent>
                <Button size="sm" onClick={regenerate} disabled={regenM.isPending}>
                  <RefreshCwIcon className={regenM.isPending ? "animate-spin" : ""} />
                  {status.total > 0 ? t("mfa.recoveryCodes.generate.regenerateBtn") : t("mfa.recoveryCodes.generate.generateBtn")}
                </Button>
              </CardContent>
            </Card>
          </div>
        )}

        {fresh && fresh.length > 0 && (
          <Card className="border-primary">
            <CardHeader>
              <CardTitle className="text-base">{t("mfa.recoveryCodes.fresh.title")}</CardTitle>
              <CardDescription>
                {t("mfa.recoveryCodes.fresh.description")}
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="grid grid-cols-2 gap-2 rounded-md border bg-muted/40 p-4 font-mono text-sm">
                {fresh.map((rc) => (
                  <span key={rc} className="tracking-widest">
                    {rc}
                  </span>
                ))}
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => copyAll(fresh)}>
                  {copied ? <CheckIcon /> : <CopyIcon />}
                  {copied ? t("mfa.recoveryCodes.fresh.copiedBtn") : t("mfa.recoveryCodes.fresh.copyAllBtn")}
                </Button>
                <Button variant="outline" size="sm" onClick={() => download(fresh)}>
                  <DownloadIcon /> {t("mfa.recoveryCodes.fresh.downloadBtn")}
                </Button>
              </div>
            </CardContent>
          </Card>
        )}
      </DataState>

      <StepUpDialog
        open={stepUpOpen}
        onOpenChange={setStepUpOpen}
        actionLabel={t("mfa.recoveryCodes.stepUpLabel")}
        onVerified={regenerate}
      />
    </div>
  );
}
