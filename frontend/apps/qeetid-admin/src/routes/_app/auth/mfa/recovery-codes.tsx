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
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { useRecoveryStatus, useRegenerateRecoveryCodes } from "@/lib/mfa";

export const Route = createFileRoute("/_app/auth/mfa/recovery-codes")({ component: RecoveryCodesPage });

function RecoveryCodesPage() {
  const statusQ = useRecoveryStatus();
  const regenM = useRegenerateRecoveryCodes();
  const [copied, setCopied] = useState(false);

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
      <PageHeader description="Single-use backup codes for signing in when your authenticator device is unavailable." />

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
              <CardTitle className="text-base">Enable two-factor authentication first</CardTitle>
              <CardDescription>
                Recovery codes back up an authenticator app. Set up TOTP, then generate codes here.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Link to="/auth/mfa/totp" className={buttonVariants({ variant: "default", size: "sm" })}>
                <KeyRoundIcon /> Set up authenticator
              </Link>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardDescription>Codes remaining</CardDescription>
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
                  {low ? "Running low" : "Healthy"}
                </StatusPill>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Generate new codes</CardTitle>
                <CardDescription>This invalidates any existing codes.</CardDescription>
              </CardHeader>
              <CardContent>
                <Button size="sm" onClick={() => regenM.mutate()} disabled={regenM.isPending}>
                  <RefreshCwIcon className={regenM.isPending ? "animate-spin" : ""} />
                  {status.total > 0 ? "Regenerate codes" : "Generate codes"}
                </Button>
              </CardContent>
            </Card>
          </div>
        )}

        {fresh && fresh.length > 0 && (
          <Card className="border-primary">
            <CardHeader>
              <CardTitle className="text-base">Your new recovery codes</CardTitle>
              <CardDescription>
                Save these now — for security they are shown once and cannot be retrieved again. Each
                code works a single time.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="grid grid-cols-2 gap-2 rounded-md border bg-muted/40 p-4 font-mono text-sm">
                {fresh.map((c) => (
                  <span key={c} className="tracking-widest">
                    {c}
                  </span>
                ))}
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => copyAll(fresh)}>
                  {copied ? <CheckIcon /> : <CopyIcon />}
                  {copied ? "Copied" : "Copy all"}
                </Button>
                <Button variant="outline" size="sm" onClick={() => download(fresh)}>
                  <DownloadIcon /> Download .txt
                </Button>
              </div>
            </CardContent>
          </Card>
        )}
      </DataState>
    </div>
  );
}
