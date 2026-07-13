import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle } from "@qeetrix/ui";
import { useMutation } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { DownloadIcon, Trash2Icon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { ApiError, api } from "@/lib/api";

export const Route = createFileRoute("/account/data")({ component: DataPage });

function DataPage() {
  const { t } = useTranslation("account");
  const [confirmDialog, openConfirm] = useConfirmDialog();

  // Both endpoints below are part of the GDPR roadmap (§B9 data export
  // and §B10 self-service erasure). They aren't deployed yet — these
  // mutations are 404-tolerant so the buttons stay visible and the user
  // gets a friendly message until the backend lands.

  const exportM = useMutation({
    mutationFn: () =>
      api<{ download_url?: string }>("/v1/account/export", {
        method: "POST",
      }).catch((err) => {
        if (err instanceof ApiError && (err.status === 404 || err.status === 501)) {
          throw new ApiError(
            err.status,
            "endpoint_unavailable",
            "Data export isn't enabled yet. We'll email you a download link as soon as it ships.",
          );
        }
        throw err;
      }),
    meta: { successMessage: "We'll email a download link when it's ready" },
  });

  const deleteM = useMutation({
    mutationFn: () =>
      api<void>("/v1/account/delete", { method: "POST" }).catch((err) => {
        if (err instanceof ApiError && (err.status === 404 || err.status === 501)) {
          throw new ApiError(
            err.status,
            "endpoint_unavailable",
            "Self-service deletion isn't enabled yet. Contact support@qeet.in for now.",
          );
        }
        throw err;
      }),
    meta: { successMessage: "Account scheduled for deletion" },
  });

  return (
    <div className="flex flex-col gap-4">
      {confirmDialog}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <DownloadIcon className="size-5 text-muted-foreground" />
            <CardTitle className="text-base">{t("data.export.title")}</CardTitle>
          </div>
          <CardDescription>{t("data.export.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button variant="outline" onClick={() => exportM.mutate()} disabled={exportM.isPending}>
            <DownloadIcon /> {t("data.export.button")}
          </Button>
        </CardContent>
      </Card>

      <Card className="border-rose-500/40">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Trash2Icon className="size-5 text-rose-600 dark:text-rose-400" />
            <CardTitle className="text-base">{t("data.delete.title")}</CardTitle>
          </div>
          <CardDescription>{t("data.delete.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button
            variant="outline"
            className="border-rose-500/40 text-rose-700 hover:bg-rose-50 dark:text-rose-400 dark:hover:bg-rose-950/30"
            onClick={() =>
              openConfirm({
                title: t("data.delete.confirm.title"),
                description: t("data.delete.confirm.description"),
                variant: "destructive",
                confirmLabel: t("data.delete.confirm.label"),
                onConfirm: () => deleteM.mutate(),
              })
            }
            disabled={deleteM.isPending}
          >
            <Trash2Icon /> {t("data.delete.button")}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
