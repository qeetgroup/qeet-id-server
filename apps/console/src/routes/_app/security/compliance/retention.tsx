import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Field,
  FieldDescription,
  FieldLabel,
  Slider,
  StatusPill,
  Switch,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import {
  type RetentionPolicy,
  useRetentionPolicy,
  useRetentionPreview,
  useRunRetention,
  useUpdateRetentionPolicy,
} from "@/lib/retention";

export const Route = createFileRoute("/_app/security/compliance/retention")({ component: RetentionPage });

function RetentionPage() {
  const { t } = useTranslation("compliance");
  const policyQ = useRetentionPolicy();
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description={t("retention.description")} />
      <DataState
        isLoading={policyQ.isLoading}
        isError={policyQ.isError}
        error={policyQ.error}
        isEmpty={false}
        skeletonRows={3}
      >
        {policyQ.data && <RetentionForm initial={policyQ.data} />}
      </DataState>
    </div>
  );
}

function RetentionForm({ initial }: { initial: RetentionPolicy }) {
  const { t } = useTranslation("compliance");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const updateM = useUpdateRetentionPolicy();
  const previewM = useRetentionPreview();
  const runM = useRunRetention();
  const [draft, setDraft] = useState<RetentionPolicy>(initial);
  const dirty =
    draft.deleted_users_enabled !== initial.deleted_users_enabled ||
    draft.deleted_users_days !== initial.deleted_users_days;

  return (
    <>
      {confirmDialog}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t("retention.deletedUsers.title")}</CardTitle>
              <CardDescription>{t("retention.deletedUsers.description")}</CardDescription>
            </div>
            <StatusPill kind={draft.deleted_users_enabled ? "success" : "muted"}>
              {draft.deleted_users_enabled
                ? t("retention.deletedUsers.enabled")
                : t("retention.deletedUsers.disabled")}
            </StatusPill>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-6">
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>{t("retention.deletedUsers.automaticPurge")}</FieldLabel>
                <FieldDescription>{t("retention.deletedUsers.automaticPurgeHelp")}</FieldDescription>
              </div>
              <Switch
                checked={draft.deleted_users_enabled}
                onCheckedChange={(v) => setDraft((d) => ({ ...d, deleted_users_enabled: v }))}
              />
            </div>
          </Field>
          <Field>
            <FieldLabel>
              {t("retention.deletedUsers.windowLabel", { days: draft.deleted_users_days })}
            </FieldLabel>
            <Slider
              value={[draft.deleted_users_days]}
              onValueChange={(v) =>
                setDraft((d) => ({ ...d, deleted_users_days: Array.isArray(v) ? (v[0] ?? 30) : v }))
              }
              min={1}
              max={365}
              step={1}
            />
            <FieldDescription>{t("retention.deletedUsers.windowHelp")}</FieldDescription>
          </Field>
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="ghost" onClick={() => previewM.mutate()} disabled={previewM.isPending}>
              {t("retention.deletedUsers.preview")}
            </Button>
            <Button
              variant="outline"
              onClick={() =>
                openConfirm({
                  title: t("retention.deletedUsers.purgeConfirmTitle"),
                  description: t("retention.deletedUsers.purgeConfirmDescription"),
                  variant: "destructive",
                  confirmLabel: t("retention.deletedUsers.purgeConfirmLabel"),
                  onConfirm: () => runM.mutate(),
                })
              }
              disabled={runM.isPending}
            >
              {t("retention.deletedUsers.runPurge")}
            </Button>
            <Button onClick={() => updateM.mutate(draft)} disabled={updateM.isPending || !dirty}>
              {updateM.isPending
                ? t("retention.deletedUsers.saving")
                : t("retention.deletedUsers.save")}
            </Button>
          </div>

          {previewM.data && (
            <p className="rounded-md border bg-muted/40 px-3 py-2 text-sm">
              {t("retention.deletedUsers.previewResult", {
                count: previewM.data.ripe_deleted_users,
                days: previewM.data.deleted_users_days,
              })}
            </p>
          )}
          {runM.data && (
            <p className="rounded-md border bg-muted/40 px-3 py-2 text-sm">
              {t("retention.deletedUsers.runResult", { count: runM.data.purged })}
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("retention.otherDataClasses.title")}</CardTitle>
          <CardDescription>{t("retention.otherDataClasses.description")}</CardDescription>
        </CardHeader>
      </Card>
    </>
  );
}
