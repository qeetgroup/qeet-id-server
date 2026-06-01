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
  const policyQ = useRetentionPolicy();
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="How long deleted data is kept before it's permanently purged. Retention runs automatically once enabled; you can also preview or run it on demand." />
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
  const updateM = useUpdateRetentionPolicy();
  const previewM = useRetentionPreview();
  const runM = useRunRetention();
  const [draft, setDraft] = useState<RetentionPolicy>(initial);
  const dirty =
    draft.deleted_users_enabled !== initial.deleted_users_enabled ||
    draft.deleted_users_days !== initial.deleted_users_days;

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Soft-deleted users</CardTitle>
              <CardDescription>
                Permanently purge users that have been in the recycle bin longer than the window.
              </CardDescription>
            </div>
            <StatusPill kind={draft.deleted_users_enabled ? "success" : "muted"}>
              {draft.deleted_users_enabled ? "Enabled" : "Disabled"}
            </StatusPill>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-6">
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Automatic purge</FieldLabel>
                <FieldDescription>A background job purges ripe users hourly when enabled.</FieldDescription>
              </div>
              <Switch
                checked={draft.deleted_users_enabled}
                onCheckedChange={(v) => setDraft((d) => ({ ...d, deleted_users_enabled: v }))}
              />
            </div>
          </Field>
          <Field>
            <FieldLabel>Retention window: {draft.deleted_users_days} days</FieldLabel>
            <Slider
              value={[draft.deleted_users_days]}
              onValueChange={(v) =>
                setDraft((d) => ({ ...d, deleted_users_days: Array.isArray(v) ? (v[0] ?? 30) : v }))
              }
              min={1}
              max={365}
              step={1}
            />
            <FieldDescription>Users soft-deleted longer ago than this are purged. 1–3650 days.</FieldDescription>
          </Field>
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="ghost" onClick={() => previewM.mutate()} disabled={previewM.isPending}>
              Preview
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                if (
                  confirm(
                    "Permanently purge all soft-deleted users older than the retention window? This cannot be undone.",
                  )
                ) {
                  runM.mutate();
                }
              }}
              disabled={runM.isPending}
            >
              Run purge now
            </Button>
            <Button onClick={() => updateM.mutate(draft)} disabled={updateM.isPending || !dirty}>
              {updateM.isPending ? "Saving…" : "Save policy"}
            </Button>
          </div>

          {previewM.data && (
            <p className="rounded-md border bg-muted/40 px-3 py-2 text-sm">
              <span className="font-medium">{previewM.data.ripe_deleted_users}</span> user
              {previewM.data.ripe_deleted_users === 1 ? "" : "s"} would be purged at the current{" "}
              {previewM.data.deleted_users_days}-day window.
            </p>
          )}
          {runM.data && (
            <p className="rounded-md border bg-muted/40 px-3 py-2 text-sm">
              Purged <span className="font-medium">{runM.data.purged}</span> user
              {runM.data.purged === 1 ? "" : "s"}.
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Other data classes</CardTitle>
          <CardDescription>
            Audit logs are append-only and retained for the compliance window; session and event
            retention are managed by the platform. Configurable per-class policies are on the roadmap.
          </CardDescription>
        </CardHeader>
      </Card>
    </>
  );
}
