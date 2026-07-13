import {
  Badge,
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
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, RadioTowerIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import type { ApiError } from "@/lib/api";
import {
  type SinkType,
  useCreateLogSink,
  useDeleteLogSink,
  useLogSinks,
  useToggleLogSink,
} from "@/lib/log-sinks";

export const Route = createFileRoute("/_app/security/log-streaming")({
  component: LogStreamingPage,
});

const TYPE_LABELS: Record<SinkType, string> = {
  splunk_hec: "Splunk HEC",
  datadog: "Datadog",
  http: "Generic HTTP",
};

function LogStreamingPage() {
  const { t } = useTranslation("security");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const sinksQ = useLogSinks();
  const createM = useCreateLogSink();
  const toggleM = useToggleLogSink();
  const deleteM = useDeleteLogSink();

  const [type, setType] = useState<SinkType>("splunk_hec");
  const [endpoint, setEndpoint] = useState("");
  const [token, setToken] = useState("");

  const items = sinksQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {confirmDialog}
      <PageHeader description={t("logStreaming.description")} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("logStreaming.addSink.title")}</CardTitle>
          <CardDescription>{t("logStreaming.addSink.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-3 sm:flex-row sm:items-end"
            onSubmit={(e) => {
              e.preventDefault();
              if (endpoint.trim()) {
                createM.mutate(
                  { type, endpoint: endpoint.trim(), token: token.trim() },
                  {
                    onSuccess: () => {
                      setEndpoint("");
                      setToken("");
                    },
                  },
                );
              }
            }}
          >
            <Field className="sm:w-44">
              <FieldLabel>{t("logStreaming.addSink.type")}</FieldLabel>
              <Select value={type} onValueChange={(v) => setType(v as SinkType)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="splunk_hec">Splunk HEC</SelectItem>
                  <SelectItem value="datadog">Datadog</SelectItem>
                  <SelectItem value="http">Generic HTTP</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field className="flex-1">
              <FieldLabel htmlFor="endpoint">{t("logStreaming.addSink.endpointLabel")}</FieldLabel>
              <Input
                id="endpoint"
                placeholder="https://http-intake.logs.datadoghq.com/api/v2/logs"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
              />
            </Field>
            <Field className="sm:w-56">
              <FieldLabel htmlFor="token">{t("logStreaming.addSink.tokenLabel")}</FieldLabel>
              <Input
                id="token"
                type="password"
                placeholder="write-only"
                value={token}
                onChange={(e) => setToken(e.target.value)}
              />
              <FieldDescription>{t("logStreaming.addSink.tokenHelp")}</FieldDescription>
            </Field>
            <Button type="submit" disabled={createM.isPending || !endpoint.trim()}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {t("logStreaming.addSink.add")}
            </Button>
          </form>
          {createM.error && (
            <p className="mt-2 text-destructive text-sm">{(createM.error as ApiError).message}</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("logStreaming.sinks.title")}</CardTitle>
          <CardDescription>{t("logStreaming.sinks.description")}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={sinksQ.isLoading}
            isError={sinksQ.isError}
            error={sinksQ.error}
            isEmpty={items.length === 0}
            emptyIcon={RadioTowerIcon}
            emptyTitle={t("logStreaming.sinks.empty")}
            emptyDescription={t("logStreaming.sinks.emptyDescription")}
            skeletonRows={2}
          >
            <ul className="divide-y">
              {items.map((s) => (
                <li key={s.id} className="flex items-center justify-between gap-4 px-6 py-3">
                  <div className="min-w-0">
                    <p className="flex items-center gap-2 text-sm font-medium">
                      {TYPE_LABELS[s.type] ?? s.type}
                      {s.last_error ? (
                        <Badge variant="destructive">error</Badge>
                      ) : s.last_forwarded_at ? (
                        <Badge variant="success">streaming</Badge>
                      ) : (
                        <Badge variant="outline">idle</Badge>
                      )}
                    </p>
                    <p className="truncate text-xs text-muted-foreground">{s.endpoint}</p>
                    {s.last_error ? (
                      <p className="truncate text-xs text-destructive">{s.last_error}</p>
                    ) : s.last_forwarded_at ? (
                      <p className="text-xs text-muted-foreground">
                        {t("logStreaming.sinks.lastForwarded")}{" "}
                        <TimeSince value={s.last_forwarded_at} />
                      </p>
                    ) : null}
                  </div>
                  <div className="flex items-center gap-3">
                    <Switch
                      checked={s.enabled}
                      aria-label="Enabled"
                      disabled={toggleM.isPending}
                      onCheckedChange={(v) => toggleM.mutate({ id: s.id, enabled: v })}
                    />
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={deleteM.isPending}
                      onClick={() =>
                        openConfirm({
                          title: t("logStreaming.sinks.confirmRemoveTitle"),
                          variant: "destructive",
                          confirmLabel: t("logStreaming.sinks.confirmRemoveLabel"),
                          onConfirm: () => deleteM.mutate(s.id),
                        })
                      }
                    >
                      <Trash2Icon /> {t("logStreaming.sinks.remove")}
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
          </DataState>
        </CardContent>
      </Card>
    </div>
  );
}
