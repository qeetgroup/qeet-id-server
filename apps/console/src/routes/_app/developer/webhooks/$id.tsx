import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CodeBlock,
  DataState,
  Skeleton,
  StatusPill,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import {
  ArrowLeftIcon,
  ChevronDownIcon,
  PlayIcon,
  RotateCwIcon,
  Trash2Icon,
  WebhookIcon,
} from "lucide-react";
import { Fragment, useState } from "react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { api } from "@/lib/api";

export const Route = createFileRoute("/_app/developer/webhooks/$id")({
  component: WebhookDetailPage,
});

type Webhook = {
  id: string;
  tenant_id: string;
  url: string;
  events: string[];
  disabled_at?: string | null;
  created_at: string;
};

type Delivery = {
  id: string;
  event_type: string;
  attempt: number;
  status_code?: number | null;
  error?: string | null;
  payload: string;
  response_body?: string | null;
  next_attempt_at?: string | null;
  delivered_at?: string | null;
  dead_at?: string | null;
  created_at: string;
};

function WebhookDetailPage() {
  const { t } = useTranslation("developer");
  const { id } = Route.useParams();
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState<string | null>(null);
  const [confirmDialog, openConfirm] = useConfirmDialog();

  const webhookQ = useQuery({
    queryKey: ["webhook", id],
    queryFn: () => api<Webhook>(`/v1/webhooks/${id}`),
  });

  const deliveriesQ = useQuery({
    queryKey: ["webhook-deliveries", id],
    queryFn: () => api<{ items: Delivery[] }>(`/v1/webhooks/${id}/deliveries`),
    meta: { silent: true },
    retry: false,
  });

  const testM = useMutation({
    mutationFn: () => api<void>(`/v1/webhooks/${id}/test`, { method: "POST" }),
    onSettled: () => qc.invalidateQueries({ queryKey: ["webhook-deliveries", id] }),
    meta: { successMessage: t("webhooks.toast.testQueued") },
  });

  const retryM = useMutation({
    mutationFn: (deliveryId: string) =>
      api<void>(`/v1/webhooks/${id}/deliveries/${deliveryId}/retry`, { method: "POST" }),
    onSettled: () => qc.invalidateQueries({ queryKey: ["webhook-deliveries", id] }),
    meta: { successMessage: "Delivery re-queued" },
  });

  const disableM = useMutation({
    mutationFn: () => api<void>(`/v1/webhooks/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhook", id] }),
    meta: { successMessage: t("webhooks.toast.disabled") },
  });

  const w = webhookQ.data;

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {confirmDialog}
      <Link
        to="/developer/webhooks"
        className="inline-flex w-fit items-center gap-1 text-sm text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
      >
        <ArrowLeftIcon className="size-3" /> {t("webhookDetail.back")}
      </Link>

      <Card>
        <CardHeader>
          {webhookQ.isLoading ? (
            <>
              <Skeleton className="h-5 w-64" />
              <Skeleton className="mt-2 h-4 w-48" />
            </>
          ) : webhookQ.isError ? (
            <CardTitle className="text-base text-destructive">
              {(webhookQ.error as Error).message}
            </CardTitle>
          ) : w ? (
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <CardTitle className="flex items-center gap-2 text-base">
                  <WebhookIcon className="size-4 text-muted-foreground" />
                  <span className="break-all font-mono text-sm">{w.url}</span>
                </CardTitle>
                <CardDescription>
                  {t("webhookDetail.subscribedCount", { count: w.events.length })}
                </CardDescription>
              </div>
              <StatusPill status={w.disabled_at ? "disabled" : "active"} />
            </div>
          ) : null}
        </CardHeader>
        {w && (
          <CardContent className="flex flex-col gap-3">
            <div className="flex flex-wrap gap-1">
              {w.events.map((e) => (
                <Badge key={e} variant="muted" className="font-mono text-[10px]">
                  {e}
                </Badge>
              ))}
            </div>
            <div className="flex flex-wrap items-center gap-2 border-t pt-3">
              <Button
                size="sm"
                variant="outline"
                onClick={() => testM.mutate()}
                disabled={testM.isPending || !!w.disabled_at}
              >
                <PlayIcon /> {t("webhookDetail.testEvent")}
              </Button>
              {!w.disabled_at && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() =>
                    openConfirm({
                      title: t("webhookDetail.confirm.disableTitle"),
                      description: t("webhooks.confirm.disableDescription", { url: w.url }),
                      variant: "destructive",
                      confirmLabel: t("webhookDetail.confirm.disableLabel"),
                      onConfirm: () => disableM.mutate(),
                    })
                  }
                  disabled={disableM.isPending}
                >
                  <Trash2Icon /> {t("webhookDetail.disable")}
                </Button>
              )}
              <span className="ms-auto text-xs text-muted-foreground">
                {t("webhookDetail.created")} <TimeSince value={w.created_at} />
              </span>
            </div>
          </CardContent>
        )}
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("webhookDetail.deliveries.title")}</CardTitle>
          <CardDescription>{t("webhookDetail.deliveries.description")}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={deliveriesQ.isLoading}
            isError={deliveriesQ.isError}
            error={deliveriesQ.error}
            isEmpty={!deliveriesQ.data?.items?.length}
            emptyIcon={WebhookIcon}
            emptyTitle={t("webhookDetail.deliveries.empty")}
            emptyDescription={t("webhookDetail.deliveries.emptyDescription")}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>{t("webhookDetail.deliveries.columns.when")}</TableHead>
                  <TableHead>{t("webhookDetail.deliveries.columns.event")}</TableHead>
                  <TableHead>{t("webhookDetail.deliveries.columns.status")}</TableHead>
                  <TableHead>{t("webhookDetail.deliveries.columns.attempts")}</TableHead>
                  <TableHead className="text-right">
                    {t("webhookDetail.deliveries.columns.actions")}
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {deliveriesQ.data?.items?.map((d) => (
                  <Fragment key={d.id}>
                    <TableRow>
                      <TableCell>
                        <button
                          type="button"
                          aria-label={
                            expanded === d.id
                              ? t("webhookDetail.deliveries.collapse")
                              : t("webhookDetail.deliveries.expand")
                          }
                          className="text-muted-foreground hover:text-foreground"
                          onClick={() => setExpanded(expanded === d.id ? null : d.id)}
                        >
                          <ChevronDownIcon
                            className={`size-4 transition-transform ${expanded === d.id ? "rotate-180" : ""}`}
                          />
                        </button>
                      </TableCell>
                      <TableCell>
                        <TimeSince value={d.created_at} className="font-mono text-xs" />
                      </TableCell>
                      <TableCell className="font-mono text-xs">{d.event_type}</TableCell>
                      <TableCell>
                        <StatusPill
                          kind={
                            d.delivered_at
                              ? "success"
                              : d.dead_at
                                ? "danger"
                                : d.status_code && d.status_code >= 500
                                  ? "danger"
                                  : d.status_code
                                    ? "warning"
                                    : "muted"
                          }
                          dot
                        >
                          {d.delivered_at
                            ? t("webhookDetail.deliveries.statusDelivered")
                            : d.dead_at
                              ? t("webhookDetail.deliveries.statusDead")
                              : `${d.status_code ?? t("webhookDetail.deliveries.statusPending")}`}
                        </StatusPill>
                      </TableCell>
                      <TableCell className="text-muted-foreground">{d.attempt}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => retryM.mutate(d.id)}
                          disabled={retryM.isPending}
                        >
                          <RotateCwIcon /> {t("webhookDetail.deliveries.retry")}
                        </Button>
                      </TableCell>
                    </TableRow>
                    {expanded === d.id && (
                      <TableRow key={`${d.id}-detail`}>
                        <TableCell colSpan={6} className="bg-muted/30">
                          <div className="flex flex-col gap-3 py-2">
                            {d.error && <p className="text-destructive text-xs">{d.error}</p>}
                            <div>
                              <p className="mb-1 text-xs font-medium text-muted-foreground">
                                {t("webhookDetail.deliveries.requestPayload")}
                              </p>
                              <CodeBlock language="json" value={d.payload} />
                            </div>
                            {d.response_body && (
                              <div>
                                <p className="mb-1 text-xs font-medium text-muted-foreground">
                                  {t("webhookDetail.deliveries.responseBody")}
                                </p>
                                <CodeBlock language="text" value={d.response_body} />
                              </div>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      {w && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("webhookDetail.sample.title")}</CardTitle>
            <CardDescription>{t("webhookDetail.sample.description")}</CardDescription>
          </CardHeader>
          <CardContent>
            <CodeBlock
              language="json"
              lineNumbers
              value={JSON.stringify(
                {
                  id: "evt_example",
                  event: w.events[0] ?? "user.created",
                  tenant_id: w.tenant_id,
                  data: {
                    /* event-specific payload */
                  },
                  created_at: new Date().toISOString(),
                },
                null,
                2,
              )}
            />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
