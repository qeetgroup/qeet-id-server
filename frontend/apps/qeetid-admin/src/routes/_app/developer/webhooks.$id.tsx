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
} from "@qeetid/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { ArrowLeftIcon, PlayIcon, Trash2Icon, WebhookIcon } from "lucide-react";

import { ApiError, api } from "@/lib/api";

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
  webhook_subscription_id: string;
  event: string;
  status_code?: number | null;
  attempts: number;
  next_attempt_at?: string | null;
  delivered_at?: string | null;
  payload?: unknown;
  created_at: string;
};

function WebhookDetailPage() {
  const { id } = Route.useParams();
  const qc = useQueryClient();

  const webhookQ = useQuery({
    queryKey: ["webhook", id],
    queryFn: () => api<Webhook>(`/v1/webhooks/${id}`),
  });

  // Delivery history isn't a guaranteed-shipped endpoint yet (planned in
  // §1.5 / future webhook-history work). 404/501 graceful-degrade.
  const deliveriesQ = useQuery({
    queryKey: ["webhook-deliveries", id],
    queryFn: async (): Promise<{ items: Delivery[] }> => {
      try {
        return await api<{ items: Delivery[] }>(`/v1/webhooks/${id}/deliveries`);
      } catch (err) {
        if (err instanceof ApiError && (err.status === 404 || err.status === 501)) {
          return { items: [] };
        }
        throw err;
      }
    },
    meta: { silent: true },
    retry: false,
  });

  const testM = useMutation({
    mutationFn: () => api<void>(`/v1/webhooks/${id}/test`, { method: "POST" }),
    onSettled: () => qc.invalidateQueries({ queryKey: ["webhook-deliveries", id] }),
    meta: { successMessage: "Test event queued" },
  });

  const disableM = useMutation({
    mutationFn: () => api<void>(`/v1/webhooks/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhook", id] }),
    meta: { successMessage: "Webhook disabled" },
  });

  const w = webhookQ.data;

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <Link
        to="/developer/webhooks"
        className="inline-flex w-fit items-center gap-1 text-sm text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
      >
        <ArrowLeftIcon className="size-3" /> Back to webhooks
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
                  Subscribed to {w.events.length} event{w.events.length === 1 ? "" : "s"}.
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
                <PlayIcon /> Send test event
              </Button>
              {!w.disabled_at && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    if (confirm(`Disable webhook ${w.url}?`)) disableM.mutate();
                  }}
                  disabled={disableM.isPending}
                >
                  <Trash2Icon /> Disable
                </Button>
              )}
              <span className="ms-auto text-xs text-muted-foreground">
                Created <TimeSince value={w.created_at} />
              </span>
            </div>
          </CardContent>
        )}
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent deliveries</CardTitle>
          <CardDescription>
            Last 50 attempts. Failures are retried with exponential backoff.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={deliveriesQ.isLoading}
            isError={deliveriesQ.isError}
            error={deliveriesQ.error}
            isEmpty={!deliveriesQ.data?.items?.length}
            emptyIcon={WebhookIcon}
            emptyTitle="No deliveries yet."
            emptyDescription="When this webhook fires, attempts will appear here."
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>Event</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Attempts</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {deliveriesQ.data?.items?.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell>
                      <TimeSince value={d.created_at} className="font-mono text-xs" />
                    </TableCell>
                    <TableCell className="font-mono text-xs">{d.event}</TableCell>
                    <TableCell>
                      <StatusPill
                        kind={
                          d.delivered_at
                            ? "success"
                            : d.status_code && d.status_code >= 500
                              ? "danger"
                              : d.status_code
                                ? "warning"
                                : "muted"
                        }
                        dot
                      >
                        {d.delivered_at ? "Delivered" : `${d.status_code ?? "Pending"}`}
                      </StatusPill>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{d.attempts}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      {w && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Sample payload</CardTitle>
            <CardDescription>
              POSTed to the URL above with an HMAC-SHA256 signature in the X-Signature header.
            </CardDescription>
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
