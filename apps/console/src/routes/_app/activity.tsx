import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  StatusPill,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
  cn,
} from "@qeetrix/ui";
import { Link, createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ActivityIcon, RadioIcon } from "lucide-react";
import { useMemo, useRef } from "react";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/activity")({ component: ActivityPage });

type AuditEvent = {
  id: string;
  actor_user_id?: string | null;
  actor_type: string;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  ip?: string | null;
  created_at: string;
};

function ActivityPage() {
  const { t } = useTranslation("security");
  const tenantId = useTenantId();
  const eventsQ = useQuery({
    queryKey: ["activity-recent", tenantId],
    queryFn: () =>
      api<{ items: AuditEvent[] }>(`/v1/tenants/${tenantId}/audit`, { query: { limit: 20 } }),
    enabled: !!tenantId,
    refetchInterval: 15_000,
    refetchIntervalInBackground: false,
  });

  // Track the highest `created_at` seen on the very first successful
  // fetch of this page lifecycle. Anything newer that streams in via
  // the refetchInterval is marked as "NEW" so the user can spot it at
  // a glance. The ref intentionally only writes once — refreshing the
  // browser is the way to reset.
  const seenSinceRef = useRef<string | null>(null);
  // Backend may return `{ items: null }` for empty result sets (Go nil
  // slice → JSON null); coerce before indexing so we don't crash on
  // null[0]. Memoized so the identity is stable across renders (avoids
  // `useMemo` dep churn below).
  const items = useMemo(() => eventsQ.data?.items ?? [], [eventsQ.data?.items]);
  if (eventsQ.data && seenSinceRef.current === null) {
    const newest = items[0]?.created_at;
    if (newest) seenSinceRef.current = newest;
  }
  const seenSince = seenSinceRef.current;
  const newCount = useMemo(
    () => items.filter((e) => seenSince && e.created_at > seenSince).length,
    [items, seenSince],
  );

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description={t("activity.description")} />

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              {t("activity.cardTitle")}
              <span
                className={cn(
                  "inline-flex items-center gap-1 rounded-full border px-1.5 py-px text-[10px] font-medium",
                  eventsQ.isFetching
                    ? "border-emerald-500/40 text-emerald-700 dark:text-emerald-400"
                    : "border-muted-foreground/40 text-muted-foreground",
                )}
                title={eventsQ.isFetching ? t("activity.titleRefreshing") : t("activity.titleIdle")}
              >
                <RadioIcon
                  className={cn(
                    "size-3",
                    eventsQ.isFetching && "animate-pulse text-emerald-500",
                  )}
                />
                {t("activity.liveBadge")}
              </span>
            </CardTitle>
            <CardDescription>
              For deep search and export, see{" "}
              <Link to="/security/audit-logs" className="underline">Audit Logs</Link>.
            </CardDescription>
          </div>
          {newCount > 0 && (
            <StatusPill kind="success" dot={false}>
              {t("activity.newSince", { count: newCount })}
            </StatusPill>
          )}
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={eventsQ.isLoading}
            isError={eventsQ.isError}
            error={eventsQ.error}
            isEmpty={!items.length}
            emptyIcon={ActivityIcon}
            emptyTitle={t("activity.empty")}
            skeletonRows={5}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("activity.colWhen")}</TableHead>
                  <TableHead>{t("activity.colActor")}</TableHead>
                  <TableHead>{t("activity.colAction")}</TableHead>
                  <TableHead>{t("activity.colResource")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((e) => {
                  const isNew = !!seenSince && e.created_at > seenSince;
                  return (
                    <TableRow
                      key={e.id}
                      className={cn(
                        "transition-colors",
                        isNew && "bg-emerald-50/40 dark:bg-emerald-950/15",
                      )}
                    >
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <TimeSince value={e.created_at} className="font-mono text-xs" />
                          {isNew && (
                            <StatusPill kind="success" dot={false} className="text-[10px]">
                              {t("activity.newBadge")}
                            </StatusPill>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="muted">{e.actor_type}</Badge>
                      </TableCell>
                      <TableCell className="font-medium">{e.action}</TableCell>
                      <TableCell className="text-muted-foreground">
                        {e.resource_type}
                        {e.resource_id && (
                          <span className="ml-1 font-mono text-xs">
                            ({e.resource_id.slice(0, 8)}…)
                          </span>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>
    </div>
  );
}
