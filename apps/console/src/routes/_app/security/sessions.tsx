import {
  Button,
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
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MonitorSmartphoneIcon, RefreshCwIcon, ShieldIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/api";

export const Route = createFileRoute("/_app/security/sessions")({ component: SessionsPage });

type Session = {
  id: string;
  user_id: string;
  tenant_id: string;
  ip?: string | null;
  user_agent?: string | null;
  created_at: string;
  last_seen_at: string;
  revoked_at?: string | null;
};

function SessionsPage() {
  const { t } = useTranslation("security");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const qc = useQueryClient();

  const sessionsQ = useQuery({
    queryKey: ["sessions"],
    queryFn: () => api<{ items: Session[] }>("/v1/auth/sessions"),
  });

  const revokeM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/auth/sessions/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sessions"] }),
  });

  const itemCount = sessionsQ.data?.items?.length ?? 0;

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {confirmDialog}
      <PageHeader
        description={t("sessions.description")}
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => sessionsQ.refetch()}
            disabled={sessionsQ.isFetching}
          >
            <RefreshCwIcon className={sessionsQ.isFetching ? "animate-spin" : ""} />
            {t("sessions.refresh")}
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("sessions.list.title")}</CardTitle>
          <CardDescription>
            {t("sessions.list.count", { count: itemCount })}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={sessionsQ.isLoading}
            isError={sessionsQ.isError}
            error={sessionsQ.error}
            isEmpty={!sessionsQ.data?.items?.length}
            emptyIcon={ShieldIcon}
            emptyTitle={t("sessions.list.empty")}
            skeletonRows={3}
          >
            {sessionsQ.data && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("sessions.list.columns.userAgent")}</TableHead>
                  <TableHead>{t("sessions.list.columns.ip")}</TableHead>
                  <TableHead>{t("sessions.list.columns.created")}</TableHead>
                  <TableHead>{t("sessions.list.columns.lastSeen")}</TableHead>
                  <TableHead>{t("sessions.list.columns.status")}</TableHead>
                  <TableHead className="text-right">{t("sessions.list.columns.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessionsQ.data.items.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className="max-w-md truncate text-xs text-muted-foreground" title={s.user_agent ?? ""}>
                      <MonitorSmartphoneIcon className="mr-1 inline size-3" />
                      {s.user_agent ?? "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{s.ip ?? "—"}</TableCell>
                    <TableCell>
                      <TimeSince value={s.created_at} />
                    </TableCell>
                    <TableCell>
                      <TimeSince value={s.last_seen_at} />
                    </TableCell>
                    <TableCell>
                      <StatusPill status={s.revoked_at ? "revoked" : "active"} />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={!!s.revoked_at || revokeM.isPending}
                        onClick={() =>
                          openConfirm({
                            title: t("sessions.confirm.revokeTitle"),
                            variant: "destructive",
                            confirmLabel: t("sessions.confirm.revokeLabel"),
                            onConfirm: () => revokeM.mutate(s.id),
                          })
                        }
                      >
                        {t("sessions.list.revoke")}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            )}
          </DataState>
        </CardContent>
      </Card>
    </div>
  );
}
