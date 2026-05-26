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
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MonitorSmartphoneIcon, RefreshCwIcon, ShieldIcon } from "lucide-react";

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
  const qc = useQueryClient();

  const sessionsQ = useQuery({
    queryKey: ["sessions"],
    queryFn: () => api<{ items: Session[] }>("/v1/auth/sessions"),
  });

  const revokeM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/auth/sessions/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sessions"] }),
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Every active and revoked session for your account. Revoking a session terminates the refresh token immediately."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => sessionsQ.refetch()}
            disabled={sessionsQ.isFetching}
          >
            <RefreshCwIcon className={sessionsQ.isFetching ? "animate-spin" : ""} />
            Refresh
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Your sessions</CardTitle>
          <CardDescription>
            {sessionsQ.data?.items?.length ?? 0} session{sessionsQ.data?.items?.length === 1 ? "" : "s"}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={sessionsQ.isLoading}
            isError={sessionsQ.isError}
            error={sessionsQ.error}
            isEmpty={!sessionsQ.data?.items?.length}
            emptyIcon={ShieldIcon}
            emptyTitle="No sessions recorded."
            skeletonRows={3}
          >
            {sessionsQ.data && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User agent</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Last seen</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
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
                        onClick={() => {
                          if (confirm("Revoke this session?")) revokeM.mutate(s.id);
                        }}
                      >
                        Revoke
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
