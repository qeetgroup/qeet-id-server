import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
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
          {sessionsQ.isLoading ? (
            <div className="space-y-3 p-4">
              {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
            </div>
          ) : sessionsQ.isError ? (
            <div className="p-6 text-sm text-destructive">{(sessionsQ.error as Error).message}</div>
          ) : !sessionsQ.data?.items?.length ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <ShieldIcon className="size-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">No sessions recorded.</p>
            </div>
          ) : (
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
                    <TableCell className="text-muted-foreground">
                      {new Date(s.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(s.last_seen_at).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      {s.revoked_at ? <Badge variant="destructive">Revoked</Badge> : <Badge variant="success">Active</Badge>}
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
        </CardContent>
      </Card>
    </div>
  );
}
