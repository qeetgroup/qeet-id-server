import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { RotateCcwIcon, Trash2Icon, UserMinusIcon } from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/users/deleted")({ component: DeletedUsersPage });

type DeletedUser = {
  id: string;
  email: string;
  display_name: string | null;
  deleted_at: string;
  created_at: string;
};

function DeletedUsersPage() {
  const tenantId = useTenantId();
  const qc = useQueryClient();

  const listQ = useQuery({
    queryKey: ["users", "deleted", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<{ items: DeletedUser[] }>("/v1/users/deleted"),
  });

  const restoreM = useMutation({
    mutationFn: (id: string) => api(`/v1/users/${id}/restore`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
    meta: { successMessage: "User restored" },
  });

  const purgeM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/users/${id}/purge`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users", "deleted"] }),
    meta: { successMessage: "User permanently deleted" },
  });

  const items = listQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="Soft-deleted users. Restore brings an account back; permanent deletion removes it and its sessions for good." />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Soft-deleted</CardDescription>
            <UserMinusIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">{items.length}</div>
            <p className="text-xs text-muted-foreground">Recoverable until permanently deleted</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recycle bin</CardTitle>
          <CardDescription>Accounts removed from this tenant.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={items.length === 0}
            emptyIcon={UserMinusIcon}
            emptyTitle="No deleted users."
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Deleted</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((u) => (
                  <TableRow key={u.id}>
                    <TableCell>
                      <div className="font-medium">{u.display_name || u.email}</div>
                      {u.display_name && <div className="text-xs text-muted-foreground">{u.email}</div>}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <TimeSince value={u.deleted_at} />
                    </TableCell>
                    <TableCell className="text-right whitespace-nowrap">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => restoreM.mutate(u.id)}
                        disabled={restoreM.isPending}
                      >
                        <RotateCcwIcon /> Restore
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          if (
                            confirm(
                              `Permanently delete ${u.email}? This removes the account and its sessions and cannot be undone.`,
                            )
                          ) {
                            purgeM.mutate(u.id);
                          }
                        }}
                        disabled={purgeM.isPending}
                      >
                        <Trash2Icon /> Delete forever
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>
    </div>
  );
}
