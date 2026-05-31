import {
  Avatar,
  AvatarFallback,
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
  buttonVariants,
} from "@qeetrix/ui";
import { useQuery } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import { ArrowLeftIcon, FolderIcon, UsersIcon } from "lucide-react";

import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/groups/$groupId")({
  component: GroupDetailPage,
});

type Group = {
  id: string;
  tenant_id: string;
  parent_id?: string | null;
  name: string;
  description: string;
  created_at: string;
};

type GroupMember = {
  user_id: string;
  email: string;
  display_name?: string | null;
};

function initialsFor(s: string): string {
  const parts = s.trim().split(/\s+/);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0]!.slice(0, 2).toUpperCase();
  return (parts[0]![0]! + parts[1]![0]!).toUpperCase();
}

function GroupDetailPage() {
  const { groupId } = Route.useParams();
  const tenantId = useTenantId();

  // Same pattern as the OIDC client detail page: read the tenant list
  // and filter locally, because the backend doesn't yet ship
  // GET /v1/groups/{id}. Members come from a separate endpoint.
  const listQ = useQuery({
    queryKey: ["groups", tenantId],
    queryFn: () => api<{ items: Group[] }>(`/v1/tenants/${tenantId}/groups`),
    enabled: !!tenantId,
  });

  const membersQ = useQuery({
    queryKey: ["group-members", groupId],
    queryFn: async (): Promise<{ items: GroupMember[] }> => {
      try {
        return await api<{ items: GroupMember[] }>(`/v1/groups/${groupId}/members`);
      } catch (err) {
        // Membership table may not exist if the group was just created
        // empty; treat missing as no members rather than an error.
        if (err instanceof ApiError && err.status === 404) return { items: [] };
        throw err;
      }
    },
    meta: { silent: true },
  });

  const group = listQ.data?.items?.find((g) => g.id === groupId);
  const members = membersQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <div>
        <Link
          to="/groups"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <ArrowLeftIcon className="size-3.5" /> All groups
        </Link>
      </div>

      <DataState
        isLoading={listQ.isLoading}
        isError={listQ.isError}
        error={listQ.error}
        isEmpty={listQ.isSuccess && !group}
        emptyIcon={FolderIcon}
        emptyTitle={`No group with id "${groupId.slice(0, 8)}…" in this tenant`}
        emptyDescription={
          <>
            It may have been deleted, or you may not have permission to view it.{" "}
            <Link to="/groups" className="underline">
              Back to the list
            </Link>
            .
          </>
        }
      >
        {group && (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-xl">{group.name}</CardTitle>
                <CardDescription>
                  {group.description || (
                    <span className="italic text-muted-foreground/70">No description</span>
                  )}
                </CardDescription>
              </CardHeader>
              <CardContent className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <p className="text-xs text-muted-foreground">Members</p>
                  <p className="mt-1 text-2xl font-semibold tabular-nums">
                    {membersQ.isLoading ? "—" : members.length}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Created</p>
                  <TimeSince value={group.created_at} className="font-mono text-xs" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Metadata</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col gap-3 text-sm">
                <div>
                  <p className="text-xs text-muted-foreground">Group ID</p>
                  <p className="font-mono text-xs">{group.id}</p>
                </div>
                {group.parent_id && (
                  <div>
                    <p className="text-xs text-muted-foreground">Parent group</p>
                    <Link
                      to="/groups/$groupId"
                      params={{ groupId: group.parent_id }}
                      className="font-mono text-xs underline"
                    >
                      {group.parent_id.slice(0, 8)}…
                    </Link>
                  </div>
                )}
                <div>
                  <p className="text-xs text-muted-foreground">Tenant</p>
                  <p className="font-mono text-xs">{group.tenant_id}</p>
                </div>
              </CardContent>
            </Card>

            <Card className="lg:col-span-3">
              <CardHeader className="flex flex-row items-start justify-between gap-3">
                <div>
                  <CardTitle className="text-base">Members</CardTitle>
                  <CardDescription>Users currently belonging to this group.</CardDescription>
                </div>
                <Link
                  to="/groups"
                  className={buttonVariants({ variant: "outline", size: "sm" })}
                >
                  Manage on list
                </Link>
              </CardHeader>
              <CardContent className="p-0">
                <DataState
                  isLoading={membersQ.isLoading}
                  isError={membersQ.isError}
                  error={membersQ.error}
                  isEmpty={members.length === 0}
                  emptyIcon={UsersIcon}
                  emptyTitle="No members in this group yet."
                  skeletonRows={3}
                >
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>User</TableHead>
                        <TableHead>Email</TableHead>
                        <TableHead className="text-right">User ID</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {members.map((m) => (
                        <TableRow key={m.user_id}>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <Avatar className="size-7">
                                <AvatarFallback className="text-[10px]">
                                  {initialsFor(m.display_name || m.email)}
                                </AvatarFallback>
                              </Avatar>
                              <Link
                                to="/users/$userId"
                                params={{ userId: m.user_id }}
                                className="text-sm font-medium hover:underline"
                              >
                                {m.display_name || m.email}
                              </Link>
                            </div>
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">{m.email}</TableCell>
                          <TableCell className="text-right">
                            <span className="font-mono text-xs text-muted-foreground">
                              {m.user_id.slice(0, 8)}…
                            </span>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </DataState>
              </CardContent>
            </Card>
          </div>
        )}
      </DataState>
    </div>
  );
}
