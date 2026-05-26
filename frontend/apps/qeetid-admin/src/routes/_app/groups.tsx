import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Textarea,
  TimeSince,
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2Icon, PlusIcon, RefreshCwIcon, Trash2Icon, UserPlusIcon, UsersRoundIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/groups")({ component: GroupsPage });

type Group = {
  id: string;
  tenant_id: string;
  parent_id?: string | null;
  name: string;
  description: string;
  created_at: string;
};

type Member = { user_id: string; email?: string; display_name?: string | null };

function GroupsPage() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const groupsQ = useQuery({
    queryKey: ["groups", tenantId],
    queryFn: () => api<{ items: Group[] }>(`/v1/tenants/${tenantId}/groups`),
    enabled: !!tenantId,
  });

  const deleteM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/groups/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["groups"] }),
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Hierarchical groups inside this tenant. Use them to organise members; group-based RBAC inheritance is on the v1.0 roadmap."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => groupsQ.refetch()} disabled={groupsQ.isFetching}>
              <RefreshCwIcon className={groupsQ.isFetching ? "animate-spin" : ""} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> New group
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Groups</CardTitle>
          <CardDescription>{groupsQ.data?.items?.length ?? 0} group{groupsQ.data?.items?.length === 1 ? "" : "s"}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {groupsQ.isLoading ? (
            <div className="space-y-3 p-4">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : groupsQ.isError ? (
            <div className="p-6 text-sm text-destructive">{(groupsQ.error as Error).message}</div>
          ) : !groupsQ.data?.items?.length ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <UsersRoundIcon className="size-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">No groups yet.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Parent</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {groupsQ.data.items.map((g) => (
                  <TableRow key={g.id}>
                    <TableCell className="font-medium">{g.name}</TableCell>
                    <TableCell className="text-muted-foreground">{g.description || "—"}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {g.parent_id ? g.parent_id.slice(0, 8) + "…" : "—"}
                    </TableCell>
                    <TableCell><TimeSince value={g.created_at} /></TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="sm" onClick={() => setExpandedId(g.id)}>
                        <UserPlusIcon /> Members
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={deleteM.isPending}
                        onClick={() => {
                          if (confirm(`Delete group "${g.name}"?`)) deleteM.mutate(g.id);
                        }}
                      >
                        <Trash2Icon /> Delete
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <CreateGroupSheet
        open={creating}
        onOpenChange={setCreating}
        tenantId={tenantId}
        groups={groupsQ.data?.items ?? []}
        onCreated={() => qc.invalidateQueries({ queryKey: ["groups"] })}
      />

      {expandedId && (
        <MembersSheet
          groupId={expandedId}
          groupName={groupsQ.data?.items?.find((g) => g.id === expandedId)?.name ?? ""}
          onClose={() => setExpandedId(null)}
        />
      )}
    </div>
  );
}

type CreateGroupSheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  tenantId: string | null;
  groups: Group[];
  onCreated: () => void;
};

function CreateGroupSheet({ open, onOpenChange, tenantId, groups, onCreated }: CreateGroupSheetProps) {
  const createM = useMutation({
    mutationFn: (body: { tenant_id: string; parent_id: string | null; name: string; description: string }) =>
      api<Group>("/v1/groups", { method: "POST", body }),
    onSuccess: () => {
      onCreated();
      onOpenChange(false);
    },
  });

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <form
          className="flex h-full flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            if (!tenantId) return;
            const data = new FormData(e.currentTarget);
            const parentId = String(data.get("parent_id") ?? "");
            createM.mutate({
              tenant_id: tenantId,
              parent_id: parentId || null,
              name: String(data.get("name") ?? "").trim(),
              description: String(data.get("description") ?? "").trim(),
            });
          }}
        >
          <SheetHeader>
            <SheetTitle>New group</SheetTitle>
            <SheetDescription>Groups can be nested via the parent dropdown.</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">Name</FieldLabel>
                <Input id="name" name="name" placeholder="Engineering" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="description">Description</FieldLabel>
                <Textarea id="description" name="description" rows={3} />
              </Field>
              <Field>
                <FieldLabel htmlFor="parent_id">Parent group</FieldLabel>
                <select id="parent_id" name="parent_id" className="h-9 rounded-md border bg-background px-3 text-sm">
                  <option value="">— None (top-level)</option>
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>{g.name}</option>
                  ))}
                </select>
              </Field>
              {createM.error && <Field><FieldError>{(createM.error as ApiError).message}</FieldError></Field>}
            </FieldGroup>
          </div>
          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>Cancel</SheetClose>
            <Button type="submit" disabled={createM.isPending}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? "Creating…" : "Create"}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}

type MembersSheetProps = { groupId: string; groupName: string; onClose: () => void };

function MembersSheet({ groupId, groupName, onClose }: MembersSheetProps) {
  const qc = useQueryClient();
  const [newMemberId, setNewMemberId] = useState("");

  const membersQ = useQuery({
    queryKey: ["group-members", groupId],
    queryFn: () => api<{ items: Member[] }>(`/v1/groups/${groupId}/members`),
  });

  const addM = useMutation({
    mutationFn: (userId: string) =>
      api<void>(`/v1/groups/${groupId}/members/${userId}`, { method: "POST" }),
    onSuccess: () => {
      setNewMemberId("");
      qc.invalidateQueries({ queryKey: ["group-members", groupId] });
    },
  });

  const removeM = useMutation({
    mutationFn: (userId: string) =>
      api<void>(`/v1/groups/${groupId}/members/${userId}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["group-members", groupId] }),
  });

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <SheetHeader>
          <SheetTitle>Members — {groupName}</SheetTitle>
          <SheetDescription>Add and remove users in this group. Paste a user UUID to add.</SheetDescription>
        </SheetHeader>
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <div className="flex gap-2">
            <Input
              placeholder="user UUID"
              value={newMemberId}
              onChange={(e) => setNewMemberId(e.target.value)}
            />
            <Button
              onClick={() => addM.mutate(newMemberId.trim())}
              disabled={!newMemberId.trim() || addM.isPending}
            >
              {addM.isPending ? <Loader2Icon className="animate-spin" /> : "Add"}
            </Button>
          </div>
          {addM.error && <FieldError>{(addM.error as ApiError).message}</FieldError>}

          {membersQ.isLoading ? (
            [...Array(3)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)
          ) : !membersQ.data?.items?.length ? (
            <p className="text-sm text-muted-foreground text-center py-6">No members yet.</p>
          ) : (
            membersQ.data.items.map((m) => (
              <div key={m.user_id} className="flex items-center justify-between rounded-md border p-3 text-sm">
                <div className="min-w-0">
                  <div className="font-medium truncate">{m.display_name ?? m.email ?? m.user_id}</div>
                  <code className="text-xs text-muted-foreground">{m.user_id.slice(0, 16)}…</code>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => removeM.mutate(m.user_id)}
                  disabled={removeM.isPending}
                >
                  <Trash2Icon />
                </Button>
              </div>
            ))
          )}
        </div>
        <SheetFooter className="flex-row justify-end gap-2 border-t">
          <Button variant="outline" onClick={onClose}>Close</Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
