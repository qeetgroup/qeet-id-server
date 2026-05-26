import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
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
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, MailIcon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/invitations")({ component: InvitationsPage });

type Invite = {
  id: string;
  tenant_id: string;
  email: string;
  role_id?: string | null;
  status: "pending" | "accepted" | "expired" | "revoked";
  expires_at: string;
  accepted_at?: string | null;
  created_at: string;
};

type Role = { id: string; name: string };

function InvitationsPage() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);

  const listQ = useQuery({
    queryKey: ["invites", tenantId],
    queryFn: () => api<{ items: Invite[] }>(`/v1/tenants/${tenantId}/invites`),
    enabled: !!tenantId,
  });

  const rolesQ = useQuery({
    queryKey: ["roles", tenantId],
    queryFn: () => api<{ items: Role[] }>(`/v1/tenants/${tenantId}/roles`),
    enabled: !!tenantId,
  });

  const revokeM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/invites/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["invites"] }),
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Invite teammates by email. They get a one-time link that creates their account and assigns the chosen role on acceptance."
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => listQ.refetch()}
              disabled={listQ.isFetching}
            >
              <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> Send invite
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Invitations</CardTitle>
          <CardDescription>
            {listQ.data?.items?.length ?? 0} invitation{listQ.data?.items?.length === 1 ? "" : "s"}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {listQ.isLoading ? (
            <div className="space-y-3 p-4">
              {[...Array(3)].map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : listQ.isError ? (
            <div className="p-6 text-sm text-destructive">{(listQ.error as Error).message}</div>
          ) : !listQ.data?.items?.length ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <MailIcon className="size-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">No invitations sent yet.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Email</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Sent</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listQ.data.items.map((i) => {
                  const roleName = rolesQ.data?.items.find((r) => r.id === i.role_id)?.name ?? "—";
                  return (
                    <TableRow key={i.id}>
                      <TableCell className="font-medium">{i.email}</TableCell>
                      <TableCell>
                        <Badge variant="muted">{roleName}</Badge>
                      </TableCell>
                      <TableCell>
                        <StatusPill status={i.status} />
                      </TableCell>
                      <TableCell>
                        <TimeSince value={i.expires_at} />
                      </TableCell>
                      <TableCell>
                        <TimeSince value={i.created_at} />
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={i.status !== "pending" || revokeM.isPending}
                          onClick={() => {
                            if (confirm(`Revoke invitation for ${i.email}?`)) revokeM.mutate(i.id);
                          }}
                        >
                          <Trash2Icon /> Revoke
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <CreateInviteSheet
        open={creating}
        onOpenChange={setCreating}
        tenantId={tenantId}
        roles={rolesQ.data?.items ?? []}
        onCreated={() => qc.invalidateQueries({ queryKey: ["invites"] })}
      />
    </div>
  );
}

type CreateInviteSheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  tenantId: string | null;
  roles: Role[];
  onCreated: () => void;
};

function CreateInviteSheet({
  open,
  onOpenChange,
  tenantId,
  roles,
  onCreated,
}: CreateInviteSheetProps) {
  const [roleId, setRoleId] = useState<string>("");
  const createM = useMutation({
    mutationFn: (body: { tenant_id: string; email: string; role_id?: string }) =>
      api<Invite>("/v1/invites", { method: "POST", body }),
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
            createM.mutate({
              tenant_id: tenantId,
              email: String(data.get("email") ?? "").trim(),
              role_id: roleId || undefined,
            });
          }}
        >
          <SheetHeader>
            <SheetTitle>Send invitation</SheetTitle>
            <SheetDescription>
              The invitee gets an email with a one-time link. They set their password during
              acceptance.
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="email">Email</FieldLabel>
                <Input id="email" name="email" type="email" required />
              </Field>
              <Field>
                <FieldLabel>Role</FieldLabel>
                <Select value={roleId} onValueChange={setRoleId}>
                  <SelectTrigger>
                    <SelectValue placeholder="No role (basic member)" />
                  </SelectTrigger>
                  <SelectContent>
                    {roles.map((r) => (
                      <SelectItem key={r.id} value={r.id}>
                        {r.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FieldDescription>
                  Assigned automatically when the invite is accepted.
                </FieldDescription>
              </Field>
              {createM.error && (
                <Field>
                  <FieldError>{(createM.error as ApiError).message}</FieldError>
                </Field>
              )}
            </FieldGroup>
          </div>
          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>Cancel</SheetClose>
            <Button type="submit" disabled={createM.isPending}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? "Sending…" : "Send invite"}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
