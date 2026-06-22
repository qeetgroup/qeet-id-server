import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
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
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, MailIcon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { useEffect, useState } from "react";

import { ListToolbar, SortHeader } from "@/components/data-table";
import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";
import { exportToCsv, exportToJson, type CsvColumn } from "@/lib/export";
import { useListView } from "@/lib/list-view";

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
    meta: { successMessage: "Invitation revoked" },
  });

  const roleName = (id?: string | null) =>
    rolesQ.data?.items.find((r) => r.id === id)?.name ?? "—";

  const items = listQ.data?.items ?? [];
  const lv = useListView(items, {
    searchFields: (i) => [i.email, roleName(i.role_id)],
    filterFields: { status: (i) => i.status },
    sortFields: { email: (i) => i.email, expires: (i) => i.expires_at, sent: (i) => i.created_at },
  });
  const rows = lv.view;
  const denseCls = lv.density === "compact" ? "[&_td]:py-1.5 [&_th]:py-2" : undefined;

  const inviteCsvColumns: CsvColumn<Invite>[] = [
    { header: "id", value: (i) => i.id },
    { header: "email", value: (i) => i.email },
    { header: "role", value: (i) => roleName(i.role_id) },
    { header: "status", value: (i) => i.status },
    { header: "expires_at", value: (i) => i.expires_at },
    { header: "created_at", value: (i) => i.created_at },
  ];

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
            {rows.length} of {items.length} invitation{items.length === 1 ? "" : "s"}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <ListToolbar
            search={lv.search}
            onSearchChange={lv.setSearch}
            searchPlaceholder="Search email or role…"
            filters={[
              {
                id: "status",
                label: "Status",
                value: lv.filters.status ?? "",
                options: [
                  { label: "Pending", value: "pending" },
                  { label: "Accepted", value: "accepted" },
                  { label: "Expired", value: "expired" },
                  { label: "Revoked", value: "revoked" },
                ],
                onChange: (v) => lv.setFilter("status", v),
              },
            ]}
            columns={[
              { id: "role", label: "Role" },
              { id: "expires", label: "Expires" },
              { id: "sent", label: "Sent" },
            ]}
            isColumnVisible={lv.isVisible}
            onToggleColumn={lv.toggleColumn}
            density={lv.density}
            onDensityChange={lv.setDensity}
            onExport={(fmt) =>
              fmt === "csv"
                ? exportToCsv("invitations", rows, inviteCsvColumns)
                : exportToJson("invitations", rows)
            }
            exportDisabled={rows.length === 0}
            hasActiveFilters={lv.hasActiveFilters}
            onClear={lv.clear}
          />
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={rows.length === 0}
            emptyIcon={MailIcon}
            emptyTitle={
              lv.hasActiveFilters ? "No invitations match your filters." : "No invitations sent yet."
            }
            skeletonRows={3}
          >
            <Table className={denseCls}>
              <TableHeader>
                <TableRow>
                  <SortHeader columnKey="email" sort={lv.sort} onToggle={lv.toggleSort}>
                    Email
                  </SortHeader>
                  {lv.isVisible("role") && <TableHead>Role</TableHead>}
                  <TableHead>Status</TableHead>
                  {lv.isVisible("expires") && (
                    <SortHeader columnKey="expires" sort={lv.sort} onToggle={lv.toggleSort}>
                      Expires
                    </SortHeader>
                  )}
                  {lv.isVisible("sent") && (
                    <SortHeader columnKey="sent" sort={lv.sort} onToggle={lv.toggleSort}>
                      Sent
                    </SortHeader>
                  )}
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((i) => (
                  <TableRow key={i.id}>
                    <TableCell className="font-medium">{i.email}</TableCell>
                    {lv.isVisible("role") && (
                      <TableCell>
                        <Badge variant="muted">{roleName(i.role_id)}</Badge>
                      </TableCell>
                    )}
                    <TableCell>
                      <StatusPill status={i.status} />
                    </TableCell>
                    {lv.isVisible("expires") && (
                      <TableCell>
                        <TimeSince value={i.expires_at} />
                      </TableCell>
                    )}
                    {lv.isVisible("sent") && (
                      <TableCell>
                        <TimeSince value={i.created_at} />
                      </TableCell>
                    )}
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
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      <CreateInviteSheet
        open={creating}
        onOpenChange={setCreating}
        currentTenantId={tenantId}
        onCreated={() => qc.invalidateQueries({ queryKey: ["invites"] })}
      />
    </div>
  );
}

type CreateInviteSheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  currentTenantId: string | null;
  onCreated: () => void;
};

function CreateInviteSheet({
  open,
  onOpenChange,
  currentTenantId,
  onCreated,
}: CreateInviteSheetProps) {
  // Which workspace the invitee joins. Defaults to the current one; admins who
  // belong to several can target another. Roles are tenant-scoped, so the role
  // list (and its default) follow this selection.
  const [tenantId, setTenantId] = useState<string>(currentTenantId ?? "");
  const [roleId, setRoleId] = useState<string>("");

  useEffect(() => {
    if (open) setTenantId(currentTenantId ?? "");
  }, [open, currentTenantId]);

  // Workspaces the caller belongs to (scoped server-side).
  const tenantsQ = useQuery({
    queryKey: ["tenants", "invite-picker"],
    queryFn: () => api<{ items: { id: string; name: string }[] }>("/v1/tenants"),
    enabled: open,
  });
  const tenants = tenantsQ.data?.items ?? [];

  const rolesQ = useQuery({
    queryKey: ["roles", tenantId],
    queryFn: () => api<{ items: Role[] }>(`/v1/tenants/${tenantId}/roles`),
    enabled: open && !!tenantId,
  });
  const roles = rolesQ.data?.items ?? [];

  // Default to a "member"-type role for the selected workspace so the accepted
  // user becomes a visible member (the members list is role-based).
  useEffect(() => {
    const rs = rolesQ.data?.items ?? [];
    if (rs.length === 0) {
      setRoleId("");
      return;
    }
    const member = rs.find((r) => /member/i.test(r.name));
    setRoleId(member?.id ?? rs[rs.length - 1]!.id);
  }, [rolesQ.data]);

  const createM = useMutation({
    mutationFn: (body: { tenant_id: string; email: string; role_id?: string }) =>
      api<Invite>("/v1/invites", { method: "POST", body }),
    onSuccess: () => {
      onCreated();
      onOpenChange(false);
    },
    meta: { successMessage: "Invitation sent" },
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
                <FieldLabel>Workspace</FieldLabel>
                <Select value={tenantId} onValueChange={(v) => v && setTenantId(v)}>
                  <SelectTrigger>
                    <SelectValue
                      placeholder={tenantsQ.isLoading ? "Loading workspaces…" : "Select a workspace"}
                    />
                  </SelectTrigger>
                  <SelectContent>
                    {tenants.map((tn) => (
                      <SelectItem key={tn.id} value={tn.id}>
                        {tn.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FieldDescription>The workspace the invitee will join.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel>Role</FieldLabel>
                <Select value={roleId} onValueChange={(v) => v && setRoleId(v)}>
                  <SelectTrigger>
                    <SelectValue
                      placeholder={rolesQ.isLoading ? "Loading roles…" : "Select a role"}
                    />
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
                  Granted on acceptance — required for the user to become a member.
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
            <Button type="submit" disabled={createM.isPending || !tenantId}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? "Sending…" : "Send invite"}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
