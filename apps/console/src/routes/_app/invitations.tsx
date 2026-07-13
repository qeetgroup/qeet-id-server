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
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
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
  const { t } = useTranslation("invitations");
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [confirmDialog, openConfirm] = useConfirmDialog();

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
    meta: { successMessage: t("toast.revoked") },
  });

  const roleName = (id?: string | null) =>
    rolesQ.data?.items.find((r) => r.id === id)?.name ?? "—";

  const items = listQ.data?.items ?? [];
  const lv = useListView(items, {
    searchFields: (inv) => [inv.email, roleName(inv.role_id)],
    filterFields: { status: (inv) => inv.status },
    sortFields: {
      email: (inv) => inv.email,
      expires: (inv) => inv.expires_at,
      sent: (inv) => inv.created_at,
    },
  });
  const rows = lv.view;
  const denseCls = lv.density === "compact" ? "[&_td]:py-1.5 [&_th]:py-2" : undefined;

  const inviteCsvColumns: CsvColumn<Invite>[] = [
    { header: "id", value: (inv) => inv.id },
    { header: "email", value: (inv) => inv.email },
    { header: "role", value: (inv) => roleName(inv.role_id) },
    { header: "status", value: (inv) => inv.status },
    { header: "expires_at", value: (inv) => inv.expires_at },
    { header: "created_at", value: (inv) => inv.created_at },
  ];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {confirmDialog}
      <PageHeader
        description={t("list.description")}
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => listQ.refetch()}
              disabled={listQ.isFetching}
            >
              <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
              {t("list.refresh")}
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> {t("list.send")}
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("list.title")}</CardTitle>
          <CardDescription>
            {t("list.count", { shown: rows.length, total: items.length })}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <ListToolbar
            search={lv.search}
            onSearchChange={lv.setSearch}
            searchPlaceholder={t("list.searchPlaceholder")}
            filters={[
              {
                id: "status",
                label: t("list.filters.status.label"),
                value: lv.filters.status ?? "",
                options: [
                  { label: t("list.filters.status.pending"), value: "pending" },
                  { label: t("list.filters.status.accepted"), value: "accepted" },
                  { label: t("list.filters.status.expired"), value: "expired" },
                  { label: t("list.filters.status.revoked"), value: "revoked" },
                ],
                onChange: (v) => lv.setFilter("status", v),
              },
            ]}
            columns={[
              { id: "role", label: t("list.columns.role") },
              { id: "expires", label: t("list.columns.expires") },
              { id: "sent", label: t("list.columns.sent") },
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
              lv.hasActiveFilters ? t("list.emptyFiltered") : t("list.empty")
            }
            skeletonRows={3}
          >
            <Table className={denseCls}>
              <TableHeader>
                <TableRow>
                  <SortHeader columnKey="email" sort={lv.sort} onToggle={lv.toggleSort}>
                    {t("list.columns.email")}
                  </SortHeader>
                  {lv.isVisible("role") && <TableHead>{t("list.columns.role")}</TableHead>}
                  <TableHead>{t("list.columns.status")}</TableHead>
                  {lv.isVisible("expires") && (
                    <SortHeader columnKey="expires" sort={lv.sort} onToggle={lv.toggleSort}>
                      {t("list.columns.expires")}
                    </SortHeader>
                  )}
                  {lv.isVisible("sent") && (
                    <SortHeader columnKey="sent" sort={lv.sort} onToggle={lv.toggleSort}>
                      {t("list.columns.sent")}
                    </SortHeader>
                  )}
                  <TableHead className="text-right">{t("list.columns.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((inv) => (
                  <TableRow key={inv.id}>
                    <TableCell className="font-medium">{inv.email}</TableCell>
                    {lv.isVisible("role") && (
                      <TableCell>
                        <Badge variant="muted">{roleName(inv.role_id)}</Badge>
                      </TableCell>
                    )}
                    <TableCell>
                      <StatusPill status={inv.status} />
                    </TableCell>
                    {lv.isVisible("expires") && (
                      <TableCell>
                        <TimeSince value={inv.expires_at} />
                      </TableCell>
                    )}
                    {lv.isVisible("sent") && (
                      <TableCell>
                        <TimeSince value={inv.created_at} />
                      </TableCell>
                    )}
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={inv.status !== "pending" || revokeM.isPending}
                        onClick={() =>
                          openConfirm({
                            title: t("confirm.revokeTitle", { email: inv.email }),
                            variant: "destructive",
                            confirmLabel: t("confirm.revokeLabel"),
                            onConfirm: () => revokeM.mutate(inv.id),
                          })
                        }
                      >
                        <Trash2Icon /> {t("table.revoke")}
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
  const { t } = useTranslation("invitations");

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
    meta: { successMessage: t("toast.sent") },
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
            <SheetTitle>{t("create.title")}</SheetTitle>
            <SheetDescription>{t("create.description")}</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="invite-email">{t("create.email")}</FieldLabel>
                <Input id="invite-email" name="email" type="email" required />
              </Field>
              <Field>
                <FieldLabel>{t("create.workspace")}</FieldLabel>
                <Select value={tenantId} onValueChange={(v) => v && setTenantId(v)}>
                  <SelectTrigger>
                    <SelectValue
                      placeholder={
                        tenantsQ.isLoading
                          ? t("create.workspaceLoadingPlaceholder")
                          : t("create.workspacePlaceholder")
                      }
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
                <FieldDescription>{t("create.workspaceHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel>{t("create.role")}</FieldLabel>
                <Select value={roleId} onValueChange={(v) => v && setRoleId(v)}>
                  <SelectTrigger>
                    <SelectValue
                      placeholder={
                        rolesQ.isLoading
                          ? t("create.roleLoadingPlaceholder")
                          : t("create.rolePlaceholder")
                      }
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
                <FieldDescription>{t("create.roleHelp")}</FieldDescription>
              </Field>
              {createM.error && (
                <Field>
                  <FieldError>{(createM.error as ApiError).message}</FieldError>
                </Field>
              )}
            </FieldGroup>
          </div>
          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>
              {t("create.cancel")}
            </SheetClose>
            <Button type="submit" disabled={createM.isPending || !tenantId}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? t("create.submitting") : t("create.submit")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
