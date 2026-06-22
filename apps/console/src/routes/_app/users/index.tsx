import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
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
  PaginationBar,
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
  buttonVariants,
} from "@qeetrix/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, createFileRoute } from "@tanstack/react-router";
import {
  KeyRoundIcon,
  Loader2Icon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  Trash2Icon,
  UploadCloudIcon,
  UserIcon,
} from "lucide-react";
import { useEffect, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { toast } from "sonner";

import { BulkBar, ListToolbar, MasterCheckbox, RowCheckbox, SortHeader } from "@/components/data-table";
import { PageHeader } from "@/components/page-header";
import { ApiError, api, tokenStore } from "@/lib/api";
import { useTenantId } from "@/lib/auth";
import { useRoles } from "@/lib/rbac-groups";
import { exportToCsv, exportToJson, type CsvColumn } from "@/lib/export";
import { useListView } from "@/lib/list-view";

export const Route = createFileRoute("/_app/users/")({ component: UsersPage });

type User = {
  id: string;
  tenant_id: string;
  email: string;
  display_name?: string | null;
  phone?: string | null;
  status: "active" | "invited" | "suspended" | "deleted";
  email_verified_at?: string | null;
  roles?: string[] | null;
  created_at: string;
};

type UsersResponse = { items: User[]; next_cursor?: string };

const userCsvColumns: CsvColumn<User>[] = [
  { header: "id", value: (u) => u.id },
  { header: "email", value: (u) => u.email },
  { header: "display_name", value: (u) => u.display_name },
  { header: "phone", value: (u) => u.phone },
  { header: "status", value: (u) => u.status },
  { header: "email_verified_at", value: (u) => u.email_verified_at },
  { header: "created_at", value: (u) => u.created_at },
];

function UsersPage() {
  const { t } = useTranslation("users");
  const tenantId = useTenantId();
  const currentUserId = tokenStore.getUserId();
  const qc = useQueryClient();
  const statusOptions = [
    { label: t("status.active"), value: "active" },
    { label: t("status.invited"), value: "invited" },
    { label: t("status.suspended"), value: "suspended" },
    { label: t("status.deleted"), value: "deleted" },
  ];
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);
  const [settingPassword, setSettingPassword] = useState<User | null>(null);
  const [confirmingDelete, setConfirmingDelete] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [bulkProgress, setBulkProgress] = useState<{ done: number; total: number } | null>(null);
  // Cursor stack lets us pop back to the previous page without re-walking
  // from the start, while the API itself is forward-only (next_cursor).
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const currentCursor = cursorStack[cursorStack.length - 1];

  const usersQ = useQuery({
    queryKey: ["users", tenantId, currentCursor ?? ""],
    queryFn: () =>
      api<UsersResponse>("/v1/users", {
        query: currentCursor ? { cursor: currentCursor } : undefined,
      }),
    enabled: !!tenantId,
  });

  const items = usersQ.data?.items ?? [];
  const lv = useListView(items, {
    searchFields: (u) => [u.email, u.display_name, u.phone],
    filterFields: { status: (u) => u.status },
    sortFields: {
      email: (u) => u.email,
      name: (u) => u.display_name ?? "",
      status: (u) => u.status,
      created: (u) => u.created_at,
    },
  });
  const rows = lv.view;
  const selectableIds = rows.filter((u) => u.id !== currentUserId).map((u) => u.id);

  // Bulk delete fans out N single deletes (capped concurrency) since the
  // backend has no bulk endpoint; allSettled surfaces partial successes.
  const bulkDeleteM = useMutation({
    mutationFn: async (ids: string[]): Promise<{ ok: number; failed: number }> => {
      setBulkProgress({ done: 0, total: ids.length });
      const CONCURRENCY = 5;
      let done = 0;
      let ok = 0;
      let failed = 0;
      const queue = [...ids];
      async function worker() {
        for (;;) {
          const id = queue.shift();
          if (!id) return;
          try {
            await api<void>(`/v1/users/${id}`, { method: "DELETE" });
            ok++;
          } catch {
            failed++;
          }
          done++;
          setBulkProgress({ done, total: ids.length });
        }
      }
      await Promise.all(Array.from({ length: Math.min(CONCURRENCY, ids.length) }, worker));
      return { ok, failed };
    },
    onSettled: () => {
      setBulkProgress(null);
      setSelectedIds(new Set());
      qc.invalidateQueries({ queryKey: ["users"] });
    },
    meta: { silent: true }, // we toast manually with combined ok/failed
  });

  const deleteM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/users/${id}`, { method: "DELETE" }),
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey: ["users"] });
      const snapshots = qc.getQueriesData<UsersResponse>({ queryKey: ["users"] });
      qc.setQueriesData<UsersResponse>({ queryKey: ["users"] }, (prev) =>
        prev ? { ...prev, items: prev.items.filter((u) => u.id !== id) } : prev,
      );
      return { snapshots };
    },
    onError: (_err, _id, ctx) => {
      ctx?.snapshots.forEach(([key, snap]) => qc.setQueryData(key, snap));
    },
    onSuccess: () => {
      setConfirmingDelete(null);
      qc.invalidateQueries({ queryKey: ["users"] });
    },
    meta: { successMessage: t("toast.deleted") },
  });

  function runBulkDelete() {
    const ids = Array.from(selectedIds);
    if (!ids.length) return;
    if (!confirm(t("bulk.confirm", { count: ids.length }))) {
      return;
    }
    bulkDeleteM.mutate(ids, {
      onSuccess: (res) => {
        if (res.failed === 0) {
          toast.success(t("bulk.deletedOk", { count: res.ok }));
        } else if (res.ok === 0) {
          toast.error(t("bulk.deletedFail", { count: res.failed }));
        } else {
          toast.warning(t("bulk.deletedPartial", { ok: res.ok, failed: res.failed }));
        }
      },
    });
  }

  const denseCls = lv.density === "compact" ? "[&_td]:py-1.5 [&_th]:py-2" : undefined;

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description={t("list.description")}
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => usersQ.refetch()}
              disabled={usersQ.isFetching}
            >
              <RefreshCwIcon className={usersQ.isFetching ? "animate-spin" : ""} />
              {t("common:actions.refresh")}
            </Button>
            <Link to="/users/import" className={buttonVariants({ variant: "outline", size: "sm" })}>
              <UploadCloudIcon /> {t("list.import")}
            </Link>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> {t("list.newUser")}
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("list.membersTitle")}</CardTitle>
          <CardDescription>
            {t("list.membersSubtitle", { shown: rows.length, total: items.length, count: items.length })}
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
                label: t("table.status"),
                value: lv.filters.status ?? "",
                options: statusOptions,
                onChange: (v) => lv.setFilter("status", v),
              },
            ]}
            columns={[
              { id: "name", label: t("table.name") },
              { id: "verified", label: t("table.emailVerified") },
              { id: "created", label: t("table.created") },
            ]}
            isColumnVisible={lv.isVisible}
            onToggleColumn={lv.toggleColumn}
            density={lv.density}
            onDensityChange={lv.setDensity}
            onExport={(fmt) =>
              fmt === "csv" ? exportToCsv("users", rows, userCsvColumns) : exportToJson("users", rows)
            }
            exportDisabled={rows.length === 0}
            hasActiveFilters={lv.hasActiveFilters}
            onClear={lv.clear}
          />

          {selectedIds.size > 0 && (
            <BulkBar
              count={selectedIds.size}
              progress={bulkProgress}
              disabled={bulkDeleteM.isPending}
              onClear={() => setSelectedIds(new Set())}
            >
              <Button
                variant="destructive"
                size="sm"
                onClick={runBulkDelete}
                disabled={bulkDeleteM.isPending}
              >
                {bulkDeleteM.isPending ? <Loader2Icon className="animate-spin" /> : <Trash2Icon />}
                {t("list.bulkDelete", { count: selectedIds.size })}
              </Button>
            </BulkBar>
          )}

          <DataState
            isLoading={usersQ.isLoading}
            isError={usersQ.isError}
            error={usersQ.error}
            isEmpty={rows.length === 0}
            emptyIcon={UserIcon}
            emptyTitle={lv.hasActiveFilters ? t("list.emptyTitleFiltered") : t("list.emptyTitle")}
            emptyDescription={
              lv.hasActiveFilters ? t("list.emptyDescriptionFiltered") : t("list.emptyDescription")
            }
          >
            <>
              <Table className={denseCls}>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-8">
                      <MasterCheckbox
                        selectableIds={selectableIds}
                        selectedIds={selectedIds}
                        onChange={setSelectedIds}
                        label={t("list.selectAll")}
                      />
                    </TableHead>
                    <SortHeader columnKey="email" sort={lv.sort} onToggle={lv.toggleSort}>
                      {t("table.email")}
                    </SortHeader>
                    {lv.isVisible("name") && (
                      <SortHeader columnKey="name" sort={lv.sort} onToggle={lv.toggleSort}>
                        {t("table.name")}
                      </SortHeader>
                    )}
                    <TableHead>{t("table.role")}</TableHead>
                    <SortHeader columnKey="status" sort={lv.sort} onToggle={lv.toggleSort}>
                      {t("table.status")}
                    </SortHeader>
                    {lv.isVisible("verified") && <TableHead>{t("table.emailVerified")}</TableHead>}
                    {lv.isVisible("created") && (
                      <SortHeader columnKey="created" sort={lv.sort} onToggle={lv.toggleSort}>
                        {t("table.created")}
                      </SortHeader>
                    )}
                    <TableHead className="text-right">{t("table.actions")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((u) => {
                    const isSelf = u.id === currentUserId;
                    const isSelected = selectedIds.has(u.id);
                    return (
                      <TableRow key={u.id} className={isSelected ? "bg-muted/40" : undefined}>
                        <TableCell>
                          <RowCheckbox
                            id={u.id}
                            checked={isSelected}
                            disabled={isSelf}
                            label={t("list.selectOne", { email: u.email })}
                            onChange={(id, checked) =>
                              setSelectedIds((prev) => {
                                const next = new Set(prev);
                                if (checked) next.add(id);
                                else next.delete(id);
                                return next;
                              })
                            }
                          />
                        </TableCell>
                        <TableCell className="font-medium">
                          <Link
                            to="/users/$userId"
                            params={{ userId: u.id }}
                            className="hover:underline"
                          >
                            {u.email}
                          </Link>
                          {isSelf && (
                            <Badge variant="muted" className="ml-2">
                              {t("list.you")}
                            </Badge>
                          )}
                        </TableCell>
                        {lv.isVisible("name") && (
                          <TableCell className="text-muted-foreground">
                            {u.display_name ?? "—"}
                          </TableCell>
                        )}
                        <TableCell>
                          {u.roles && u.roles.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {u.roles.map((r) => (
                                <Badge key={r} variant="secondary">
                                  {r}
                                </Badge>
                              ))}
                            </div>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <StatusPill status={u.status} />
                        </TableCell>
                        {lv.isVisible("verified") && (
                          <TableCell>
                            {u.email_verified_at ? (
                              <TimeSince value={u.email_verified_at} />
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                        )}
                        {lv.isVisible("created") && (
                          <TableCell>
                            <TimeSince value={u.created_at} />
                          </TableCell>
                        )}
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1">
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label={t("table.editUser")}
                              onClick={() => setEditing(u)}
                            >
                              <PencilIcon />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label={t("table.setPassword")}
                              onClick={() => setSettingPassword(u)}
                            >
                              <KeyRoundIcon />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label={t("table.deleteUser")}
                              disabled={isSelf}
                              title={isSelf ? t("table.deleteSelf") : t("table.deleteUser")}
                              onClick={() => setConfirmingDelete(u.id)}
                            >
                              <Trash2Icon className="text-destructive" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
              {(cursorStack.length > 0 || !!usersQ.data?.next_cursor) && (
                <PaginationBar
                  hasPrev={cursorStack.length > 0}
                  hasNext={!!usersQ.data?.next_cursor}
                  onFirst={() => {
                    setCursorStack([]);
                    setSelectedIds(new Set());
                  }}
                  onNext={() => {
                    const next = usersQ.data?.next_cursor;
                    if (next) {
                      setCursorStack((s) => [...s, next]);
                      setSelectedIds(new Set());
                    }
                  }}
                  itemsOnPage={rows.length}
                  pageSize={50}
                  loading={usersQ.isFetching}
                />
              )}
            </>
          </DataState>
        </CardContent>
      </Card>

      <CreateUserSheet
        open={creating}
        onOpenChange={setCreating}
        tenantId={tenantId}
        onCreated={() => qc.invalidateQueries({ queryKey: ["users"] })}
      />

      <EditUserSheet
        user={editing}
        isSelf={!!editing && editing.id === currentUserId}
        onOpenChange={(o) => !o && setEditing(null)}
        onSaved={() => {
          setEditing(null);
          qc.invalidateQueries({ queryKey: ["users"] });
        }}
      />

      <SetPasswordSheet
        user={settingPassword}
        onOpenChange={(o) => !o && setSettingPassword(null)}
        onSaved={() => setSettingPassword(null)}
      />

      <AlertDialog
        open={!!confirmingDelete}
        onOpenChange={(o) => {
          if (!o && !deleteM.isPending) setConfirmingDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("delete.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {(() => {
                const target = items.find((u) => u.id === confirmingDelete);
                return target ? (
                  <Trans
                    t={t}
                    i18nKey="delete.descriptionNamed"
                    values={{ email: target.email }}
                    components={{ strong: <span className="font-medium text-foreground" /> }}
                  />
                ) : (
                  t("delete.descriptionFallback")
                );
              })()}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteM.isPending}>
              {t("common:actions.cancel")}
            </AlertDialogCancel>
            <Button
              variant="destructive"
              disabled={deleteM.isPending}
              onClick={() => confirmingDelete && deleteM.mutate(confirmingDelete)}
            >
              {deleteM.isPending && <Loader2Icon className="animate-spin" />}
              {deleteM.isPending ? t("common:actions.deleting") : t("common:actions.delete")}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

type CreateUserSheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  tenantId: string | null;
  onCreated: () => void;
};

function CreateUserSheet({ open, onOpenChange, tenantId, onCreated }: CreateUserSheetProps) {
  const { t } = useTranslation("users");
  const rolesQ = useRoles();
  const roles = rolesQ.data?.items ?? [];
  const [roleId, setRoleId] = useState("");

  // Default to a "member"-type role (else the least-privileged/last one) so a
  // created user is a workspace member out of the box.
  useEffect(() => {
    if (!roleId && roles.length > 0) {
      const member = roles.find((r) => /member/i.test(r.name));
      setRoleId(member?.id ?? roles[roles.length - 1]!.id);
    }
  }, [roles, roleId]);

  const createM = useMutation({
    mutationFn: async (vars: {
      tenant_id: string;
      email: string;
      password: string;
      display_name?: string;
      phone?: string;
      role_id?: string;
    }) => {
      const { role_id, ...body } = vars;
      const user = await api<User>("/v1/users", { method: "POST", body });
      // The members list is rbac.user_roles-based, so a user is only "in" the
      // workspace once they hold a role — grant the chosen one now.
      if (role_id) {
        await api<void>(`/v1/users/${user.id}/tenants/${body.tenant_id}/roles/${role_id}`, {
          method: "POST",
        });
      }
      return user;
    },
    onSuccess: () => {
      onCreated();
      onOpenChange(false);
    },
    meta: { successMessage: t("toast.created") },
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
              password: String(data.get("password") ?? ""),
              display_name: String(data.get("display_name") ?? "").trim() || undefined,
              phone: String(data.get("phone") ?? "").trim() || undefined,
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
                <FieldLabel htmlFor="email">{t("create.email")}</FieldLabel>
                <Input id="email" name="email" type="email" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="display_name">{t("create.displayName")}</FieldLabel>
                <Input id="display_name" name="display_name" type="text" />
                <FieldDescription>{t("create.displayNameHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="phone">{t("create.phone")}</FieldLabel>
                <Input
                  id="phone"
                  name="phone"
                  type="tel"
                  placeholder="+15555550100"
                  pattern="\+[1-9]\d{1,14}"
                />
                <FieldDescription>{t("create.phoneHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="password">{t("create.password")}</FieldLabel>
                <Input id="password" name="password" type="password" minLength={8} required />
                <FieldDescription>{t("create.passwordHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="role">Role</FieldLabel>
                <Select value={roleId} onValueChange={(v) => v && setRoleId(v)}>
                  <SelectTrigger id="role" aria-label="Role">
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
                  Grants workspace membership — without a role the user won&apos;t appear in the
                  members list.
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
            <SheetClose render={<Button type="button" variant="outline" />}>
              {t("common:actions.cancel")}
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

type EditUserSheetProps = {
  user: User | null;
  isSelf: boolean;
  onOpenChange: (o: boolean) => void;
  onSaved: () => void;
};

type UpdateBody = {
  display_name?: string | null;
  phone?: string | null;
  status?: "active" | "suspended";
};

function EditUserSheet({ user, isSelf, onOpenChange, onSaved }: EditUserSheetProps) {
  const { t } = useTranslation("users");
  // Reset selected status when the editing target changes.
  const [trackedId, setTrackedId] = useState<string | null>(null);
  const [status, setStatus] = useState<"active" | "suspended">(
    user?.status === "suspended" ? "suspended" : "active",
  );
  if (user && user.id !== trackedId) {
    setTrackedId(user.id);
    setStatus(user.status === "suspended" ? "suspended" : "active");
  }

  const updateM = useMutation({
    mutationFn: (body: UpdateBody) => api<User>(`/v1/users/${user!.id}`, { method: "PATCH", body }),
    onSuccess: onSaved,
    meta: { successMessage: t("toast.updated") },
  });

  return (
    <Sheet open={!!user} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        {user && (
          <form
            className="flex h-full flex-col"
            onSubmit={(e) => {
              e.preventDefault();
              const data = new FormData(e.currentTarget);
              const displayName = String(data.get("display_name") ?? "").trim();
              const phone = String(data.get("phone") ?? "").trim();
              updateM.mutate({
                display_name: displayName || null,
                phone: phone || null,
                // Don't allow suspending yourself.
                ...(isSelf ? {} : { status }),
              });
            }}
          >
            <SheetHeader>
              <SheetTitle>{t("edit.title")}</SheetTitle>
              <SheetDescription>{t("edit.description")}</SheetDescription>
            </SheetHeader>

            <div className="flex-1 overflow-y-auto p-4">
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="edit-email">{t("edit.email")}</FieldLabel>
                  <Input id="edit-email" value={user.email} readOnly disabled />
                </Field>
                <Field>
                  <FieldLabel htmlFor="edit-display-name">{t("edit.displayName")}</FieldLabel>
                  <Input
                    id="edit-display-name"
                    name="display_name"
                    defaultValue={user.display_name ?? ""}
                    maxLength={200}
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="edit-phone">{t("edit.phone")}</FieldLabel>
                  <Input
                    id="edit-phone"
                    name="phone"
                    type="tel"
                    defaultValue={user.phone ?? ""}
                    placeholder="+15555550100"
                    pattern="\+[1-9]\d{1,14}"
                  />
                  <FieldDescription>{t("edit.phoneHelp")}</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel id="user-status-label">{t("edit.status")}</FieldLabel>
                  <Select
                    value={status}
                    onValueChange={(v) => v && setStatus(v as "active" | "suspended")}
                    disabled={isSelf}
                  >
                    <SelectTrigger aria-labelledby="user-status-label">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="active">{t("edit.statusActive")}</SelectItem>
                      <SelectItem value="suspended">{t("edit.statusSuspended")}</SelectItem>
                    </SelectContent>
                  </Select>
                  <FieldDescription>
                    {isSelf ? t("edit.statusSelfHelp") : t("edit.statusHelp")}
                  </FieldDescription>
                </Field>
                {updateM.error && (
                  <Field>
                    <FieldError>{(updateM.error as ApiError).message}</FieldError>
                  </Field>
                )}
              </FieldGroup>
            </div>

            <SheetFooter className="flex-row justify-end gap-2 border-t">
              <SheetClose render={<Button type="button" variant="outline" />}>
                {t("common:actions.cancel")}
              </SheetClose>
              <Button type="submit" disabled={updateM.isPending}>
                {updateM.isPending && <Loader2Icon className="animate-spin" />}
                {updateM.isPending ? t("common:actions.saving") : t("common:actions.saveChanges")}
              </Button>
            </SheetFooter>
          </form>
        )}
      </SheetContent>
    </Sheet>
  );
}

type SetPasswordSheetProps = {
  user: User | null;
  onOpenChange: (o: boolean) => void;
  onSaved: () => void;
};

function SetPasswordSheet({ user, onOpenChange, onSaved }: SetPasswordSheetProps) {
  const { t } = useTranslation("users");
  const setM = useMutation({
    mutationFn: (body: { password: string }) =>
      api<void>(`/v1/users/${user!.id}/password`, { method: "POST", body }),
    onSuccess: onSaved,
    meta: { successMessage: t("toast.passwordUpdated") },
  });

  return (
    <Sheet open={!!user} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        {user && (
          <form
            className="flex h-full flex-col"
            onSubmit={(e) => {
              e.preventDefault();
              const data = new FormData(e.currentTarget);
              const password = String(data.get("password") ?? "");
              const confirm = String(data.get("confirm") ?? "");
              if (password !== confirm) {
                setM.reset();
                const el = e.currentTarget.elements.namedItem("confirm") as HTMLInputElement;
                el.setCustomValidity(t("setPassword.mismatch"));
                el.reportValidity();
                return;
              }
              setM.mutate({ password });
            }}
          >
            <SheetHeader>
              <SheetTitle>{t("setPassword.title")}</SheetTitle>
              <SheetDescription>
                <Trans
                  t={t}
                  i18nKey="setPassword.description"
                  values={{ email: user.email }}
                  components={{
                    strong: <span className="font-medium text-foreground" />,
                    path: <span className="font-mono text-xs" />,
                  }}
                />
              </SheetDescription>
            </SheetHeader>

            <div className="flex-1 overflow-y-auto p-4">
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="new-password">{t("setPassword.newPassword")}</FieldLabel>
                  <Input
                    id="new-password"
                    name="password"
                    type="password"
                    minLength={8}
                    maxLength={256}
                    required
                    autoComplete="new-password"
                  />
                  <FieldDescription>{t("setPassword.newPasswordHelp")}</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="confirm-password">
                    {t("setPassword.confirmPassword")}
                  </FieldLabel>
                  <Input
                    id="confirm-password"
                    name="confirm"
                    type="password"
                    minLength={8}
                    maxLength={256}
                    required
                    autoComplete="new-password"
                    onInput={(e) => (e.currentTarget as HTMLInputElement).setCustomValidity("")}
                  />
                </Field>
                {setM.error && (
                  <Field>
                    <FieldError>{(setM.error as ApiError).message}</FieldError>
                  </Field>
                )}
                {setM.isSuccess && (
                  <Field>
                    <FieldDescription className="text-success">
                      {t("setPassword.success")}
                    </FieldDescription>
                  </Field>
                )}
              </FieldGroup>
            </div>

            <SheetFooter className="flex-row justify-end gap-2 border-t">
              <SheetClose render={<Button type="button" variant="outline" />}>
                {t("common:actions.cancel")}
              </SheetClose>
              <Button type="submit" disabled={setM.isPending}>
                {setM.isPending && <Loader2Icon className="animate-spin" />}
                {setM.isPending ? t("common:actions.saving") : t("setPassword.submit")}
              </Button>
            </SheetFooter>
          </form>
        )}
      </SheetContent>
    </Sheet>
  );
}
