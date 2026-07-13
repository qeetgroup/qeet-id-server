import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
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
} from "@qeetrix/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Loader2Icon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  Trash2Icon,
  UserPlusIcon,
  UsersRoundIcon,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useConfirmDialog } from "@/components/confirm-dialog";
import { ListToolbar, SortHeader } from "@/components/data-table";
import { PageHeader } from "@/components/page-header";
import { type ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";
import { type CsvColumn, exportToCsv, exportToJson } from "@/lib/export";
import { useListView } from "@/lib/list-view";

export const Route = createFileRoute("/_app/groups/")({
  component: GroupsPage,
});

type Group = {
  id: string;
  tenant_id: string;
  parent_id?: string | null;
  name: string;
  description: string;
  created_at: string;
};

type Member = { user_id: string; email?: string; display_name?: string | null };

const groupCsvColumns: CsvColumn<Group>[] = [
  { header: "id", value: (g) => g.id },
  { header: "name", value: (g) => g.name },
  { header: "description", value: (g) => g.description },
  { header: "parent_id", value: (g) => g.parent_id },
  { header: "created_at", value: (g) => g.created_at },
];

function GroupsPage() {
  const { t } = useTranslation("groups");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Group | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const groupsQ = useQuery({
    queryKey: ["groups", tenantId],
    queryFn: () => api<{ items: Group[] }>(`/v1/tenants/${tenantId}/groups`),
    enabled: !!tenantId,
  });

  const items = groupsQ.data?.items ?? [];
  const lv = useListView(items, {
    searchFields: (g) => [g.name, g.description],
    filterFields: { scope: (g) => (g.parent_id ? "nested" : "top-level") },
    sortFields: { name: (g) => g.name, created: (g) => g.created_at },
  });
  const rows = lv.view;
  const denseCls = lv.density === "compact" ? "[&_td]:py-1.5 [&_th]:py-2" : undefined;

  const deleteM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/groups/${id}`, { method: "DELETE" }),
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey: ["groups"] });
      const snapshots = qc.getQueriesData<{ items: Group[] }>({
        queryKey: ["groups"],
      });
      qc.setQueriesData<{ items: Group[] }>({ queryKey: ["groups"] }, (prev) =>
        prev ? { ...prev, items: prev.items.filter((g) => g.id !== id) } : prev,
      );
      return { snapshots };
    },
    onError: (_err, _id, ctx) => {
      ctx?.snapshots.forEach(([key, snap]) => qc.setQueryData(key, snap));
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["groups"] }),
    meta: { successMessage: "Group deleted" },
  });

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
              onClick={() => groupsQ.refetch()}
              disabled={groupsQ.isFetching}
            >
              <RefreshCwIcon className={groupsQ.isFetching ? "animate-spin" : ""} />
              {t("list.refresh")}
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> {t("list.new")}
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
                id: "scope",
                label: t("list.filters.scope.label"),
                value: lv.filters.scope ?? "",
                options: [
                  {
                    label: t("list.filters.scope.topLevel"),
                    value: "top-level",
                  },
                  { label: t("list.filters.scope.nested"), value: "nested" },
                ],
                onChange: (v) => lv.setFilter("scope", v),
              },
            ]}
            columns={[
              { id: "description", label: t("list.columns.description") },
              { id: "parent", label: t("list.columns.parent") },
              { id: "created", label: t("list.columns.created") },
            ]}
            isColumnVisible={lv.isVisible}
            onToggleColumn={lv.toggleColumn}
            density={lv.density}
            onDensityChange={lv.setDensity}
            onExport={(fmt) =>
              fmt === "csv"
                ? exportToCsv("groups", rows, groupCsvColumns)
                : exportToJson("groups", rows)
            }
            exportDisabled={rows.length === 0}
            hasActiveFilters={lv.hasActiveFilters}
            onClear={lv.clear}
          />
          <DataState
            isLoading={groupsQ.isLoading}
            isError={groupsQ.isError}
            error={groupsQ.error}
            isEmpty={rows.length === 0}
            emptyIcon={UsersRoundIcon}
            emptyTitle={lv.hasActiveFilters ? t("list.emptyFiltered") : t("list.empty")}
            skeletonRows={3}
          >
            <Table className={denseCls}>
              <TableHeader>
                <TableRow>
                  <SortHeader columnKey="name" sort={lv.sort} onToggle={lv.toggleSort}>
                    {t("list.columns.name")}
                  </SortHeader>
                  {lv.isVisible("description") && (
                    <TableHead>{t("list.columns.description")}</TableHead>
                  )}
                  {lv.isVisible("parent") && <TableHead>{t("list.columns.parent")}</TableHead>}
                  {lv.isVisible("created") && (
                    <SortHeader columnKey="created" sort={lv.sort} onToggle={lv.toggleSort}>
                      {t("list.columns.created")}
                    </SortHeader>
                  )}
                  <TableHead className="text-right">{t("list.columns.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((g) => (
                  <TableRow key={g.id}>
                    <TableCell className="font-medium">
                      <Link
                        to="/groups/$groupId"
                        params={{ groupId: g.id }}
                        className="hover:underline"
                      >
                        {g.name}
                      </Link>
                    </TableCell>
                    {lv.isVisible("description") && (
                      <TableCell className="text-muted-foreground">
                        {g.description || "—"}
                      </TableCell>
                    )}
                    {lv.isVisible("parent") && (
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {g.parent_id ? g.parent_id.slice(0, 8) + "…" : "—"}
                      </TableCell>
                    )}
                    {lv.isVisible("created") && (
                      <TableCell>
                        <TimeSince value={g.created_at} />
                      </TableCell>
                    )}
                    <TableCell className="text-right">
                      <Button variant="ghost" size="sm" onClick={() => setExpandedId(g.id)}>
                        <UserPlusIcon /> {t("table.members")}
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => setEditing(g)}>
                        <PencilIcon /> {t("table.edit")}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={deleteM.isPending}
                        onClick={() =>
                          openConfirm({
                            title: t("confirm.delete", { name: g.name }),
                            variant: "destructive",
                            confirmLabel: t("confirm.deleteLabel"),
                            onConfirm: () => deleteM.mutate(g.id),
                          })
                        }
                      >
                        <Trash2Icon /> {t("table.delete")}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      <CreateGroupSheet
        open={creating}
        onOpenChange={setCreating}
        tenantId={tenantId}
        groups={groupsQ.data?.items ?? []}
        onCreated={() => qc.invalidateQueries({ queryKey: ["groups"] })}
      />

      <EditGroupSheet
        group={editing}
        onOpenChange={(o) => !o && setEditing(null)}
        groups={groupsQ.data?.items ?? []}
        onSaved={() => {
          setEditing(null);
          qc.invalidateQueries({ queryKey: ["groups"] });
        }}
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

function CreateGroupSheet({
  open,
  onOpenChange,
  tenantId,
  groups,
  onCreated,
}: CreateGroupSheetProps) {
  const { t } = useTranslation("groups");
  const createM = useMutation({
    mutationFn: (body: {
      tenant_id: string;
      parent_id: string | null;
      name: string;
      description: string;
    }) => api<Group>("/v1/groups", { method: "POST", body }),
    onSuccess: () => {
      onCreated();
      onOpenChange(false);
    },
    meta: { successMessage: "Group created" },
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
            <SheetTitle>{t("create.title")}</SheetTitle>
            <SheetDescription>{t("create.description")}</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">{t("create.name")}</FieldLabel>
                <Input id="name" name="name" placeholder={t("create.namePlaceholder")} required />
              </Field>
              <Field>
                <FieldLabel htmlFor="description">{t("create.description_field")}</FieldLabel>
                <Textarea id="description" name="description" rows={3} />
              </Field>
              <Field>
                <FieldLabel htmlFor="parent_id">{t("create.parent")}</FieldLabel>
                <select
                  id="parent_id"
                  name="parent_id"
                  className="h-9 rounded-md border bg-background px-3 text-sm"
                >
                  <option value="">{t("create.parentNone")}</option>
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </select>
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
            <Button type="submit" disabled={createM.isPending}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? t("create.submitting") : t("create.submit")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}

type EditGroupSheetProps = {
  group: Group | null;
  onOpenChange: (o: boolean) => void;
  groups: Group[];
  onSaved: () => void;
};

function EditGroupSheet({ group, onOpenChange, groups, onSaved }: EditGroupSheetProps) {
  const { t } = useTranslation("groups");
  const updateM = useMutation({
    mutationFn: (body: { name: string; description: string; parent_id: string | null }) =>
      api<Group>(`/v1/groups/${group?.id}`, { method: "PATCH", body }),
    onSuccess: () => {
      onSaved();
    },
    meta: { successMessage: "Group updated" },
  });

  return (
    <Sheet open={!!group} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <form
          className="flex h-full flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            if (!group) return;
            const data = new FormData(e.currentTarget);
            const parentId = String(data.get("parent_id") ?? "");
            updateM.mutate({
              name: String(data.get("name") ?? "").trim(),
              description: String(data.get("description") ?? "").trim(),
              parent_id: parentId || null,
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
                <FieldLabel htmlFor="edit-name">{t("edit.name")}</FieldLabel>
                <Input
                  id="edit-name"
                  name="name"
                  defaultValue={group?.name ?? ""}
                  key={group?.id + "-name"}
                  required
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="edit-description">{t("edit.description_field")}</FieldLabel>
                <Textarea
                  id="edit-description"
                  name="description"
                  rows={3}
                  defaultValue={group?.description ?? ""}
                  key={group?.id + "-desc"}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="edit-parent_id">{t("edit.parent")}</FieldLabel>
                <select
                  id="edit-parent_id"
                  name="parent_id"
                  key={group?.id + "-parent"}
                  defaultValue={group?.parent_id ?? ""}
                  className="h-9 rounded-md border bg-background px-3 text-sm"
                >
                  <option value="">{t("edit.parentNone")}</option>
                  {groups
                    .filter((g) => g.id !== group?.id)
                    .map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                      </option>
                    ))}
                </select>
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
              {t("edit.cancel")}
            </SheetClose>
            <Button type="submit" disabled={updateM.isPending}>
              {updateM.isPending && <Loader2Icon className="animate-spin" />}
              {updateM.isPending ? t("edit.saving") : t("edit.save")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}

type MembersSheetProps = {
  groupId: string;
  groupName: string;
  onClose: () => void;
};

type PickUser = { id: string; email: string; display_name?: string | null };

function MembersSheet({ groupId, groupName, onClose }: MembersSheetProps) {
  const { t } = useTranslation("groups");
  const qc = useQueryClient();
  const [query, setQuery] = useState("");

  const membersQ = useQuery({
    queryKey: ["group-members", groupId],
    queryFn: () => api<{ items: Member[] }>(`/v1/groups/${groupId}/members`),
  });

  const usersQ = useQuery({
    queryKey: ["pick-users"],
    queryFn: () => api<{ items: PickUser[] }>(`/v1/users?limit=200`),
  });

  const addM = useMutation({
    mutationFn: (userId: string) =>
      api<void>(`/v1/groups/${groupId}/members/${userId}`, { method: "POST" }),
    onSuccess: () => {
      setQuery("");
      qc.invalidateQueries({ queryKey: ["group-members", groupId] });
    },
    meta: { successMessage: "Member added" },
  });

  const removeM = useMutation({
    mutationFn: (userId: string) =>
      api<void>(`/v1/groups/${groupId}/members/${userId}`, {
        method: "DELETE",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["group-members", groupId] }),
    meta: { successMessage: "Member removed" },
  });

  const memberIds = new Set((membersQ.data?.items ?? []).map((m) => m.user_id));
  const q = query.trim().toLowerCase();
  const candidates = (usersQ.data?.items ?? [])
    .filter((u) => !memberIds.has(u.id))
    .filter(
      (u) =>
        q !== "" &&
        ((u.display_name ?? "").toLowerCase().includes(q) || u.email.toLowerCase().includes(q)),
    )
    .slice(0, 8);

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <SheetHeader>
          <SheetTitle>{t("members.title", { groupName })}</SheetTitle>
          <SheetDescription>{t("members.description")}</SheetDescription>
        </SheetHeader>
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <div className="relative">
            <Input
              placeholder={t("members.searchPlaceholder")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            {q !== "" && (
              <div className="mt-1 overflow-hidden rounded-md border">
                {usersQ.isLoading ? (
                  <p className="px-3 py-2 text-sm text-muted-foreground">
                    {t("members.loadingUsers")}
                  </p>
                ) : candidates.length === 0 ? (
                  <p className="px-3 py-2 text-sm text-muted-foreground">{t("members.noMatch")}</p>
                ) : (
                  candidates.map((u) => (
                    <button
                      key={u.id}
                      type="button"
                      disabled={addM.isPending}
                      onClick={() => addM.mutate(u.id)}
                      className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-sm transition-colors hover:bg-muted/60 disabled:opacity-50"
                    >
                      <span className="min-w-0">
                        <span className="block truncate font-medium">
                          {u.display_name || u.email}
                        </span>
                        <span className="block truncate text-xs text-muted-foreground">
                          {u.email}
                        </span>
                      </span>
                      <UserPlusIcon className="size-4 shrink-0 text-muted-foreground" />
                    </button>
                  ))
                )}
              </div>
            )}
          </div>
          {addM.error && <FieldError>{(addM.error as ApiError).message}</FieldError>}

          {membersQ.isLoading ? (
            [...Array(3)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)
          ) : !membersQ.data?.items?.length ? (
            <p className="text-sm text-muted-foreground text-center py-6">
              {t("members.noMembers")}
            </p>
          ) : (
            membersQ.data.items.map((m) => (
              <div
                key={m.user_id}
                className="flex items-center justify-between rounded-md border p-3 text-sm"
              >
                <div className="min-w-0">
                  <div className="font-medium truncate">
                    {m.display_name ?? m.email ?? m.user_id}
                  </div>
                  <code className="text-xs text-muted-foreground">{m.user_id.slice(0, 16)}…</code>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label={t("members.removeLabel")}
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
          <Button variant="outline" onClick={onClose}>
            {t("members.close")}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
