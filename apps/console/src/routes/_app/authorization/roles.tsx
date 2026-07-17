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
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Textarea,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, PlusIcon, RefreshCwIcon, ShieldCheckIcon } from "lucide-react";
import { useState } from "react";

import { ListToolbar, SortHeader } from "@/components/data-table";
import { PageHeader } from "@/components/page-header";
import type { ApiError } from "@/lib/api";
import {
  type Permission,
  type Role,
  useCreateRole,
  useGrantPermission,
  usePermissions,
  useRevokePermission,
  useRolePermissions,
  useRoles,
} from "@/lib/authz-rbac";
import { type CsvColumn, exportToCsv, exportToJson } from "@/lib/export";
import { useListView } from "@/lib/list-view";

export const Route = createFileRoute("/_app/authorization/roles")({
  component: RolesPage,
});

const roleCsvColumns: CsvColumn<Role>[] = [
  { header: "id", value: (r) => r.id },
  { header: "name", value: (r) => r.name },
  { header: "description", value: (r) => r.description },
  { header: "type", value: (r) => (r.is_system ? "system" : "custom") },
  { header: "created_at", value: (r) => r.created_at },
];

function RolesPage() {
  const rolesQ = useRoles();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Role | null>(null);

  const items = rolesQ.data?.items ?? [];
  const lv = useListView(items, {
    searchFields: (r) => [r.name, r.description],
    filterFields: { type: (r) => (r.is_system ? "system" : "custom") },
    sortFields: { name: (r) => r.name, created: (r) => r.created_at },
  });
  const rows = lv.view;

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Create roles and manage the permissions they grant. Role assignments propagate through groups automatically."
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => rolesQ.refetch()}
              disabled={rolesQ.isFetching}
            >
              <RefreshCwIcon className={rolesQ.isFetching ? "animate-spin" : ""} /> Refresh
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> New role
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Roles</CardTitle>
          <CardDescription>
            {rows.length} of {items.length} role{items.length === 1 ? "" : "s"}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <ListToolbar
            search={lv.search}
            onSearchChange={lv.setSearch}
            searchPlaceholder="Search roles…"
            filters={[
              {
                id: "type",
                label: "Type",
                value: lv.filters.type ?? "",
                options: [
                  { label: "System", value: "system" },
                  { label: "Custom", value: "custom" },
                ],
                onChange: (v) => lv.setFilter("type", v),
              },
            ]}
            columns={[{ id: "created", label: "Created" }]}
            isColumnVisible={lv.isVisible}
            onToggleColumn={lv.toggleColumn}
            density={lv.density}
            onDensityChange={lv.setDensity}
            onExport={(fmt) =>
              fmt === "csv"
                ? exportToCsv("roles", rows, roleCsvColumns)
                : exportToJson("roles", rows)
            }
            exportDisabled={rows.length === 0}
            hasActiveFilters={lv.hasActiveFilters}
            onClear={lv.clear}
          />
          <DataState
            isLoading={rolesQ.isLoading}
            isError={rolesQ.isError}
            error={rolesQ.error}
            isEmpty={rows.length === 0}
            emptyIcon={ShieldCheckIcon}
            emptyTitle={lv.hasActiveFilters ? "No roles match your filters" : "No roles yet"}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <SortHeader columnKey="name" sort={lv.sort} onToggle={lv.toggleSort}>
                    Name
                  </SortHeader>
                  <TableHead>Description</TableHead>
                  <TableHead>Type</TableHead>
                  {lv.isVisible("created") && (
                    <SortHeader columnKey="created" sort={lv.sort} onToggle={lv.toggleSort}>
                      Created
                    </SortHeader>
                  )}
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="font-medium">{r.name}</TableCell>
                    <TableCell className="text-muted-foreground">{r.description || "—"}</TableCell>
                    <TableCell>
                      <Badge variant={r.is_system ? "muted" : "outline"}>
                        {r.is_system ? "system" : "custom"}
                      </Badge>
                    </TableCell>
                    {lv.isVisible("created") && (
                      <TableCell>
                        <TimeSince value={r.created_at} />
                      </TableCell>
                    )}
                    <TableCell className="text-right">
                      <Button variant="ghost" size="sm" onClick={() => setEditing(r)}>
                        Permissions
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      <CreateRoleSheet open={creating} onOpenChange={setCreating} />
      {editing && <RolePermissionsSheet role={editing} onClose={() => setEditing(null)} />}
    </div>
  );
}

function CreateRoleSheet({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const createM = useCreateRole();
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <form
          className="flex h-full flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            const data = new FormData(e.currentTarget);
            createM.mutate(
              {
                name: String(data.get("name") ?? "").trim(),
                description: String(data.get("description") ?? "").trim(),
              },
              { onSuccess: () => onOpenChange(false) },
            );
          }}
        >
          <SheetHeader>
            <SheetTitle>New role</SheetTitle>
            <SheetDescription>
              Roles bundle permissions and can be assigned to users or groups.
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">Name</FieldLabel>
                <Input
                  id="name"
                  name="name"
                  placeholder="editor"
                  required
                  minLength={1}
                  maxLength={64}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="description">Description</FieldLabel>
                <Textarea id="description" name="description" rows={3} maxLength={500} />
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
              Create role
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}

function RolePermissionsSheet({ role, onClose }: { role: Role; onClose: () => void }) {
  const permsQ = useRolePermissions(role.id);
  const grantM = useGrantPermission(role.id);
  const revokeM = useRevokePermission(role.id);
  const granted = new Set((permsQ.data?.items ?? []).map((p: Permission) => p.id));

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>Permissions · {role.name}</SheetTitle>
          <SheetDescription>
            Toggle a permission to grant or revoke it for this role.
          </SheetDescription>
        </SheetHeader>
        <div className="flex-1 overflow-y-auto p-4">
          <DataState
            isLoading={permsQ.isLoading}
            isError={permsQ.isError}
            error={permsQ.error}
            isEmpty={false}
            skeletonRows={4}
          >
            <PermissionToggleList
              grantedIds={granted}
              busy={grantM.isPending || revokeM.isPending}
              onGrant={(id) => grantM.mutate(id)}
              onRevoke={(id) => revokeM.mutate(id)}
              currentPermissions={permsQ.data?.items ?? []}
            />
          </DataState>
        </div>
        <SheetFooter className="flex-row justify-end gap-2 border-t">
          <Button variant="outline" onClick={onClose}>
            Done
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}

function PermissionToggleList({
  grantedIds,
  busy,
  onGrant,
  onRevoke,
  currentPermissions,
}: {
  grantedIds: Set<string>;
  busy: boolean;
  onGrant: (id: string) => void;
  onRevoke: (id: string) => void;
  currentPermissions: Permission[];
}) {
  // Load the full catalogue to offer permissions not yet granted.
  const catalogue = usePermissionsCatalogue();
  const merged = mergeCatalogue(catalogue, currentPermissions);
  return (
    <ul className="flex flex-col gap-2">
      {merged.map((p) => {
        const isGranted = grantedIds.has(p.id);
        return (
          <li key={p.id} className="flex items-center justify-between gap-3 rounded-md border p-3">
            <span className="min-w-0">
              <code className="text-xs font-medium">{p.key}</code>
              <p className="truncate text-xs text-muted-foreground">{p.description}</p>
            </span>
            <Switch
              checked={isGranted}
              disabled={busy}
              aria-label={`${isGranted ? "Revoke" : "Grant"} ${p.key}`}
              onCheckedChange={(checked) => (checked ? onGrant(p.id) : onRevoke(p.id))}
            />
          </li>
        );
      })}
    </ul>
  );
}

// Small helpers to reuse the cached permissions catalogue without prop-drilling.
function usePermissionsCatalogue(): Permission[] {
  const q = usePermissions();
  return q.data?.items ?? [];
}
function mergeCatalogue(catalogue: Permission[], current: Permission[]): Permission[] {
  const byId = new Map<string, Permission>();
  for (const p of catalogue) byId.set(p.id, p);
  for (const p of current) byId.set(p.id, p);
  return [...byId.values()].sort((a, b) => a.key.localeCompare(b.key));
}
