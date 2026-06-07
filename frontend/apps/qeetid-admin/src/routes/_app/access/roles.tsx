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
import { Link, createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2Icon, PlusIcon, RefreshCwIcon, ShieldCheckIcon } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { ListToolbar, SortHeader } from "@/components/data-table";
import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";
import { exportToCsv, exportToJson, type CsvColumn } from "@/lib/export";
import { useListView } from "@/lib/list-view";

export const Route = createFileRoute("/_app/access/roles")({ component: RolesPage });

type Permission = { id: string; key: string; description: string };
type Role = {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  is_system: boolean;
  created_at: string;
};

const roleCsvColumns: CsvColumn<Role>[] = [
  { header: "id", value: (r) => r.id },
  { header: "name", value: (r) => r.name },
  { header: "description", value: (r) => r.description },
  { header: "type", value: (r) => (r.is_system ? "system" : "custom") },
  { header: "created_at", value: (r) => r.created_at },
];

function RolesPage() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [editingRole, setEditingRole] = useState<Role | null>(null);

  const rolesQ = useQuery({
    queryKey: ["roles", tenantId],
    queryFn: () => api<{ items: Role[] }>(`/v1/tenants/${tenantId}/roles`),
    enabled: !!tenantId,
  });

  const permsQ = useQuery({
    queryKey: ["permissions"],
    queryFn: () => api<{ items: Permission[] }>("/v1/permissions"),
  });

  const items = rolesQ.data?.items ?? [];
  const lv = useListView(items, {
    searchFields: (r) => [r.name, r.description],
    filterFields: { type: (r) => (r.is_system ? "system" : "custom") },
    sortFields: { name: (r) => r.name, created: (r) => r.created_at },
  });
  const rows = lv.view;
  const denseCls = lv.density === "compact" ? "[&_td]:py-1.5 [&_th]:py-2" : undefined;

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="RBAC roles scoped to this tenant. Assign permissions per role; users get the union of permissions across all roles they hold."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => rolesQ.refetch()} disabled={rolesQ.isFetching}>
              <RefreshCwIcon className={rolesQ.isFetching ? "animate-spin" : ""} />
              Refresh
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
            searchPlaceholder="Search name or description…"
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
            columns={[
              { id: "description", label: "Description" },
              { id: "created", label: "Created" },
            ]}
            isColumnVisible={lv.isVisible}
            onToggleColumn={lv.toggleColumn}
            density={lv.density}
            onDensityChange={lv.setDensity}
            onExport={(fmt) =>
              fmt === "csv" ? exportToCsv("roles", rows, roleCsvColumns) : exportToJson("roles", rows)
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
            emptyTitle={lv.hasActiveFilters ? "No roles match your filters." : "No roles defined."}
            skeletonRows={3}
          >
            <Table className={denseCls}>
              <TableHeader>
                <TableRow>
                  <SortHeader columnKey="name" sort={lv.sort} onToggle={lv.toggleSort}>
                    Name
                  </SortHeader>
                  {lv.isVisible("description") && <TableHead>Description</TableHead>}
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
                    <TableCell className="font-medium">
                      <Link
                        to="/access/roles/$roleId"
                        params={{ roleId: r.id }}
                        className="hover:underline"
                      >
                        {r.name}
                      </Link>
                    </TableCell>
                    {lv.isVisible("description") && (
                      <TableCell className="text-muted-foreground">{r.description || "—"}</TableCell>
                    )}
                    <TableCell>
                      {r.is_system ? <Badge variant="muted">System</Badge> : <Badge variant="outline">Custom</Badge>}
                    </TableCell>
                    {lv.isVisible("created") && (
                      <TableCell><TimeSince value={r.created_at} /></TableCell>
                    )}
                    <TableCell className="text-right">
                      <Button variant="ghost" size="sm" onClick={() => setEditingRole(r)}>
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

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Platform permissions</CardTitle>
          <CardDescription>The global permission keys available for assignment to any role.</CardDescription>
        </CardHeader>
        <CardContent>
          {permsQ.isLoading ? (
            <div className="space-y-2">{[...Array(4)].map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}</div>
          ) : (
            <div className="grid gap-2 sm:grid-cols-2">
              {permsQ.data?.items?.map((p) => (
                <div key={p.id} className="flex items-start gap-2 rounded-md border p-3 text-sm">
                  <code className="text-xs font-medium">{p.key}</code>
                  <span className="text-muted-foreground">{p.description}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <CreateRoleSheet
        open={creating}
        onOpenChange={setCreating}
        tenantId={tenantId}
        onCreated={() => qc.invalidateQueries({ queryKey: ["roles"] })}
      />

      {editingRole && (
        <RolePermissionsSheet
          role={editingRole}
          permissions={permsQ.data?.items ?? []}
          onClose={() => setEditingRole(null)}
        />
      )}
    </div>
  );
}

type CreateRoleSheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  tenantId: string | null;
  onCreated: () => void;
};

function CreateRoleSheet({ open, onOpenChange, tenantId, onCreated }: CreateRoleSheetProps) {
  const createM = useMutation({
    mutationFn: (body: { name: string; description: string }) =>
      api<Role>(`/v1/tenants/${tenantId}/roles`, { method: "POST", body }),
    onSuccess: () => {
      onCreated();
      onOpenChange(false);
    },
    meta: { successMessage: "Role created" },
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
              name: String(data.get("name") ?? "").trim(),
              description: String(data.get("description") ?? "").trim(),
            });
          }}
        >
          <SheetHeader>
            <SheetTitle>New role</SheetTitle>
            <SheetDescription>Create a custom role for this tenant. Assign permissions afterwards.</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">Name</FieldLabel>
                <Input id="name" name="name" placeholder="editor" required minLength={1} maxLength={64} />
              </Field>
              <Field>
                <FieldLabel htmlFor="description">Description</FieldLabel>
                <Textarea id="description" name="description" rows={3} maxLength={500} />
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

type RolePermissionsSheetProps = {
  role: Role;
  permissions: Permission[];
  onClose: () => void;
};

function RolePermissionsSheet({ role, permissions, onClose }: RolePermissionsSheetProps) {
  // We don't have a "list permissions for a role" endpoint, so derive
  // membership by checking each permission with the rbac check endpoint
  // is impractical. Instead, when toggled we just call grant/revoke and
  // optimistically reflect state.
  const [granted, setGranted] = useState<Set<string>>(new Set());

  // Load existing grants via per-permission "effective" check is heavy.
  // For now we leave the panel as a write-only grant/revoke UI; toggling
  // a row immediately hits the API.
  const grantM = useMutation({
    mutationFn: (permId: string) => api<void>(`/v1/roles/${role.id}/permissions/${permId}`, { method: "POST" }),
    meta: { successMessage: "Permission granted" },
  });
  const revokeM = useMutation({
    mutationFn: (permId: string) => api<void>(`/v1/roles/${role.id}/permissions/${permId}`, { method: "DELETE" }),
    meta: { successMessage: "Permission revoked" },
  });

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <SheetHeader>
          <SheetTitle>Permissions — {role.name}</SheetTitle>
          <SheetDescription>
            Toggle to grant or revoke. Changes apply immediately to every user holding this role.
          </SheetDescription>
        </SheetHeader>
        <div className="flex-1 overflow-y-auto p-4">
          <FieldGroup>
            {permissions.map((p) => {
              const isGranted = granted.has(p.id);
              return (
                <label
                  key={p.id}
                  className="flex items-start gap-3 rounded-md border p-3 text-sm hover:bg-muted/40"
                >
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={isGranted}
                    disabled={grantM.isPending || revokeM.isPending}
                    onChange={async (e) => {
                      if (e.target.checked) {
                        await grantM.mutateAsync(p.id);
                        setGranted((s) => new Set(s).add(p.id));
                      } else {
                        await revokeM.mutateAsync(p.id);
                        setGranted((s) => {
                          const n = new Set(s);
                          n.delete(p.id);
                          return n;
                        });
                      }
                    }}
                  />
                  <div className="flex-1">
                    <code className="text-xs font-medium">{p.key}</code>
                    <p className="text-xs text-muted-foreground">{p.description}</p>
                  </div>
                </label>
              );
            })}
          </FieldGroup>
        </div>
        <SheetFooter className="flex-row justify-end gap-2 border-t">
          <Button variant="outline" onClick={onClose}>Close</Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
