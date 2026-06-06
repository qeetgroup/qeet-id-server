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
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Building2Icon,
  Loader2Icon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  Trash2Icon,
} from "lucide-react";
import { useState } from "react";

import { ListToolbar, SortHeader } from "@/components/data-table";
import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { tokenStore } from "@/lib/api";
import { switchToTenant } from "@/lib/auth";
import { exportToCsv, exportToJson, type CsvColumn } from "@/lib/export";
import { useListView } from "@/lib/list-view";

export const Route = createFileRoute("/_app/organizations/tenants")({ component: TenantsPage });

type Tenant = {
  id: string;
  slug: string;
  name: string;
  status: "active" | "suspended" | "deleted";
  plan: string;
  region: string;
  created_at: string;
};

const tenantCsvColumns: CsvColumn<Tenant>[] = [
  { header: "id", value: (t) => t.id },
  { header: "name", value: (t) => t.name },
  { header: "slug", value: (t) => t.slug },
  { header: "plan", value: (t) => t.plan },
  { header: "region", value: (t) => t.region },
  { header: "status", value: (t) => t.status },
  { header: "created_at", value: (t) => t.created_at },
];

function TenantsPage() {
  const qc = useQueryClient();
  const currentTenantId = tokenStore.getTenantId();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Tenant | null>(null);
  const [confirmingDelete, setConfirmingDelete] = useState<string | null>(null);

  const listQ = useQuery({
    queryKey: ["tenants"],
    queryFn: () => api<{ items: Tenant[] }>("/v1/tenants"),
  });

  const items = listQ.data?.items ?? [];
  const lv = useListView(items, {
    searchFields: (t) => [t.name, t.slug, t.region],
    filterFields: { status: (t) => t.status, plan: (t) => t.plan },
    sortFields: { name: (t) => t.name, plan: (t) => t.plan, created: (t) => t.created_at },
  });
  const rows = lv.view;
  const denseCls = lv.density === "compact" ? "[&_td]:py-1.5 [&_th]:py-2" : undefined;

  const deleteM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/tenants/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      setConfirmingDelete(null);
      qc.invalidateQueries({ queryKey: ["tenants"] });
    },
    meta: { successMessage: "Tenant deleted" },
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Every tenant your account has access to. Click a tenant to switch into it, or create a new one — you become its owner automatically."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => listQ.refetch()} disabled={listQ.isFetching}>
              <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> New tenant
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Tenants</CardTitle>
          <CardDescription>
            {rows.length} of {items.length} tenant{items.length === 1 ? "" : "s"}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <ListToolbar
            search={lv.search}
            onSearchChange={lv.setSearch}
            searchPlaceholder="Search name, slug, region…"
            filters={[
              {
                id: "status",
                label: "Status",
                value: lv.filters.status ?? "",
                options: [
                  { label: "Active", value: "active" },
                  { label: "Suspended", value: "suspended" },
                  { label: "Deleted", value: "deleted" },
                ],
                onChange: (v) => lv.setFilter("status", v),
              },
              {
                id: "plan",
                label: "Plan",
                value: lv.filters.plan ?? "",
                options: [
                  { label: "Free", value: "free" },
                  { label: "Pro", value: "pro" },
                  { label: "Enterprise", value: "enterprise" },
                ],
                onChange: (v) => lv.setFilter("plan", v),
              },
            ]}
            columns={[
              { id: "slug", label: "Slug" },
              { id: "plan", label: "Plan" },
              { id: "region", label: "Region" },
              { id: "created", label: "Created" },
            ]}
            isColumnVisible={lv.isVisible}
            onToggleColumn={lv.toggleColumn}
            density={lv.density}
            onDensityChange={lv.setDensity}
            onExport={(fmt) =>
              fmt === "csv" ? exportToCsv("tenants", rows, tenantCsvColumns) : exportToJson("tenants", rows)
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
            emptyIcon={Building2Icon}
            emptyTitle={lv.hasActiveFilters ? "No tenants match your filters." : "No tenants yet."}
            skeletonRows={3}
          >
            <Table className={denseCls}>
              <TableHeader>
                <TableRow>
                  <SortHeader columnKey="name" sort={lv.sort} onToggle={lv.toggleSort}>
                    Name
                  </SortHeader>
                  {lv.isVisible("slug") && <TableHead>Slug</TableHead>}
                  {lv.isVisible("plan") && (
                    <SortHeader columnKey="plan" sort={lv.sort} onToggle={lv.toggleSort}>
                      Plan
                    </SortHeader>
                  )}
                  {lv.isVisible("region") && <TableHead>Region</TableHead>}
                  <TableHead>Status</TableHead>
                  {lv.isVisible("created") && (
                    <SortHeader columnKey="created" sort={lv.sort} onToggle={lv.toggleSort}>
                      Created
                    </SortHeader>
                  )}
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="font-medium">
                      {t.name}
                      {t.id === currentTenantId && (
                        <Badge variant="muted" className="ml-2">
                          Current
                        </Badge>
                      )}
                    </TableCell>
                    {lv.isVisible("slug") && (
                      <TableCell className="font-mono text-xs text-muted-foreground">{t.slug}</TableCell>
                    )}
                    {lv.isVisible("plan") && (
                      <TableCell><Badge variant="muted">{t.plan}</Badge></TableCell>
                    )}
                    {lv.isVisible("region") && (
                      <TableCell className="text-muted-foreground">{t.region}</TableCell>
                    )}
                    <TableCell><StatusPill status={t.status} /></TableCell>
                    {lv.isVisible("created") && (
                      <TableCell><TimeSince value={t.created_at} /></TableCell>
                    )}
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={t.id === currentTenantId}
                          onClick={() => void switchToTenant(t.id)}
                        >
                          Switch
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label="Edit tenant"
                          onClick={() => setEditing(t)}
                        >
                          <PencilIcon />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label="Delete tenant"
                          disabled={t.id === currentTenantId}
                          title={
                            t.id === currentTenantId
                              ? "Switch to another tenant before deleting this one"
                              : "Delete tenant"
                          }
                          onClick={() => setConfirmingDelete(t.id)}
                        >
                          <Trash2Icon className="text-destructive" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      <CreateTenantSheet
        open={creating}
        onOpenChange={setCreating}
        onCreated={() => qc.invalidateQueries({ queryKey: ["tenants"] })}
      />

      <EditTenantSheet
        tenant={editing}
        onOpenChange={(o) => !o && setEditing(null)}
        onSaved={() => {
          setEditing(null);
          qc.invalidateQueries({ queryKey: ["tenants"] });
        }}
      />

      <AlertDialog
        open={!!confirmingDelete}
        onOpenChange={(o) => {
          if (!o && !deleteM.isPending) setConfirmingDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete this tenant?</AlertDialogTitle>
            <AlertDialogDescription>
              {(() => {
                const target = listQ.data?.items?.find((t) => t.id === confirmingDelete);
                return target ? (
                  <>
                    This soft-deletes <span className="font-medium text-foreground">{target.name}</span>{" "}
                    (<span className="font-mono text-xs">{target.slug}</span>). Audit history is
                    preserved, but you won&apos;t be able to undo this from the UI.
                  </>
                ) : (
                  "This soft-deletes the tenant. Audit history is preserved."
                );
              })()}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteM.isPending}>Cancel</AlertDialogCancel>
            <Button
              variant="destructive"
              disabled={deleteM.isPending}
              onClick={() => confirmingDelete && deleteM.mutate(confirmingDelete)}
            >
              {deleteM.isPending && <Loader2Icon className="animate-spin" />}
              {deleteM.isPending ? "Deleting…" : "Delete"}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

type CreateTenantSheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onCreated: () => void;
};

type CreateTenantResponse = {
  tenant: Tenant;
  tenant_id: string;
  access_token?: string;
  refresh_token?: string;
};

function CreateTenantSheet({ open, onOpenChange, onCreated }: CreateTenantSheetProps) {
  const [plan, setPlan] = useState("free");
  const createM = useMutation({
    mutationFn: (body: { slug: string; name: string; plan: string; region: string }) =>
      api<CreateTenantResponse>("/v1/tenants", { method: "POST", body }),
    onSuccess: (res) => {
      onCreated();
      onOpenChange(false);
      // Now owner of this workspace; persist the scoped token and switch in.
      if (res.access_token && res.refresh_token) {
        tokenStore.set(res.access_token);
        tokenStore.setRefresh(res.refresh_token);
      }
      tokenStore.setTenantId(res.tenant_id);
      window.location.assign("/");
    },
    meta: { successMessage: "Workspace created" },
  });

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <form
          className="flex h-full flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            const data = new FormData(e.currentTarget);
            createM.mutate({
              slug: String(data.get("slug") ?? "").trim(),
              name: String(data.get("name") ?? "").trim(),
              plan,
              region: String(data.get("region") ?? "us-east-1").trim(),
            });
          }}
        >
          <SheetHeader>
            <SheetTitle>New workspace</SheetTitle>
            <SheetDescription>
              You&apos;ll become the owner of this workspace and switch into it once it&apos;s created.
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">Name</FieldLabel>
                <Input id="name" name="name" placeholder="Acme Corp" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="slug">Slug</FieldLabel>
                <Input id="slug" name="slug" pattern="[a-z0-9-]+" minLength={2} maxLength={64} placeholder="acme" required />
                <FieldDescription>Lowercase letters, numbers, dashes. Used in URLs.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel>Plan</FieldLabel>
                <Select value={plan} onValueChange={(v) => v && setPlan(v)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="free">Free</SelectItem>
                    <SelectItem value="pro">Pro</SelectItem>
                    <SelectItem value="enterprise">Enterprise</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              <Field>
                <FieldLabel htmlFor="region">Region</FieldLabel>
                <Input id="region" name="region" defaultValue="us-east-1" />
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

type EditTenantSheetProps = {
  tenant: Tenant | null;
  onOpenChange: (o: boolean) => void;
  onSaved: () => void;
};

type UpdateBody = {
  name?: string;
  status?: "active" | "suspended";
  plan?: "free" | "pro" | "enterprise";
  region?: string;
};

function EditTenantSheet({ tenant, onOpenChange, onSaved }: EditTenantSheetProps) {
  const [plan, setPlan] = useState<string>(tenant?.plan ?? "free");
  const [status, setStatus] = useState<string>(tenant?.status === "suspended" ? "suspended" : "active");

  // Reset selects when the editing target changes — without this the sheet
  // would keep the previous tenant's plan/status on the second open.
  const lastId = useState<string | null>(null);
  if (tenant && tenant.id !== lastId[0]) {
    lastId[1](tenant.id);
    setPlan(tenant.plan);
    setStatus(tenant.status === "suspended" ? "suspended" : "active");
  }

  const updateM = useMutation({
    mutationFn: (body: UpdateBody) =>
      api<Tenant>(`/v1/tenants/${tenant!.id}`, { method: "PATCH", body }),
    onSuccess: onSaved,
    meta: { successMessage: "Tenant updated" },
  });

  return (
    <Sheet open={!!tenant} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        {tenant && (
          <form
            className="flex h-full flex-col"
            onSubmit={(e) => {
              e.preventDefault();
              const data = new FormData(e.currentTarget);
              updateM.mutate({
                name: String(data.get("name") ?? "").trim(),
                region: String(data.get("region") ?? "").trim(),
                plan: plan as UpdateBody["plan"],
                status: status as UpdateBody["status"],
              });
            }}
          >
            <SheetHeader>
              <SheetTitle>Edit tenant</SheetTitle>
              <SheetDescription>
                Slug can't be changed once a tenant is created.
              </SheetDescription>
            </SheetHeader>
            <div className="flex-1 overflow-y-auto p-4">
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="edit-name">Name</FieldLabel>
                  <Input
                    id="edit-name"
                    name="name"
                    defaultValue={tenant.name}
                    required
                    minLength={1}
                    maxLength={200}
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="edit-slug">Slug</FieldLabel>
                  <Input id="edit-slug" value={tenant.slug} readOnly disabled />
                  <FieldDescription>Immutable after creation.</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel>Plan</FieldLabel>
                  <Select value={plan} onValueChange={(v) => v && setPlan(v)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="free">Free</SelectItem>
                      <SelectItem value="pro">Pro</SelectItem>
                      <SelectItem value="enterprise">Enterprise</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                <Field>
                  <FieldLabel>Status</FieldLabel>
                  <Select value={status} onValueChange={(v) => v && setStatus(v)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="active">Active</SelectItem>
                      <SelectItem value="suspended">Suspended</SelectItem>
                    </SelectContent>
                  </Select>
                  <FieldDescription>
                    Use the Delete action to soft-delete a tenant.
                  </FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="edit-region">Region</FieldLabel>
                  <Input
                    id="edit-region"
                    name="region"
                    defaultValue={tenant.region}
                    maxLength={64}
                  />
                </Field>
                {updateM.error && (
                  <Field>
                    <FieldError>{(updateM.error as ApiError).message}</FieldError>
                  </Field>
                )}
              </FieldGroup>
            </div>
            <SheetFooter className="flex-row justify-end gap-2 border-t">
              <SheetClose render={<Button type="button" variant="outline" />}>Cancel</SheetClose>
              <Button type="submit" disabled={updateM.isPending}>
                {updateM.isPending && <Loader2Icon className="animate-spin" />}
                {updateM.isPending ? "Saving…" : "Save changes"}
              </Button>
            </SheetFooter>
          </form>
        )}
      </SheetContent>
    </Sheet>
  );
}
