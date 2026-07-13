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
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  Building2Icon,
  Loader2Icon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  Trash2Icon,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { ListToolbar, SortHeader } from "@/components/data-table";
import { PageHeader } from "@/components/page-header";
import { type ApiError, api, tokenStore } from "@/lib/api";
import { switchToTenant } from "@/lib/auth";
import { type CsvColumn, exportToCsv, exportToJson } from "@/lib/export";
import { useListView } from "@/lib/list-view";

export const Route = createFileRoute("/_app/organizations/tenants")({
  component: TenantsPage,
});

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
  { header: "id", value: (row) => row.id },
  { header: "name", value: (row) => row.name },
  { header: "slug", value: (row) => row.slug },
  { header: "plan", value: (row) => row.plan },
  { header: "region", value: (row) => row.region },
  { header: "status", value: (row) => row.status },
  { header: "created_at", value: (row) => row.created_at },
];

function TenantsPage() {
  const { t } = useTranslation("organizations");
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
    searchFields: (row) => [row.name, row.slug, row.region],
    filterFields: { status: (row) => row.status, plan: (row) => row.plan },
    sortFields: {
      name: (row) => row.name,
      plan: (row) => row.plan,
      created: (row) => row.created_at,
    },
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
        description={t("tenants.description")}
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => listQ.refetch()}
              disabled={listQ.isFetching}
            >
              <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
              {t("tenants.refresh")}
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> {t("tenants.new")}
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("tenants.list.title")}</CardTitle>
          <CardDescription>
            {t("tenants.list.count", {
              shown: rows.length,
              total: items.length,
            })}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <ListToolbar
            search={lv.search}
            onSearchChange={lv.setSearch}
            searchPlaceholder={t("tenants.list.searchPlaceholder")}
            filters={[
              {
                id: "status",
                label: t("tenants.filters.status.label"),
                value: lv.filters.status ?? "",
                options: [
                  {
                    label: t("tenants.filters.status.active"),
                    value: "active",
                  },
                  {
                    label: t("tenants.filters.status.suspended"),
                    value: "suspended",
                  },
                  {
                    label: t("tenants.filters.status.deleted"),
                    value: "deleted",
                  },
                ],
                onChange: (v) => lv.setFilter("status", v),
              },
              {
                id: "plan",
                label: t("tenants.filters.plan.label"),
                value: lv.filters.plan ?? "",
                options: [
                  { label: t("tenants.filters.plan.free"), value: "free" },
                  {
                    label: t("tenants.filters.plan.starter"),
                    value: "starter",
                  },
                  { label: t("tenants.filters.plan.pro"), value: "pro" },
                  {
                    label: t("tenants.filters.plan.enterprise"),
                    value: "enterprise",
                  },
                ],
                onChange: (v) => lv.setFilter("plan", v),
              },
            ]}
            columns={[
              { id: "slug", label: t("tenants.columns.slug") },
              { id: "plan", label: t("tenants.columns.plan") },
              { id: "region", label: t("tenants.columns.region") },
              { id: "created", label: t("tenants.columns.created") },
            ]}
            isColumnVisible={lv.isVisible}
            onToggleColumn={lv.toggleColumn}
            density={lv.density}
            onDensityChange={lv.setDensity}
            onExport={(fmt) =>
              fmt === "csv"
                ? exportToCsv("tenants", rows, tenantCsvColumns)
                : exportToJson("tenants", rows)
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
            emptyTitle={
              lv.hasActiveFilters ? t("tenants.list.emptyFiltered") : t("tenants.list.empty")
            }
            skeletonRows={3}
          >
            <Table className={denseCls}>
              <TableHeader>
                <TableRow>
                  <SortHeader columnKey="name" sort={lv.sort} onToggle={lv.toggleSort}>
                    {t("tenants.columns.name")}
                  </SortHeader>
                  {lv.isVisible("slug") && <TableHead>{t("tenants.columns.slug")}</TableHead>}
                  {lv.isVisible("plan") && (
                    <SortHeader columnKey="plan" sort={lv.sort} onToggle={lv.toggleSort}>
                      {t("tenants.columns.plan")}
                    </SortHeader>
                  )}
                  {lv.isVisible("region") && <TableHead>{t("tenants.columns.region")}</TableHead>}
                  <TableHead>{t("tenants.columns.status")}</TableHead>
                  {lv.isVisible("created") && (
                    <SortHeader columnKey="created" sort={lv.sort} onToggle={lv.toggleSort}>
                      {t("tenants.columns.created")}
                    </SortHeader>
                  )}
                  <TableHead className="text-right">{t("tenants.columns.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell className="font-medium">
                      {row.name}
                      {row.id === currentTenantId && (
                        <Badge variant="muted" className="ml-2">
                          {t("tenants.table.current")}
                        </Badge>
                      )}
                    </TableCell>
                    {lv.isVisible("slug") && (
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {row.slug}
                      </TableCell>
                    )}
                    {lv.isVisible("plan") && (
                      <TableCell>
                        <Badge variant="muted">{row.plan}</Badge>
                      </TableCell>
                    )}
                    {lv.isVisible("region") && (
                      <TableCell className="text-muted-foreground">{row.region}</TableCell>
                    )}
                    <TableCell>
                      <StatusPill status={row.status} />
                    </TableCell>
                    {lv.isVisible("created") && (
                      <TableCell>
                        <TimeSince value={row.created_at} />
                      </TableCell>
                    )}
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={row.id === currentTenantId}
                          onClick={() => void switchToTenant(row.id)}
                        >
                          {t("tenants.table.switch")}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={t("tenants.table.editLabel")}
                          onClick={() => setEditing(row)}
                        >
                          <PencilIcon />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={t("tenants.table.deleteLabel")}
                          disabled={row.id === currentTenantId}
                          title={
                            row.id === currentTenantId
                              ? t("tenants.table.deleteSelfTitle")
                              : t("tenants.table.deleteLabel")
                          }
                          onClick={() => setConfirmingDelete(row.id)}
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
            <AlertDialogTitle>{t("tenants.delete.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {(() => {
                const target = listQ.data?.items?.find((item) => item.id === confirmingDelete);
                return target ? (
                  <>
                    {t("tenants.delete.descriptionPrefix")}{" "}
                    <span className="font-medium text-foreground">{target.name}</span> (
                    <span className="font-mono text-xs">{target.slug}</span>)
                    {t("tenants.delete.descriptionSuffix")}
                  </>
                ) : (
                  t("tenants.delete.descriptionFallback")
                );
              })()}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteM.isPending}>
              {t("tenants.delete.cancel")}
            </AlertDialogCancel>
            <Button
              variant="destructive"
              disabled={deleteM.isPending}
              onClick={() => confirmingDelete && deleteM.mutate(confirmingDelete)}
            >
              {deleteM.isPending && <Loader2Icon className="animate-spin" />}
              {deleteM.isPending ? t("tenants.delete.deleting") : t("tenants.delete.delete")}
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
  const { t } = useTranslation("organizations");
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
            <SheetTitle>{t("tenants.create.title")}</SheetTitle>
            <SheetDescription>{t("tenants.create.description")}</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">{t("tenants.create.name")}</FieldLabel>
                <Input id="name" name="name" placeholder="Acme Corp" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="slug">{t("tenants.create.slug")}</FieldLabel>
                <Input
                  id="slug"
                  name="slug"
                  pattern="[a-z0-9-]+"
                  minLength={2}
                  maxLength={64}
                  placeholder="acme"
                  required
                />
                <FieldDescription>{t("tenants.create.slugHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel>{t("tenants.create.plan")}</FieldLabel>
                <Select value={plan} onValueChange={(v) => v && setPlan(v)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="free">{t("tenants.filters.plan.free")}</SelectItem>
                    <SelectItem value="starter">{t("tenants.filters.plan.starter")}</SelectItem>
                    <SelectItem value="pro">{t("tenants.filters.plan.pro")}</SelectItem>
                    <SelectItem value="enterprise">
                      {t("tenants.filters.plan.enterprise")}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              <Field>
                <FieldLabel htmlFor="region">{t("tenants.create.region")}</FieldLabel>
                <Input id="region" name="region" defaultValue="us-east-1" />
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
              {t("tenants.create.cancel")}
            </SheetClose>
            <Button type="submit" disabled={createM.isPending}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? t("tenants.create.submitting") : t("tenants.create.submit")}
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
  plan?: "free" | "starter" | "pro" | "enterprise";
  region?: string;
};

function EditTenantSheet({ tenant, onOpenChange, onSaved }: EditTenantSheetProps) {
  const { t } = useTranslation("organizations");
  const [plan, setPlan] = useState<string>(tenant?.plan ?? "free");
  const [status, setStatus] = useState<string>(
    tenant?.status === "suspended" ? "suspended" : "active",
  );

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
              <SheetTitle>{t("tenants.edit.title")}</SheetTitle>
              <SheetDescription>{t("tenants.edit.description")}</SheetDescription>
            </SheetHeader>
            <div className="flex-1 overflow-y-auto p-4">
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="edit-name">{t("tenants.edit.name")}</FieldLabel>
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
                  <FieldLabel htmlFor="edit-slug">{t("tenants.edit.slug")}</FieldLabel>
                  <Input id="edit-slug" value={tenant.slug} readOnly disabled />
                  <FieldDescription>{t("tenants.edit.slugHelp")}</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel>{t("tenants.edit.plan")}</FieldLabel>
                  <Select value={plan} onValueChange={(v) => v && setPlan(v)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="free">{t("tenants.filters.plan.free")}</SelectItem>
                      <SelectItem value="starter">{t("tenants.filters.plan.starter")}</SelectItem>
                      <SelectItem value="pro">{t("tenants.filters.plan.pro")}</SelectItem>
                      <SelectItem value="enterprise">
                        {t("tenants.filters.plan.enterprise")}
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                <Field>
                  <FieldLabel>{t("tenants.edit.status")}</FieldLabel>
                  <Select value={status} onValueChange={(v) => v && setStatus(v)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="active">{t("tenants.edit.statusActive")}</SelectItem>
                      <SelectItem value="suspended">{t("tenants.edit.statusSuspended")}</SelectItem>
                    </SelectContent>
                  </Select>
                  <FieldDescription>{t("tenants.edit.statusHelp")}</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="edit-region">{t("tenants.edit.region")}</FieldLabel>
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
              <SheetClose render={<Button type="button" variant="outline" />}>
                {t("tenants.edit.cancel")}
              </SheetClose>
              <Button type="submit" disabled={updateM.isPending}>
                {updateM.isPending && <Loader2Icon className="animate-spin" />}
                {updateM.isPending ? t("tenants.edit.saving") : t("tenants.edit.save")}
              </Button>
            </SheetFooter>
          </form>
        )}
      </SheetContent>
    </Sheet>
  );
}
