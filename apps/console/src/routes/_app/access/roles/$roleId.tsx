import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeftIcon, ShieldCheckIcon, Trash2Icon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/access/roles/$roleId")({
  component: RoleDetailPage,
});

type Role = {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  is_system: boolean;
  created_at: string;
};

type Permission = { id: string; key: string; description: string };

function RoleDetailPage() {
  const { t } = useTranslation("rbac");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const { roleId } = Route.useParams();
  const tenantId = useTenantId();
  const qc = useQueryClient();

  // We don't have a single-role GET endpoint today, so we read the list
  // and find by id. Cached at the same key as the list view so the
  // navigation transition is instant.
  const rolesQ = useQuery({
    queryKey: ["roles", tenantId],
    queryFn: () => api<{ items: Role[] }>(`/v1/tenants/${tenantId}/roles`),
    enabled: !!tenantId,
  });
  const role = rolesQ.data?.items.find((r) => r.id === roleId);

  // Full permission catalogue + the role's own permissions, intersected
  // client-side.
  const permsQ = useQuery({
    queryKey: ["permissions"],
    queryFn: () => api<{ items: Permission[] }>("/v1/permissions"),
  });
  const rolePermsQ = useQuery({
    queryKey: ["role-permissions", roleId],
    queryFn: () => api<{ items: Permission[] }>(`/v1/roles/${roleId}/permissions`),
  });

  const revokeM = useMutation({
    mutationFn: (permId: string) =>
      api<void>(`/v1/roles/${roleId}/permissions/${permId}`, {
        method: "DELETE",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["role-permissions", roleId] }),
    meta: { successMessage: "Permission revoked" },
  });

  const grantM = useMutation({
    mutationFn: (permId: string) =>
      api<void>(`/v1/roles/${roleId}/permissions/${permId}`, {
        method: "POST",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["role-permissions", roleId] }),
    meta: { successMessage: "Permission granted" },
  });

  const heldIds = new Set(rolePermsQ.data?.items.map((p) => p.id) ?? []);
  const available = (permsQ.data?.items ?? []).filter((p) => !heldIds.has(p.id));

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {confirmDialog}
      <Link
        to="/access/roles"
        className="inline-flex w-fit items-center gap-1 text-sm text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
      >
        <ArrowLeftIcon className="size-3" /> {t("roles.detail.backLink")}
      </Link>

      <Card>
        <CardHeader>
          {rolesQ.isLoading ? (
            <Skeleton className="h-5 w-48" />
          ) : role ? (
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <CardTitle className="flex items-center gap-2 text-base">
                  <ShieldCheckIcon className="size-4 text-muted-foreground" />
                  {role.name}
                  {role.is_system && <Badge variant="muted">{t("roles.detail.systemBadge")}</Badge>}
                </CardTitle>
                <CardDescription>
                  {role.description || t("roles.detail.noDescription")}
                </CardDescription>
              </div>
              <TimeSince value={role.created_at} className="text-xs" />
            </div>
          ) : (
            <CardTitle className="text-base text-destructive">
              {t("roles.detail.notFound")}
            </CardTitle>
          )}
        </CardHeader>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("roles.detail.granted.title")}</CardTitle>
          <CardDescription>
            {t("roles.detail.granted.count", {
              count: rolePermsQ.data?.items?.length ?? 0,
            })}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={rolePermsQ.isLoading}
            isError={rolePermsQ.isError}
            error={rolePermsQ.error}
            isEmpty={!rolePermsQ.data?.items?.length}
            emptyIcon={ShieldCheckIcon}
            emptyTitle={t("roles.detail.granted.empty")}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("roles.detail.granted.colKey")}</TableHead>
                  <TableHead>{t("roles.detail.granted.colDescription")}</TableHead>
                  <TableHead className="text-right">
                    {t("roles.detail.granted.colActions")}
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rolePermsQ.data?.items?.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell className="font-mono text-xs">{p.key}</TableCell>
                    <TableCell className="text-muted-foreground">{p.description}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={role?.is_system || revokeM.isPending}
                        onClick={() =>
                          openConfirm({
                            title: t("roles.detail.granted.confirmTitle", {
                              key: p.key,
                            }),
                            variant: "destructive",
                            confirmLabel: t("roles.detail.granted.confirmLabel"),
                            onConfirm: () => revokeM.mutate(p.id),
                          })
                        }
                      >
                        <Trash2Icon /> {t("roles.detail.granted.revokeBtn")}
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
          <CardTitle className="text-base">{t("roles.detail.available.title")}</CardTitle>
          <CardDescription>{t("roles.detail.available.description")}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={permsQ.isLoading}
            isError={permsQ.isError}
            error={permsQ.error}
            isEmpty={available.length === 0}
            emptyIcon={ShieldCheckIcon}
            emptyTitle={t("roles.detail.available.empty")}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("roles.detail.available.colKey")}</TableHead>
                  <TableHead>{t("roles.detail.available.colDescription")}</TableHead>
                  <TableHead className="text-right">
                    {t("roles.detail.available.colActions")}
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {available.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell className="font-mono text-xs">{p.key}</TableCell>
                    <TableCell className="text-muted-foreground">{p.description}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={role?.is_system || grantM.isPending}
                        onClick={() => grantM.mutate(p.id)}
                      >
                        {t("roles.detail.available.grantBtn")}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>
    </div>
  );
}
