import { Card, CardContent, CardDescription, CardHeader, CardTitle, Skeleton } from "@qeetrix/ui";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { ShieldCheckIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/api";

export const Route = createFileRoute("/_app/access/permissions")({
  component: PermissionsPage,
});

type Permission = { id: string; key: string; description: string };

function PermissionsPage() {
  const { t } = useTranslation("rbac");
  const permsQ = useQuery({
    queryKey: ["permissions"],
    queryFn: () => api<{ items: Permission[] }>("/v1/permissions"),
  });

  // Group permissions by resource prefix (e.g. "user.read" → "user").
  const grouped = (permsQ.data?.items ?? []).reduce<Record<string, Permission[]>>((acc, p) => {
    const resource = p.key.split(".")[0];
    (acc[resource] ??= []).push(p);
    return acc;
  }, {});

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description={t("permissions.description")} />

      {permsQ.isLoading ? (
        <Card>
          <CardContent className="p-6 space-y-3">
            {[...Array(6)].map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </CardContent>
        </Card>
      ) : permsQ.isError ? (
        <Card>
          <CardContent className="p-6 text-sm text-destructive">
            {(permsQ.error as Error).message}
          </CardContent>
        </Card>
      ) : !permsQ.data?.items?.length ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-2 p-10 text-center">
            <ShieldCheckIcon className="size-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">{t("permissions.empty")}</p>
          </CardContent>
        </Card>
      ) : (
        Object.entries(grouped).map(([resource, perms]) => (
          <Card key={resource}>
            <CardHeader>
              <CardTitle className="text-base capitalize">{resource}</CardTitle>
              <CardDescription>{t("permissions.count", { count: perms.length })}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-2 sm:grid-cols-2">
                {perms.map((p) => (
                  <div key={p.id} className="flex flex-col gap-1 rounded-md border p-3">
                    <code className="text-xs font-medium">{p.key}</code>
                    <span className="text-xs text-muted-foreground">
                      {p.description || t("permissions.noDescription")}
                    </span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ))
      )}
    </div>
  );
}
