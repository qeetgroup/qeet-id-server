import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetrix/ui";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { BoxesIcon, KeyRoundIcon, ShieldCheckIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/api";

export const Route = createFileRoute("/_app/access/resources")({
  component: ResourcesPage,
});

type Permission = { id: string; key: string; description: string };

type Resource = {
  name: string;
  actions: string[];
  count: number;
};

// A resource is the prefix of a permission key ("users.read" → "users"); the
// action is everything after the first dot.
function groupResources(perms: Permission[]): Resource[] {
  const map = new Map<string, Set<string>>();
  for (const p of perms) {
    const dot = p.key.indexOf(".");
    const resource = dot === -1 ? p.key : p.key.slice(0, dot);
    const action = dot === -1 ? "*" : p.key.slice(dot + 1);
    if (!map.has(resource)) map.set(resource, new Set());
    map.get(resource)!.add(action);
  }
  return [...map.entries()]
    .map(([name, actions]) => ({
      name,
      actions: [...actions].sort(),
      count: actions.size,
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function ResourcesPage() {
  const { t } = useTranslation("rbac");
  const permsQ = useQuery({
    queryKey: ["permissions"],
    queryFn: () => api<{ items: Permission[] }>("/v1/permissions"),
  });

  const perms = permsQ.data?.items ?? [];
  const resources = groupResources(perms);
  const totalActions = resources.reduce((s, r) => s + r.count, 0);

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description={t("resources.description")} />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>{t("resources.stats.resources")}</CardDescription>
            <BoxesIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">{resources.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>{t("resources.stats.actions")}</CardDescription>
            <ShieldCheckIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">{totalActions}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>{t("resources.stats.keys")}</CardDescription>
            <KeyRoundIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">{perms.length}</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t("resources.catalogue.title")}</CardTitle>
          <CardDescription>{t("resources.catalogue.description")}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={permsQ.isLoading}
            isError={permsQ.isError}
            error={permsQ.error}
            isEmpty={resources.length === 0}
            emptyIcon={BoxesIcon}
            emptyTitle={t("resources.catalogue.empty")}
            skeletonRows={4}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("resources.columns.resource")}</TableHead>
                  <TableHead>{t("resources.columns.actions")}</TableHead>
                  <TableHead className="text-right">{t("resources.columns.count")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {resources.map((r) => (
                  <TableRow key={r.name}>
                    <TableCell className="font-medium capitalize">{r.name}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {r.actions.map((a) => (
                          <Badge key={a} variant="muted" className="font-mono text-xs">
                            {a}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-right text-sm text-muted-foreground">
                      {r.count}
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
