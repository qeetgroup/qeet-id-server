import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Input,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { AlertTriangleIcon, KeyRoundIcon } from "lucide-react";
import { useMemo, useState } from "react";

import { PageHeader } from "@/components/page-header";
import { groupPermissionsByResource, usePermissions, wildcardPermissions } from "@/lib/authz-rbac";

export const Route = createFileRoute("/_app/authorization/permissions")({
  component: PermissionsPage,
});

function PermissionsPage() {
  const permsQ = usePermissions();
  const [q, setQ] = useState("");
  const all = permsQ.data?.items ?? [];

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return all;
    return all.filter(
      (p) => p.key.toLowerCase().includes(needle) || p.description.toLowerCase().includes(needle),
    );
  }, [all, q]);

  const groups = useMemo(() => groupPermissionsByResource(filtered), [filtered]);
  const wildcards = useMemo(() => wildcardPermissions(all), [all]);

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="The platform permission catalogue, grouped by resource. Permissions use resource.action keys." />

      {wildcards.length > 0 && (
        <Card className="border-amber-500/40 bg-amber-500/5">
          <CardContent className="flex items-center gap-3 py-3">
            <AlertTriangleIcon
              className="size-4 shrink-0 text-amber-600 dark:text-amber-400"
              aria-hidden
            />
            <p className="text-sm text-muted-foreground">
              <span className="font-medium text-foreground">{wildcards.length}</span> wildcard
              permission
              {wildcards.length === 1 ? "" : "s"} detected — wildcards grant broad access; prefer
              explicit keys.
            </p>
          </CardContent>
        </Card>
      )}

      <Input
        placeholder="Search permissions…"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        aria-label="Search permissions"
        className="max-w-sm"
      />

      <DataState
        isLoading={permsQ.isLoading}
        isError={permsQ.isError}
        error={permsQ.error}
        isEmpty={filtered.length === 0}
        emptyIcon={KeyRoundIcon}
        emptyTitle={q ? "No permissions match your search" : "No permissions"}
        skeletonRows={4}
      >
        <div className="grid gap-4 lg:grid-cols-2">
          {[...groups.entries()].map(([resource, perms]) => (
            <Card key={resource}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <span className="font-mono">{resource}</span>
                  <Badge variant="muted">{perms.length}</Badge>
                </CardTitle>
                <CardDescription>Actions available on {resource} resources.</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-2">
                {perms.map((p) => (
                  <div
                    key={p.id}
                    className="flex items-start gap-2 rounded-md border p-2.5 text-sm"
                  >
                    <code className="shrink-0 text-xs font-medium">{p.key}</code>
                    {p.key.includes("*") && (
                      <Badge variant="warning" className="text-[10px]">
                        wildcard
                      </Badge>
                    )}
                    <span className="text-muted-foreground">{p.description}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          ))}
        </div>
      </DataState>
    </div>
  );
}
