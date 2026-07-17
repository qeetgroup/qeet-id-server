import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { ShieldCheckIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { RoleHierarchyGraph } from "@/features/authorization/components/graph/role-hierarchy-graph";
import { useRolePermissions, useRoles } from "@/lib/authz-rbac";

export const Route = createFileRoute("/_app/authorization/rbac")({
  component: RbacPage,
});

function RbacPage() {
  const rolesQ = useRoles();
  const roles = rolesQ.data?.items ?? [];
  const [selectedRoleId, setSelectedRoleId] = useState<string | null>(null);
  const permsQ = useRolePermissions(selectedRoleId);
  const permissions = permsQ.data?.items ?? [];
  const selectedRole = roles.find((r) => r.id === selectedRoleId) ?? null;

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="Visualise how roles grant permissions. Click a role to expand its permission grants; drag to rearrange." />

      <DataState
        isLoading={rolesQ.isLoading}
        isError={rolesQ.isError}
        error={rolesQ.error}
        isEmpty={roles.length === 0}
        emptyIcon={ShieldCheckIcon}
        emptyTitle="No roles to visualise yet"
        skeletonRows={4}
      >
        <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
          <Card className="min-w-0">
            <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
              <div>
                <CardTitle className="text-base">Role → permission graph</CardTitle>
                <CardDescription>
                  {selectedRole
                    ? `Showing grants for “${selectedRole.name}”`
                    : "Select a role to expand its grants"}
                </CardDescription>
              </div>
              {selectedRole && (
                <Button variant="outline" size="sm" onClick={() => setSelectedRoleId(null)}>
                  Clear selection
                </Button>
              )}
            </CardHeader>
            <CardContent className="p-0">
              <RoleHierarchyGraph
                roles={roles}
                selectedRoleId={selectedRoleId}
                permissions={permissions}
                onSelectRole={setSelectedRoleId}
                height={520}
              />
            </CardContent>
          </Card>

          <Card className="min-w-0">
            <CardHeader>
              <CardTitle className="text-base">
                {selectedRole ? selectedRole.name : "Role details"}
              </CardTitle>
              <CardDescription>
                {selectedRole
                  ? selectedRole.description || "No description"
                  : "Click a role node to inspect the permissions it grants."}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {!selectedRole ? (
                <p className="py-8 text-center text-sm text-muted-foreground">Nothing selected</p>
              ) : (
                <DataState
                  isLoading={permsQ.isLoading}
                  isError={permsQ.isError}
                  error={permsQ.error}
                  isEmpty={permissions.length === 0}
                  emptyIcon={ShieldCheckIcon}
                  emptyTitle="This role grants no permissions"
                  skeletonRows={4}
                >
                  <div className="flex flex-col gap-2">
                    <p className="text-xs text-muted-foreground">
                      {permissions.length} permission{permissions.length === 1 ? "" : "s"} granted
                    </p>
                    {permissions.map((p) => (
                      <div key={p.id} className="rounded-md border p-2">
                        <code className="text-xs font-medium">{p.key}</code>
                        {p.key.includes("*") && (
                          <Badge variant="warning" className="ml-2 text-[10px]">
                            wildcard
                          </Badge>
                        )}
                        <p className="truncate text-xs text-muted-foreground">{p.description}</p>
                      </div>
                    ))}
                  </div>
                </DataState>
              )}
            </CardContent>
          </Card>
        </div>
      </DataState>
    </div>
  );
}
