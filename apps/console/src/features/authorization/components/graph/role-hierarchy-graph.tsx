import type { Edge, Node } from "@xyflow/react";
import { useMemo } from "react";

import type { Permission, Role } from "@/lib/authz-rbac";
import { AuthzFlow } from "./authz-flow";
import { rbacNodeTypes } from "./nodes";

/**
 * RBAC visual: roles in the left column, and — for the selected role — the
 * permissions it grants in the right column, connected by edges. Clicking a
 * role selects it. The backend has no role parent-child relation, so this
 * shows the real role→permission grant graph rather than fabricating a
 * hierarchy.
 */
export function RoleHierarchyGraph({
  roles,
  selectedRoleId,
  permissions,
  onSelectRole,
  height,
}: {
  roles: Role[];
  selectedRoleId: string | null;
  permissions: Permission[];
  onSelectRole?: (roleId: string) => void;
  height?: number;
}) {
  const { nodes, edges } = useMemo(() => {
    const roleNodes: Node[] = roles.map((r, i) => ({
      id: `role:${r.id}`,
      type: "role",
      position: { x: 0, y: i * 92 },
      data: {
        name: r.name,
        isSystem: r.is_system,
        selected: r.id === selectedRoleId,
        permCount: r.id === selectedRoleId ? permissions.length : undefined,
      },
    }));
    const permNodes: Node[] = selectedRoleId
      ? permissions.map((p, i) => ({
          id: `perm:${p.id}`,
          type: "permission",
          position: { x: 320, y: i * 78 },
          data: { key: p.key },
        }))
      : [];
    const edges: Edge[] = selectedRoleId
      ? permissions.map((p) => ({
          id: `e-${selectedRoleId}-${p.id}`,
          source: `role:${selectedRoleId}`,
          target: `perm:${p.id}`,
          type: "smoothstep",
        }))
      : [];
    return { nodes: [...roleNodes, ...permNodes], edges };
  }, [roles, selectedRoleId, permissions]);

  return (
    <AuthzFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={rbacNodeTypes}
      height={height}
      ariaLabel="RBAC role and permission graph"
      onNodeClick={(id) => {
        if (id.startsWith("role:") && onSelectRole) onSelectRole(id.slice("role:".length));
      }}
    />
  );
}
