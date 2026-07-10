// ReBAC relationship-tuple data layer (Access → Relationships). Tuples are
// "object relation subject" assertions (Zanzibar/OpenFGA style); Check resolves
// them recursively. Backed by /v1/tenants/{tenantID}/relation-tuples[/check].

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface RelationTuple {
  id: string;
  object: string;
  relation: string;
  subject: string;
}

/** List tuples on a given object ("type:id"); disabled until an object is set. */
export function useRelationTuples(object: string) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["relation-tuples", tenantId, object],
    enabled: !!tenantId && !!object,
    queryFn: () =>
      api<{ items: RelationTuple[] }>(
        `/v1/tenants/${tenantId}/relation-tuples?object=${encodeURIComponent(object)}`,
      ),
  });
}

export function useWriteTuple() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { object: string; relation: string; subject: string }) =>
      api<RelationTuple>(`/v1/tenants/${tenantId}/relation-tuples`, { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["relation-tuples"] }),
    meta: { successMessage: "Tuple written" },
  });
}

export function useDeleteTuple() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/relation-tuples/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["relation-tuples"] }),
  });
}

export function useCheckRelation() {
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: (body: { object: string; relation: string; user_id: string }) =>
      api<{ allowed: boolean }>(`/v1/tenants/${tenantId}/relation-tuples/check`, {
        method: "POST",
        body,
      }),
  });
}

// --- Identity Graph types ---

export interface GraphNode {
  id: string;    // "type:id"
  type: string;  // the type part
  label: string; // the id part
}

export interface GraphEdge {
  from: string;     // "type:id"
  to: string;       // "type:id"
  relation: string; // named relation (may include "→ userset-rel" suffix)
}

export interface RelationGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/** Expand the identity graph rooted at object+relation — all reachable subjects. */
export function useRelationGraph(object: string, relation: string, depth?: number) {
  const tenantId = useTenantId();
  const params = new URLSearchParams({
    object,
    relation,
    ...(depth != null ? { depth: String(depth) } : {}),
  });
  return useQuery({
    queryKey: ["relation-graph", tenantId, object, relation, depth],
    enabled: !!tenantId && !!object && !!relation,
    queryFn: () =>
      api<RelationGraph>(
        `/v1/tenants/${tenantId}/relation-tuples/graph?${params}`,
      ),
  });
}

/** Reverse-lookup: all objects a given subject appears in. */
export function useSubjectTuples(subject: string) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["relation-tuples-subject", tenantId, subject],
    enabled: !!tenantId && !!subject,
    queryFn: () =>
      api<{ items: RelationTuple[] }>(
        `/v1/tenants/${tenantId}/relation-tuples?subject=${encodeURIComponent(subject)}`,
      ),
  });
}
