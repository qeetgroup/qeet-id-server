// Cross-surface UI state for the Authorization section. Keeps a short history
// of decisions (so the Decision Explorer can render whatever the Simulator or
// an ABAC "Test" run just produced) and the in-flight builder document (so
// Templates can hand off to the Policy Builder). Server state stays in
// TanStack Query — this store is UI-only.

import { Store, useStore } from "@tanstack/react-store";

import type { PolicyDoc } from "./authz-codegen";
import type { DecisionRecord } from "./authz-simulate";

interface AuthzState {
  history: DecisionRecord[];
  builderDoc: PolicyDoc | null;
}

const HISTORY_LIMIT = 25;

export const authzStore = new Store<AuthzState>({ history: [], builderDoc: null });

export function pushDecision(record: DecisionRecord): void {
  authzStore.setState((s) => ({
    ...s,
    history: [record, ...s.history].slice(0, HISTORY_LIMIT),
  }));
}

export function clearHistory(): void {
  authzStore.setState((s) => ({ ...s, history: [] }));
}

export function setBuilderDoc(doc: PolicyDoc | null): void {
  authzStore.setState((s) => ({ ...s, builderDoc: doc }));
}

export function useDecisionHistory(): DecisionRecord[] {
  return useStore(authzStore, (s) => s.history);
}

export function useLatestDecision(): DecisionRecord | null {
  return useStore(authzStore, (s) => s.history[0] ?? null);
}

export function useBuilderDoc(): PolicyDoc | null {
  return useStore(authzStore, (s) => s.builderDoc);
}
