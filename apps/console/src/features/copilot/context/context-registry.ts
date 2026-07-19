// A tiny pub/sub so route pages can tell the copilot what the operator is
// looking at — "user X", "role Y", "these filters" — without the copilot having
// to reach into each page's internals. Pages call `registerContext(pathname,
// {...})` from an effect; `useConsoleContext` reads the entry for the active
// path. Keyed by pathname so a stale publish from another route never leaks into
// the current context.

import { Store, useStore } from "@tanstack/react-store";
import { useEffect } from "react";

import type { ContextSelection } from "./context-types";

export interface PublishedContext {
  selection?: ContextSelection;
  filters?: Record<string, string>;
}

type RegistryState = Record<string, PublishedContext>;

const registryStore = new Store<RegistryState>({});

const EMPTY: PublishedContext = {};

export function registerContext(pathname: string, value: PublishedContext) {
  registryStore.setState((s) => ({ ...s, [pathname]: value }));
}

export function clearContext(pathname: string) {
  registryStore.setState((s) => {
    if (!(pathname in s)) return s;
    const next = { ...s };
    delete next[pathname];
    return next;
  });
}

/** Read the published context for a path (reactive). */
export function useContextRegistry(pathname: string): PublishedContext {
  return useStore(registryStore, (s) => s[pathname] ?? EMPTY);
}

/**
 * Convenience hook for route pages: publishes `value` for the current path while
 * mounted and clears it on unmount. Stable-stringify the value at the call site
 * (or memoize) to avoid needless churn.
 */
export function useRegisterContext(pathname: string, value: PublishedContext) {
  useEffect(() => {
    registerContext(pathname, value);
    return () => clearContext(pathname);
    // The caller controls identity of `value`; re-publish when it changes.
  }, [pathname, value]);
}
