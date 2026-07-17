import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

import { getRequiredCapabilityForPath } from "@/config/navigation";
import { ApiError, tokenStore } from "@/lib/api";
import { useTenantId } from "@/lib/auth";
import { useEffectivePermissions } from "@/lib/authz-rbac";
import {
  type AccessMode,
  type AccessResolution,
  type Capability,
  type CapabilitySet,
  classifyAccessMode,
  createCapabilitySet,
  hasAllCapabilities,
  hasAnyCapability,
  hasCapability,
} from "./capability-model";

type CapabilityContextValue = {
  state: AccessResolution;
  mode: AccessMode;
  permissions: CapabilitySet;
  tenantId: string | null;
  userId: string | null;
  error: unknown;
  isRefreshing: boolean;
  can: (permission?: Capability) => boolean;
  canAll: (permissions: readonly Capability[]) => boolean;
  canAny: (permissions: readonly Capability[]) => boolean;
  canAccessPath: (pathname: string) => boolean;
  retry: () => void;
};

const CapabilityContext = createContext<CapabilityContextValue | null>(null);

export function CapabilityProvider({ children }: { children: ReactNode }) {
  const [hydrated, setHydrated] = useState(false);
  const tenantId = useTenantId();
  const userId = tokenStore.getUserId();
  const effective = useEffectivePermissions(tenantId ? userId : null);

  useEffect(() => setHydrated(true), []);

  const permissions = useMemo(
    () => createCapabilitySet(effective.data?.permissions),
    [effective.data?.permissions],
  );

  const capabilityRequestForbidden =
    effective.error instanceof ApiError && effective.error.status === 403;
  const state: AccessResolution = !hydrated
    ? "resolving"
    : !tenantId
      ? "ready"
      : capabilityRequestForbidden
        ? "error"
        : effective.data
          ? "ready"
          : effective.isPending
            ? "resolving"
            : "error";

  const can = useCallback(
    (permission?: Capability) => state === "ready" && hasCapability(permissions, permission),
    [permissions, state],
  );
  const canAll = useCallback(
    (required: readonly Capability[]) =>
      state === "ready" && hasAllCapabilities(permissions, required),
    [permissions, state],
  );
  const canAny = useCallback(
    (required: readonly Capability[]) =>
      state === "ready" && hasAnyCapability(permissions, required),
    [permissions, state],
  );
  const canAccessPath = useCallback(
    (pathname: string) => can(getRequiredCapabilityForPath(pathname)),
    [can],
  );

  const value = useMemo<CapabilityContextValue>(
    () => ({
      state,
      mode: state === "error" ? "unknown" : classifyAccessMode(permissions, !!tenantId),
      permissions,
      tenantId,
      userId,
      error: effective.error,
      isRefreshing: effective.isFetching && effective.data !== undefined,
      can,
      canAll,
      canAny,
      canAccessPath,
      retry: () => {
        void effective.refetch();
      },
    }),
    [
      can,
      canAccessPath,
      canAll,
      canAny,
      effective.data,
      effective.error,
      effective.isFetching,
      effective.refetch,
      permissions,
      state,
      tenantId,
      userId,
    ],
  );

  return <CapabilityContext.Provider value={value}>{children}</CapabilityContext.Provider>;
}

export function useCapabilities(): CapabilityContextValue {
  const value = useContext(CapabilityContext);
  if (!value) throw new Error("useCapabilities must be used inside CapabilityProvider");
  return value;
}
