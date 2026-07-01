"use client";

import { useState, useEffect, useCallback } from "react";

import { useQeetIDClient, useQeetIDState } from "../context.js";
import type { Organization } from "./useOrganization.js";

export interface UseOrganizationListReturn {
  isLoaded: boolean;
  organizationList: Organization[];
  refresh(): Promise<void>;
}

/**
 * useOrganizationList fetches the list of organizations (tenants) the current
 * user belongs to. Multi-org support requires the server SDK — this hook
 * surfaces the user's current tenant from auth state and the /v1/auth/me endpoint.
 * Requires `apiUrl` on <QeetIDProvider> (embedded mode).
 *
 *   const { organizationList } = useOrganizationList();
 */
export function useOrganizationList(): UseOrganizationListReturn {
  const client = useQeetIDClient();
  const state = useQeetIDState();
  const [isLoaded, setIsLoaded] = useState(false);
  const [organizationList, setOrganizationList] = useState<Organization[]>([]);

  const load = useCallback(async () => {
    if (!client) {
      if (state.isLoaded && state.tenantId) {
        setOrganizationList([{ id: state.tenantId }]);
      }
      setIsLoaded(true);
      return;
    }
    try {
      const user = await client.currentUser();
      const tenantId = user?.tenantId ?? user?.["tenant_id"];
      if (typeof tenantId === "string") {
        setOrganizationList([{ id: tenantId }]);
      }
    } finally {
      setIsLoaded(true);
    }
  }, [client, state.isLoaded, state.tenantId]);

  useEffect(() => {
    void load();
  }, [load]);

  return { isLoaded, organizationList, refresh: load };
}
