"use client";

import { useState, useEffect, useCallback } from "react";

import { useQeetIDClient, useQeetIDState } from "../context.js";

export interface Organization {
  id: string;
  name?: string;
}

export interface UseOrganizationReturn {
  isLoaded: boolean;
  organization: Organization | null;
  /** Switch the active tenant/organization. */
  setActive(organizationId: string): Promise<void>;
}

/**
 * useOrganization returns the active organization for the signed-in user
 * and allows switching tenants.
 * Requires `apiUrl` on <QeetIDProvider> (embedded mode).
 *
 *   const { organization, setActive } = useOrganization();
 */
export function useOrganization(): UseOrganizationReturn {
  const client = useQeetIDClient();
  const state = useQeetIDState();
  const [isLoaded, setIsLoaded] = useState(false);
  const [organization, setOrganization] = useState<Organization | null>(null);

  useEffect(() => {
    if (!state.isLoaded) return;
    if (state.tenantId) {
      setOrganization({ id: state.tenantId });
    }
    setIsLoaded(true);
  }, [state.isLoaded, state.tenantId]);

  const setActive = useCallback(
    async (organizationId: string) => {
      if (!client) throw new Error("useOrganization requires apiUrl on <QeetIDProvider>");
      await client.switchTenant(organizationId);
      setOrganization({ id: organizationId });
    },
    [client],
  );

  return { isLoaded, organization, setActive };
}
