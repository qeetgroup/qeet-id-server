"use client";

import { useState, useEffect, useCallback } from "react";

import type { Session } from "@qeet-id/client";

import { useQeetIDClient } from "../context.js";

export interface UseSessionReturn {
  isLoaded: boolean;
  sessions: Session[];
  revoke(sessionId: string): Promise<void>;
  refresh(): Promise<void>;
}

/**
 * useSession lists and manages the current user's active sessions.
 * Requires `apiUrl` on <QeetIDProvider> (embedded mode).
 *
 *   const { sessions, revoke } = useSession();
 */
export function useSession(): UseSessionReturn {
  const client = useQeetIDClient();
  const [isLoaded, setIsLoaded] = useState(false);
  const [sessions, setSessions] = useState<Session[]>([]);

  const load = useCallback(async () => {
    if (!client) return;
    try {
      const list = await client.sessions.list();
      setSessions(list);
    } finally {
      setIsLoaded(true);
    }
  }, [client]);

  useEffect(() => {
    void load();
  }, [load]);

  const revoke = useCallback(
    async (sessionId: string) => {
      if (!client) throw new Error("useSession requires apiUrl on <QeetIDProvider>");
      await client.sessions.revoke(sessionId);
      setSessions((prev) => prev.filter((s) => s.id !== sessionId));
    },
    [client],
  );

  return { isLoaded, sessions, revoke, refresh: load };
}
