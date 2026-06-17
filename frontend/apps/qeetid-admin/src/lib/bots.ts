// Bot-detection data layer for the Threats → Bots screen. Backed by
// GET /v1/tenants/{tenantID}/security/bots (recent verdicts + stats) and
// GET/PUT .../security/bots/settings. Verdicts are recorded detect-only by the
// UA scorer on login/session attempts.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ApiError, api } from "./api";
import { useTenantId } from "./auth";

export interface BotEvent {
  id: string;
  ip?: string | null;
  user_agent: string;
  score: number;
  verdict: string;
  created_at: string;
}

export interface BotStats {
  blocked_24h: number;
  challenged_24h: number;
  threshold: number;
}

export interface BotSettings {
  ua_check: boolean;
  honeypot: boolean;
  captcha: boolean;
  signature: boolean;
  score_threshold: number;
}

const KEY = ["bots"];

export function useBotOverview() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: [...KEY, "overview", tenantId],
    queryFn: async (): Promise<{ recent: BotEvent[]; stats: BotStats }> => {
      try {
        return await api<{ recent: BotEvent[]; stats: BotStats }>(
          `/v1/tenants/${tenantId}/security/bots`,
        );
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) {
          return { recent: [], stats: { blocked_24h: 0, challenged_24h: 0, threshold: 0.7 } };
        }
        throw err;
      }
    },
    enabled: !!tenantId,
    staleTime: 30_000,
  });
}

export function useBotSettings() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: [...KEY, "settings", tenantId],
    queryFn: () => api<BotSettings>(`/v1/tenants/${tenantId}/security/bots/settings`),
    enabled: !!tenantId,
    staleTime: 30_000,
  });
}

export function useUpdateBotSettings() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (settings: BotSettings) =>
      api<BotSettings>(`/v1/tenants/${tenantId}/security/bots/settings`, {
        method: "PUT",
        body: settings,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
