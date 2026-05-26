// Notifications inbox data layer. The backend endpoint isn't shipped yet
// (IMPROVEMENTS §8.7), so the hook falls back to an empty list on any
// error rather than surfacing a 404 toast every poll. When the endpoint
// lands, the hook automatically starts returning real data without any
// call-site change.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, ApiError } from "./api";

export type NotificationKind = "info" | "warning" | "alert" | "success";

export interface Notification {
  id: string;
  kind: NotificationKind;
  title: string;
  description?: string;
  /** RFC 3339 timestamp. */
  created_at: string;
  /** ISO timestamp if the user has marked it read. */
  read_at?: string | null;
  /** Optional in-app link the notification opens. */
  href?: string | null;
}

interface NotificationsResponse {
  items: Notification[];
  unread_count: number;
}

const EMPTY: NotificationsResponse = { items: [], unread_count: 0 };

/**
 * Fetches the current user's notification inbox. Refetches every 60s
 * while the tab is focused so the unread badge stays roughly current
 * without a websocket. Background polling is paused by TanStack Query
 * when the tab is hidden, so this is cheap.
 */
export function useNotifications() {
  return useQuery({
    queryKey: ["notifications"],
    queryFn: async (): Promise<NotificationsResponse> => {
      try {
        return await api<NotificationsResponse>("/v1/notifications");
      } catch (err) {
        // Until the backend ships, the endpoint returns 404. Swallow that
        // single case so we don't spam error toasts every minute; let any
        // other status (auth, server error) bubble up.
        if (err instanceof ApiError && err.status === 404) return EMPTY;
        throw err;
      }
    },
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    staleTime: 30_000,
    // Don't trigger the global error toast — the bell already shows a
    // failure state via its own UI.
    meta: { silent: true },
  });
}

/** Mark all in-app notifications as read. */
export function useMarkAllRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api<void>("/v1/notifications/mark-all-read", { method: "POST" }).catch((err) => {
        // Same 404 fallback as the GET — endpoint not shipped yet.
        if (err instanceof ApiError && err.status === 404) return;
        throw err;
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["notifications"] }),
    meta: { silent: true },
  });
}
