import { cn, StatusPill } from "@qeetrix/ui";
import { RadioIcon } from "lucide-react";

import type { ConnectionStatus } from "../types";

const STATUS_RING_CLASS: Record<ConnectionStatus, string> = {
  connected: "border-success/40 text-success",
  reconnecting: "border-warning/40 text-warning",
  disconnected: "border-destructive/40 text-destructive",
  paused: "border-muted-foreground/40 text-muted-foreground",
};

const STATUS_ICON_CLASS: Record<ConnectionStatus, string> = {
  connected: "text-success",
  reconnecting: "text-warning",
  disconnected: "text-destructive",
  paused: "text-muted-foreground",
};

const STATUS_LABEL: Record<ConnectionStatus, string> = {
  connected: "Live",
  reconnecting: "Reconnecting…",
  disconnected: "Disconnected",
  paused: "Paused",
};

const UNREAD_KIND: Partial<Record<ConnectionStatus, "success" | "warning" | "danger" | "muted">> = {
  connected: "success",
  reconnecting: "warning",
  paused: "muted",
};

/**
 * Compact connection status indicator for the activity feed header.
 * Shows the SSE connection state and an unread-event count badge.
 */
export function LiveIndicator({
  status,
  unreadCount,
  className,
}: {
  status: ConnectionStatus;
  unreadCount?: number;
  className?: string;
}) {
  const label = STATUS_LABEL[status];
  const isPulsing = status === "connected" || status === "reconnecting";

  return (
    <div className={cn("flex items-center gap-2", className)} aria-live="polite" aria-atomic="true">
      <span
        className={cn(
          "inline-flex items-center gap-1 rounded-full border px-1.5 py-px text-[10px] font-medium",
          STATUS_RING_CLASS[status],
        )}
        title={label}
      >
        <RadioIcon
          className={cn("size-3", isPulsing && "animate-pulse", STATUS_ICON_CLASS[status])}
          aria-hidden="true"
        />
        {label}
      </span>

      {unreadCount !== undefined && unreadCount > 0 && (
        <StatusPill kind={UNREAD_KIND[status] ?? "neutral"} dot={false}>
          {unreadCount > 99 ? "99+" : unreadCount} new
        </StatusPill>
      )}
    </div>
  );
}
