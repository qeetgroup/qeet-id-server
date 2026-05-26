import { Button, StatusPill, TimeSince, cn } from "@qeetid/ui";
import { useNavigate } from "@tanstack/react-router";
import {
  AlertTriangleIcon,
  BellIcon,
  CheckCheckIcon,
  CircleAlertIcon,
  InboxIcon,
  InfoIcon,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";

import {
  useMarkAllRead,
  useNotifications,
  type Notification,
  type NotificationKind,
} from "@/lib/notifications";

const KIND_ICON: Record<NotificationKind, typeof InfoIcon> = {
  info: InfoIcon,
  warning: AlertTriangleIcon,
  alert: CircleAlertIcon,
  success: CheckCheckIcon,
};

const KIND_PILL: Record<NotificationKind, "info" | "warning" | "danger" | "success"> = {
  info: "info",
  warning: "warning",
  alert: "danger",
  success: "success",
};

/**
 * NotificationsInbox is the bell-icon-anchored popover in the admin
 * header. Renders the unread badge (red dot when count > 0), and a
 * 360px-wide panel listing the most-recent notifications when opened.
 *
 * The backend endpoint isn't shipped yet (IMPROVEMENTS §8.7); the
 * hook gracefully falls back to an empty list so the UI is forward-
 * compatible — once the API ships, no call-site change is needed.
 */
export function NotificationsInbox() {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const q = useNotifications();
  const markAll = useMarkAllRead();

  // Outside-click + Esc to dismiss.
  useEffect(() => {
    if (!open) return;
    function onClick(e: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const unread = q.data?.unread_count ?? 0;
  const items = q.data?.items ?? [];

  return (
    <div ref={rootRef} className="relative">
      <Button
        variant="ghost"
        size="icon"
        aria-label={unread > 0 ? `Notifications (${unread} unread)` : "Notifications"}
        onClick={() => setOpen((o) => !o)}
        className="relative"
      >
        <BellIcon />
        {unread > 0 && (
          <span
            aria-hidden="true"
            className="absolute inset-e-2 top-2 size-1.5 rounded-full bg-rose-500"
          />
        )}
      </Button>
      {open && (
        <div
          role="dialog"
          aria-label="Notifications"
          className="absolute inset-e-0 top-full z-50 mt-2 w-[min(22rem,calc(100vw-1rem))] overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-lg"
        >
          <div className="flex items-center justify-between border-b px-3 py-2">
            <div className="text-sm font-semibold">Notifications</div>
            <Button
              variant="ghost"
              size="sm"
              disabled={unread === 0 || markAll.isPending}
              onClick={() => markAll.mutate()}
            >
              <CheckCheckIcon /> Mark all read
            </Button>
          </div>
          <div className="max-h-96 overflow-y-auto">
            {items.length === 0 ? (
              <EmptyState />
            ) : (
              <ul role="list" className="divide-y">
                {items.map((n) => (
                  <NotificationItem
                    key={n.id}
                    item={n}
                    onSelect={() => {
                      if (n.href) {
                        navigate({ to: n.href });
                        setOpen(false);
                      }
                    }}
                  />
                ))}
              </ul>
            )}
          </div>
          <div className="border-t px-3 py-2 text-center">
            <Button
              variant="link"
              size="sm"
              className="h-auto p-0 text-xs"
              onClick={() => {
                navigate({ to: "/activity" });
                setOpen(false);
              }}
            >
              View all activity →
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function NotificationItem({
  item,
  onSelect,
}: {
  item: Notification;
  onSelect: () => void;
}) {
  const Icon = KIND_ICON[item.kind] ?? InfoIcon;
  return (
    <li>
      <button
        type="button"
        onClick={onSelect}
        className={cn(
          "flex w-full items-start gap-3 px-3 py-2.5 text-left transition-colors hover:bg-muted/50",
          !item.read_at && "bg-muted/30",
        )}
      >
        <Icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-2">
            <p className="truncate text-sm font-medium">{item.title}</p>
            {!item.read_at && (
              <StatusPill kind={KIND_PILL[item.kind] ?? "info"} dot={false} className="text-[10px]">
                New
              </StatusPill>
            )}
          </div>
          {item.description && (
            <p className="line-clamp-2 text-xs text-muted-foreground">{item.description}</p>
          )}
          <TimeSince
            value={item.created_at}
            className="mt-0.5 block text-[11px]"
            refreshIntervalMs={0}
          />
        </div>
      </button>
    </li>
  );
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center gap-2 px-4 py-10 text-center">
      <InboxIcon className="size-7 text-muted-foreground" />
      <p className="text-sm font-medium">You&apos;re all caught up</p>
      <p className="text-xs text-muted-foreground">
        New activity in your workspace will show up here.
      </p>
    </div>
  );
}
