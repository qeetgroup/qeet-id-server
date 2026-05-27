import { Button, StatusPill, TimeSince, cn } from "@qeetid/ui";
import { useNavigate } from "@tanstack/react-router";
import {
  ArrowRightIcon,
  BugIcon,
  RocketIcon,
  ShieldCheckIcon,
  SparklesIcon,
  WrenchIcon,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import {
  CHANGELOG,
  CHANGELOG_LAST_SEEN_KEY,
  type ChangelogEntry,
  unseenEntries,
} from "@/lib/changelog";

const KIND_ICON: Record<NonNullable<ChangelogEntry["kind"]>, typeof RocketIcon> = {
  feature: RocketIcon,
  improvement: WrenchIcon,
  fix: BugIcon,
  security: ShieldCheckIcon,
};

const KIND_PILL: Record<
  NonNullable<ChangelogEntry["kind"]>,
  "success" | "info" | "warning" | "danger"
> = {
  feature: "success",
  improvement: "info",
  fix: "warning",
  security: "danger",
};

const KIND_LABEL: Record<NonNullable<ChangelogEntry["kind"]>, string> = {
  feature: "New",
  improvement: "Improved",
  fix: "Fixed",
  security: "Security",
};

function readLastSeen(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(CHANGELOG_LAST_SEEN_KEY);
}

function writeLastSeen(date: string) {
  try {
    localStorage.setItem(CHANGELOG_LAST_SEEN_KEY, date);
  } catch {
    // localStorage may be disabled (private mode); fall through silently.
  }
}

/**
 * WhatsNewDropdown is the header "what's new" affordance. A sparkles
 * icon with an unread-count dot opens a popover listing the most-
 * recent changelog entries (sourced from lib/changelog.ts). On open,
 * the latest entry's date is recorded in localStorage so the dot
 * disappears for that user.
 */
export function WhatsNewDropdown() {
  const [open, setOpen] = useState(false);
  const [lastSeen, setLastSeen] = useState<string | null>(() => readLastSeen());
  const rootRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  const unseen = useMemo(() => unseenEntries(lastSeen), [lastSeen]);
  const newest = CHANGELOG[0]?.date;

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

  // Mark everything seen when the dropdown opens.
  useEffect(() => {
    if (open && newest && newest !== lastSeen) {
      writeLastSeen(newest);
      setLastSeen(newest);
    }
  }, [open, newest, lastSeen]);

  const unreadCount = unseen.length;

  return (
    <div ref={rootRef} className="relative">
      <Button
        variant="ghost"
        size="icon"
        aria-label={
          unreadCount > 0
            ? `What's new (${unreadCount} new)`
            : "What's new"
        }
        onClick={() => setOpen((o) => !o)}
        className="relative"
      >
        <SparklesIcon />
        {unreadCount > 0 && (
          <span
            aria-hidden="true"
            className="absolute inset-e-2 top-2 size-1.5 rounded-full bg-sky-500"
          />
        )}
      </Button>
      {open && (
        <div
          role="dialog"
          aria-label="What's new"
          className="absolute inset-e-0 top-full z-50 mt-2 w-[min(24rem,calc(100vw-1rem))] overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-lg"
        >
          <div className="flex items-center justify-between border-b px-3 py-2">
            <div className="text-sm font-semibold">What&apos;s new</div>
            <span className="text-xs text-muted-foreground">
              {CHANGELOG.length} update{CHANGELOG.length === 1 ? "" : "s"}
            </span>
          </div>
          <ul role="list" className="max-h-[26rem] divide-y overflow-y-auto">
            {CHANGELOG.slice(0, 10).map((entry) => {
              const isUnseen = !lastSeen || entry.date > lastSeen;
              const Icon = entry.kind ? KIND_ICON[entry.kind] : SparklesIcon;
              const pill = entry.kind ? KIND_PILL[entry.kind] : "info";
              const label = entry.kind ? KIND_LABEL[entry.kind] : "Update";
              return (
                <li key={entry.id}>
                  <button
                    type="button"
                    disabled={!entry.href}
                    onClick={() => {
                      if (entry.href) {
                        navigate({ to: entry.href });
                        setOpen(false);
                      }
                    }}
                    className={cn(
                      "flex w-full items-start gap-3 px-3 py-3 text-left transition-colors",
                      entry.href ? "hover:bg-muted/50" : "cursor-default",
                      isUnseen && "bg-sky-50/40 dark:bg-sky-950/15",
                    )}
                  >
                    <Icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-medium">{entry.title}</p>
                        <StatusPill kind={pill} dot={false} className="text-[10px]">
                          {label}
                        </StatusPill>
                      </div>
                      <p className="text-xs text-muted-foreground">{entry.description}</p>
                      <TimeSince
                        value={entry.date}
                        className="mt-1 block text-[11px]"
                        refreshIntervalMs={0}
                      />
                    </div>
                    {entry.href && (
                      <ArrowRightIcon className="mt-1 size-3 text-muted-foreground" />
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
