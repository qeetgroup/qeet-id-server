// Event details drawer — a Sheet showing the full ActivityEvent payload,
// related resources, quick actions, and the JSON metadata tree.

import {
  Badge,
  Button,
  buttonVariants,
  JSONTree,
  ScrollArea,
  Separator,
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  TimeSince,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@qeetrix/ui";
import { Link } from "@tanstack/react-router";
import {
  ChevronLeftIcon,
  ChevronRightIcon,
  ClipboardIcon,
  ExternalLinkIcon,
  GlobeIcon,
  MonitorIcon,
  ServerIcon,
} from "lucide-react";
import { type ReactNode, useCallback } from "react";

import type { ActivityEvent } from "../types";
import { SeverityBadge } from "./severity-badge";

// ---------------------------------------------------------------------------
// Shared sub-components
// ---------------------------------------------------------------------------

function CopyButton({ text, label }: { text: string; label: string }) {
  const handleCopy = useCallback(() => {
    void navigator.clipboard.writeText(text);
  }, [text]);

  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <button
            type="button"
            onClick={handleCopy}
            aria-label={label}
            className="inline-flex size-6 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <ClipboardIcon className="size-3.5" aria-hidden="true" />
          </button>
        }
      />
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[7rem_minmax(0,1fr)] gap-x-3">
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-xs text-foreground">{children}</dd>
    </div>
  );
}

function SectionHeading({ children }: { children: ReactNode }) {
  return (
    <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
      {children}
    </h3>
  );
}

// ---------------------------------------------------------------------------
// Main drawer
// ---------------------------------------------------------------------------

type EventDetailsDrawerProps = {
  /** Currently selected event. Pass null to close the drawer. */
  event: ActivityEvent | null;
  /** The event immediately before this one in the list (for prev/next nav). */
  prevEvent?: ActivityEvent | null;
  /** The event immediately after this one in the list (for prev/next nav). */
  nextEvent?: ActivityEvent | null;
  onClose: () => void;
  onSelectPrev?: () => void;
  onSelectNext?: () => void;
};

/**
 * Slide-in Sheet (right-side drawer) showing the full event payload.
 * Always render this component; it controls its own open state via `event`.
 *
 * ARIA: The drawer has `role="dialog"` via Sheet/Base UI. SheetTitle and
 * SheetDescription satisfy accessible-name requirements.
 */
export function EventDetailsDrawer({
  event,
  prevEvent,
  nextEvent,
  onClose,
  onSelectPrev,
  onSelectNext,
}: EventDetailsDrawerProps) {
  const handleOpenChange = useCallback(
    (open: boolean) => {
      if (!open) onClose();
    },
    [onClose],
  );

  return (
    <Sheet open={!!event} onOpenChange={handleOpenChange}>
      <SheetContent side="right" className="flex w-full flex-col gap-0 p-0 sm:max-w-lg">
        {event ? (
          <>
            {/* Header */}
            <SheetHeader className="border-b border-border/60 p-4">
              <div className="flex items-start gap-3 pr-8">
                <div className="min-w-0 flex-1">
                  <SheetTitle className="text-sm">{event.title}</SheetTitle>
                  <SheetDescription className="mt-0.5 text-xs">
                    {event.category} ·{" "}
                    <TimeSince value={event.at} className="inline tabular-nums" />
                  </SheetDescription>
                </div>
                <SeverityBadge severity={event.severity} />
              </div>

              {/* Prev / next navigation */}
              <div className="mt-2 flex items-center gap-1.5">
                <Button
                  variant="outline"
                  size="icon-sm"
                  onClick={onSelectPrev}
                  disabled={!prevEvent || !onSelectPrev}
                  aria-label="Previous event"
                  className="size-7"
                >
                  <ChevronLeftIcon className="size-3.5" aria-hidden="true" />
                </Button>
                <Button
                  variant="outline"
                  size="icon-sm"
                  onClick={onSelectNext}
                  disabled={!nextEvent || !onSelectNext}
                  aria-label="Next event"
                  className="size-7"
                >
                  <ChevronRightIcon className="size-3.5" aria-hidden="true" />
                </Button>
                <span className="text-[10px] text-muted-foreground">Navigate events</span>
              </div>
            </SheetHeader>

            {/* Scrollable body */}
            <ScrollArea className="flex-1">
              <div className="flex flex-col gap-5 p-4">
                {/* Core fields */}
                <section aria-label="Event details">
                  <dl className="flex flex-col gap-2.5">
                    <DetailRow label="Event ID">
                      <span className="flex items-center gap-1.5">
                        <span className="max-w-48 truncate font-mono text-[10px]">{event.id}</span>
                        <CopyButton text={event.id} label="Copy event ID" />
                      </span>
                    </DetailRow>
                    <DetailRow label="Type">
                      <Badge variant="muted">{event.type}</Badge>
                    </DetailRow>
                    <DetailRow label="Category">{event.category}</DetailRow>
                    <DetailRow label="Timestamp">
                      <time dateTime={event.at}>
                        {new Date(event.at).toLocaleString(undefined, {
                          dateStyle: "medium",
                          timeStyle: "long",
                        })}
                      </time>
                    </DetailRow>
                    {event.status && (
                      <DetailRow label="Status">
                        <Badge variant="outline">{event.status}</Badge>
                      </DetailRow>
                    )}
                    {event.source && (
                      <DetailRow label="Source">
                        <span className="flex items-center gap-1">
                          <ServerIcon className="size-3 text-muted-foreground" aria-hidden="true" />
                          {event.source}
                        </span>
                      </DetailRow>
                    )}
                  </dl>
                </section>

                {/* Actor */}
                {event.actor && (
                  <>
                    <Separator />
                    <section aria-label="Actor">
                      <SectionHeading>Actor</SectionHeading>
                      <dl className="flex flex-col gap-2.5">
                        {event.actor.name && <DetailRow label="Name">{event.actor.name}</DetailRow>}
                        {event.actor.id && (
                          <DetailRow label="ID">
                            <span className="flex items-center gap-1.5">
                              <span className="max-w-48 truncate font-mono text-[10px]">
                                {event.actor.id}
                              </span>
                              <CopyButton text={event.actor.id} label="Copy actor ID" />
                            </span>
                          </DetailRow>
                        )}
                        {event.actor.type && (
                          <DetailRow label="Type">
                            <Badge variant="muted">{event.actor.type}</Badge>
                          </DetailRow>
                        )}
                      </dl>
                    </section>
                  </>
                )}

                {/* Target */}
                {event.target && (
                  <>
                    <Separator />
                    <section aria-label="Affected resource">
                      <SectionHeading>Affected resource</SectionHeading>
                      <dl className="flex flex-col gap-2.5">
                        {event.target.label && (
                          <DetailRow label="Label">{event.target.label}</DetailRow>
                        )}
                        {event.target.id && (
                          <DetailRow label="ID">
                            <span className="font-mono text-[10px]">{event.target.id}</span>
                          </DetailRow>
                        )}
                        {event.target.type && (
                          <DetailRow label="Type">
                            <Badge variant="muted">{event.target.type}</Badge>
                          </DetailRow>
                        )}
                      </dl>
                    </section>
                  </>
                )}

                {/* Network / device context */}
                {(event.ip ?? event.location ?? event.device ?? event.browser) && (
                  <>
                    <Separator />
                    <section aria-label="Request context">
                      <SectionHeading>Request context</SectionHeading>
                      <dl className="flex flex-col gap-2.5">
                        {event.ip && (
                          <DetailRow label="IP address">
                            <span className="font-mono">{event.ip}</span>
                          </DetailRow>
                        )}
                        {event.location && (
                          <DetailRow label="Location">
                            <span className="flex items-center gap-1">
                              <GlobeIcon
                                className="size-3 text-muted-foreground"
                                aria-hidden="true"
                              />
                              {event.location}
                            </span>
                          </DetailRow>
                        )}
                        {event.device && (
                          <DetailRow label="Device">
                            <span className="flex items-center gap-1">
                              <MonitorIcon
                                className="size-3 text-muted-foreground"
                                aria-hidden="true"
                              />
                              {event.device}
                            </span>
                          </DetailRow>
                        )}
                        {event.browser && <DetailRow label="Browser">{event.browser}</DetailRow>}
                      </dl>
                    </section>
                  </>
                )}

                {/* JSON metadata */}
                {event.metadata && Object.keys(event.metadata).length > 0 && (
                  <>
                    <Separator />
                    <section aria-label="Event metadata">
                      <div className="mb-2 flex items-center justify-between">
                        <SectionHeading>Metadata</SectionHeading>
                        <CopyButton
                          text={JSON.stringify(event.metadata, null, 2)}
                          label="Copy JSON payload"
                        />
                      </div>
                      <JSONTree value={event.metadata} rootLabel="payload" initialOpenDepth={1} />
                    </section>
                  </>
                )}

                <Separator />

                {/* Quick actions */}
                <section aria-label="Quick actions">
                  <SectionHeading>Quick actions</SectionHeading>
                  <div className="flex flex-wrap gap-2">
                    {event.actor?.id && (
                      <Link
                        to="/users/$userId"
                        params={{ userId: event.actor.id }}
                        className={buttonVariants({ variant: "outline", size: "sm" })}
                      >
                        <ExternalLinkIcon className="size-3.5" aria-hidden="true" />
                        View user
                      </Link>
                    )}
                    <Link
                      to="/security/audit-logs"
                      className={buttonVariants({ variant: "outline", size: "sm" })}
                    >
                      <ExternalLinkIcon className="size-3.5" aria-hidden="true" />
                      View audit log
                    </Link>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => void navigator.clipboard.writeText(event.id)}
                      aria-label="Copy event ID to clipboard"
                    >
                      <ClipboardIcon className="size-3.5" aria-hidden="true" />
                      Copy event ID
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() =>
                        void navigator.clipboard.writeText(JSON.stringify(event, null, 2))
                      }
                      aria-label="Copy full event JSON to clipboard"
                    >
                      <ClipboardIcon className="size-3.5" aria-hidden="true" />
                      Copy JSON
                    </Button>
                  </div>
                </section>
              </div>
            </ScrollArea>
          </>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}
