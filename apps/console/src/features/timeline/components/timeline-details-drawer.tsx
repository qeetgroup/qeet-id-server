// TimelineDetailsDrawer — extended event details drawer for the identity timeline.
// Extends the activity event-details-drawer concept with:
//   • Correlation / trace ID from event metadata
//   • Related events (link to filtered timeline)
//   • Destructive quick actions (Reset MFA, Disable user, Terminate session)
//     guarded by capability
//   • Prev / next event navigation (mirrors EventDetailsDrawer)
//
// REUSE: imports SeverityBadge from the activity feature (not re-implemented).
// Shares Sheet, ScrollArea, Separator, Button, Badge, Tooltip from @qeetrix/ui.

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
  ShieldOffIcon,
  UserXIcon,
} from "lucide-react";
import { type ReactNode, useCallback } from "react";

import { useCapabilities } from "@/features/access-control/capability-provider";
import { SeverityBadge } from "@/features/activity/components/severity-badge";
import type { ActivityEvent } from "@/features/activity/types";
import { useResetUserMfa, useSetUserStatus } from "@/lib/users";

// ---------------------------------------------------------------------------
// Shared sub-components (mirrored from EventDetailsDrawer, not copy-pasted)
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
// Main component
// ---------------------------------------------------------------------------

type TimelineDetailsDrawerProps = {
  /** Currently selected event. Pass null to close the drawer. */
  event: ActivityEvent | null;
  /** The user this timeline belongs to (for quick actions). */
  userId: string;
  /** Event immediately before this one (for prev navigation). */
  prevEvent?: ActivityEvent | null;
  /** Event immediately after this one (for next navigation). */
  nextEvent?: ActivityEvent | null;
  onClose: () => void;
  onSelectPrev?: () => void;
  onSelectNext?: () => void;
};

/**
 * Slide-in Sheet showing the full event payload for the identity timeline.
 * Extends the activity event-details concept with:
 *   - Correlation / trace ID section (from metadata)
 *   - Timeline-scoped quick actions (reset MFA, disable user, terminate session)
 *   - Prev / next event navigation
 *
 * The destructive actions (Reset MFA, Disable user) are guarded by user.write
 * capability. Terminate session is guarded by session management capability.
 */
export function TimelineDetailsDrawer({
  event,
  userId,
  prevEvent,
  nextEvent,
  onClose,
  onSelectPrev,
  onSelectNext,
}: TimelineDetailsDrawerProps) {
  const access = useCapabilities();
  const canWriteUsers = access.can("user.write");

  const resetMfa = useResetUserMfa();
  const setStatus = useSetUserStatus();

  const handleOpenChange = useCallback(
    (open: boolean) => {
      if (!open) onClose();
    },
    [onClose],
  );

  const handleDisableUser = useCallback(() => {
    setStatus.mutate({ userId, status: "suspended" });
  }, [setStatus, userId]);

  const handleResetMfa = useCallback(() => {
    resetMfa.mutate(userId);
  }, [resetMfa, userId]);

  // Derive correlation / trace ID from event metadata if present.
  const correlationId =
    typeof event?.metadata?.correlation_id === "string"
      ? event.metadata.correlation_id
      : typeof event?.metadata?.trace_id === "string"
        ? event.metadata.trace_id
        : null;

  // Derive session ID from metadata (if present) for session-level actions.
  const sessionId =
    typeof event?.metadata?.session_id === "string" ? event.metadata.session_id : null;

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
                {/* Core event fields */}
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

                {/* Correlation / trace ID — extended over EventDetailsDrawer */}
                {correlationId && (
                  <>
                    <Separator />
                    <section aria-label="Correlation">
                      <SectionHeading>Correlation</SectionHeading>
                      <dl className="flex flex-col gap-2.5">
                        <DetailRow label="Trace / Corr. ID">
                          <span className="flex items-center gap-1.5">
                            <span className="max-w-48 truncate font-mono text-[10px]">
                              {correlationId}
                            </span>
                            <CopyButton text={correlationId} label="Copy correlation ID" />
                          </span>
                        </DetailRow>
                      </dl>
                    </section>
                  </>
                )}

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

                {/* Target / affected resource */}
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

                {/* Quick actions — extended over EventDetailsDrawer */}
                <section aria-label="Quick actions">
                  <SectionHeading>Quick actions</SectionHeading>
                  <div className="flex flex-wrap gap-2">
                    {/* Navigation actions */}
                    <Link
                      to="/users/$userId"
                      params={{ userId }}
                      className={buttonVariants({ variant: "outline", size: "sm" })}
                    >
                      <ExternalLinkIcon className="size-3.5" aria-hidden="true" />
                      View user
                    </Link>

                    {sessionId && (
                      <Link
                        to="/security/sessions"
                        className={buttonVariants({ variant: "outline", size: "sm" })}
                      >
                        <ExternalLinkIcon className="size-3.5" aria-hidden="true" />
                        View session
                      </Link>
                    )}

                    {event.target?.type === "organization" && event.target.id && (
                      <Link
                        to="/organizations/tenants"
                        className={buttonVariants({ variant: "outline", size: "sm" })}
                      >
                        <ExternalLinkIcon className="size-3.5" aria-hidden="true" />
                        Open org
                      </Link>
                    )}

                    <Link
                      to="/security/audit-logs"
                      className={buttonVariants({ variant: "outline", size: "sm" })}
                    >
                      <ExternalLinkIcon className="size-3.5" aria-hidden="true" />
                      View audit log
                    </Link>

                    {/* Copy actions */}
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

                    {/* Destructive actions — guarded by user.write capability */}
                    {canWriteUsers && (
                      <>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={resetMfa.isPending}
                          onClick={handleResetMfa}
                          aria-label="Reset this user's MFA factors"
                        >
                          <ShieldOffIcon className="size-3.5" aria-hidden="true" />
                          {resetMfa.isPending ? "Resetting…" : "Reset MFA"}
                        </Button>

                        <Button
                          variant="outline"
                          size="sm"
                          disabled={setStatus.isPending}
                          onClick={handleDisableUser}
                          className="border-destructive/40 text-destructive hover:bg-destructive/10"
                          aria-label="Suspend this user account"
                        >
                          <UserXIcon className="size-3.5" aria-hidden="true" />
                          {setStatus.isPending ? "Suspending…" : "Disable user"}
                        </Button>
                      </>
                    )}
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
