import { Button, buttonVariants, Skeleton } from "@qeetrix/ui";
import { PageState } from "@qeetrix/ui/blocks";
import { Link, useLocation } from "@tanstack/react-router";
import { LockKeyholeIcon, RefreshCwIcon, ShieldAlertIcon } from "lucide-react";
import type { ReactNode } from "react";
import { useEffect, useRef } from "react";

import { getRequiredCapabilityForPath } from "@/config/navigation";
import { capabilityLabel } from "../capability-model";
import { useCapabilities } from "../capability-provider";

function AccessLoadingState() {
  return (
    <div className="flex min-w-0 flex-col gap-6" role="status" aria-live="polite" aria-busy="true">
      <span className="sr-only">Checking workspace access</span>
      <div className="flex items-end justify-between gap-4 border-b border-border/70 pb-5">
        <div className="space-y-3">
          <Skeleton className="h-8 w-56 max-w-[70vw]" />
          <Skeleton className="h-4 w-96 max-w-[80vw]" />
        </div>
        <Skeleton className="hidden h-9 w-28 sm:block" />
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Skeleton className="h-36 lg:col-span-2" />
        <Skeleton className="h-36" />
        <Skeleton className="h-72 lg:col-span-3" />
      </div>
    </div>
  );
}

function focusStateHeading(root: HTMLDivElement | null) {
  const heading = root?.querySelector<HTMLHeadingElement>("h1");
  if (!heading) return;
  heading.tabIndex = -1;
  heading.focus({ preventScroll: true });
}

export function AccessBoundary({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  const access = useCapabilities();
  const stateRef = useRef<HTMLDivElement>(null);
  const required = getRequiredCapabilityForPath(pathname);
  const denied = access.state === "ready" && required !== undefined && !access.can(required);
  const deniedPath = denied ? pathname : null;
  const focusKey = access.state === "error" ? `error:${pathname}` : deniedPath;

  useEffect(() => {
    if (focusKey) focusStateHeading(stateRef.current);
  }, [focusKey]);

  if (access.state === "resolving") return <AccessLoadingState />;

  if (access.state === "error") {
    return (
      <div ref={stateRef} role="alert">
        <PageState
          code="—"
          icon={ShieldAlertIcon}
          title="Workspace access could not be verified"
          description="The console could not confirm your permissions. Retry the check, switch workspaces, or use the account menu to sign out."
          actions={
            <Button onClick={access.retry}>
              <RefreshCwIcon /> Retry access check
            </Button>
          }
        />
      </div>
    );
  }

  if (denied && required) {
    return (
      <div ref={stateRef}>
        <PageState
          code="403"
          icon={LockKeyholeIcon}
          title="You don’t have access to this page"
          description={
            <>
              This workspace requires <strong>{capabilityLabel(required)}</strong>.
              <span className="mt-1 block font-mono text-xs">{required}</span>
            </>
          }
          actions={
            <Link to="/" className={buttonVariants()}>
              Go to overview
            </Link>
          }
        />
      </div>
    );
  }

  return children;
}
