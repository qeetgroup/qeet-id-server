import { Skeleton, Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@qeetrix/ui";
import {
  Building2Icon,
  CircleAlertIcon,
  EyeIcon,
  LockKeyholeIcon,
  ShieldCheckIcon,
  SlidersHorizontalIcon,
} from "lucide-react";

import { useCapabilities } from "../capability-provider";

const MODE_DETAILS = {
  setup: {
    label: "Workspace setup required",
    description: "Create or select a workspace to load operator permissions.",
    icon: Building2Icon,
  },
  full: {
    label: "Full console access",
    description: "All console capabilities are available in this workspace.",
    icon: ShieldCheckIcon,
  },
  "read-only": {
    label: "Read-only console access",
    description: "You can inspect workspace data but cannot change it.",
    icon: EyeIcon,
  },
  restricted: {
    label: "Limited console access",
    description: "The console only shows areas granted to your workspace role.",
    icon: SlidersHorizontalIcon,
  },
  none: {
    label: "No management access",
    description: "This workspace has not granted management capabilities to your account.",
    icon: LockKeyholeIcon,
  },
  unknown: {
    label: "Access status unavailable",
    description: "The console could not verify workspace permissions.",
    icon: CircleAlertIcon,
  },
} as const;

export function AccessModeIndicator() {
  const access = useCapabilities();

  if (access.state === "resolving") {
    return (
      <div className="flex items-center gap-2 px-2.5 py-2" role="status" aria-live="polite">
        <Skeleton className="size-3.5 shrink-0 rounded" />
        <Skeleton className="h-3 w-36 group-data-[collapsible=icon]:hidden" />
        <span className="sr-only">Checking workspace access</span>
      </div>
    );
  }

  const detail = MODE_DETAILS[access.mode];
  const Icon = detail.icon;

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger
          render={
            <button
              type="button"
              aria-label={detail.label}
              className="flex w-full items-center gap-2 overflow-hidden rounded-lg border border-sidebar-border/70 bg-white/3 px-2.5 py-2 text-start text-[11px] text-sidebar-foreground/65 outline-none ring-sidebar-ring focus-visible:ring-2 group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:px-0"
            >
              <Icon className="size-3.5 shrink-0 text-sidebar-foreground/75" />
              <span className="truncate group-data-[collapsible=icon]:hidden">{detail.label}</span>
            </button>
          }
        />
        <TooltipContent side="right" sideOffset={8} className="max-w-64">
          <p className="font-medium">{detail.label}</p>
          <p className="mt-1 text-xs text-muted-foreground">{detail.description}</p>
          {access.state === "ready" && access.tenantId ? (
            <p className="mt-1.5 font-mono text-[10px] text-muted-foreground">
              {access.permissions.size} effective capabilities
            </p>
          ) : null}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
