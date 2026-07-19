import { Badge, cn, StatusPill } from "@qeetrix/ui";

import type { Severity } from "../types";

type BadgeVariant = "destructive" | "warning" | "success" | "muted";

const SEVERITY_VARIANT: Record<Exclude<Severity, "info">, BadgeVariant> = {
  critical: "destructive",
  error: "destructive",
  warning: "warning",
  success: "success",
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  error: "Error",
  warning: "Warning",
  success: "Success",
  info: "Info",
};

/** A Badge that maps ActivityEvent severity onto a consistent visual variant. */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  // "info" maps to the info token (blue) via StatusPill, not the brand-orange "default" Badge.
  if (severity === "info") {
    return (
      <StatusPill kind="info" dot={false} className={className}>
        {SEVERITY_LABEL.info}
      </StatusPill>
    );
  }

  return (
    <Badge
      variant={SEVERITY_VARIANT[severity]}
      className={cn(severity === "critical" && "ring-2 ring-destructive/30", className)}
    >
      {SEVERITY_LABEL[severity]}
    </Badge>
  );
}
