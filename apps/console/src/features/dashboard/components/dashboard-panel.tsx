import { cn } from "@qeetrix/ui";
import type * as React from "react";
import { useId } from "react";

type DashboardPanelProps = Omit<React.ComponentProps<"section">, "title"> & {
  title: React.ReactNode;
  description?: React.ReactNode;
  action?: React.ReactNode;
  contentClassName?: string;
};

/** A data surface with one clear purpose; intentionally less card-like than generic UI panels. */
export function DashboardPanel({
  title,
  description,
  action,
  className,
  contentClassName,
  children,
  ...props
}: DashboardPanelProps) {
  const headingId = useId();

  return (
    <section className={cn("enterprise-panel", className)} aria-labelledby={headingId} {...props}>
      <header className="enterprise-panel-header">
        <div className="min-w-0">
          <h2 id={headingId} className="font-heading text-base font-semibold tracking-tight">
            {title}
          </h2>
          {description ? (
            <p className="mt-1 text-xs leading-5 text-muted-foreground sm:text-sm">{description}</p>
          ) : null}
        </div>
        {action ? <div className="shrink-0">{action}</div> : null}
      </header>
      <div className={cn("p-4 sm:p-4.5", contentClassName)}>{children}</div>
    </section>
  );
}
