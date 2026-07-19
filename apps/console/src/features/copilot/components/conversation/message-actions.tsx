import { Button, cn } from "@qeetrix/ui";
import type { ReactNode } from "react";

export interface MessageAction {
  icon: ReactNode;
  label: string;
  onClick: () => void;
}

/** Compact, hover-revealed action row shared by user and assistant messages. */
export function MessageActions({
  actions,
  className,
}: {
  actions: MessageAction[];
  className?: string;
}) {
  if (actions.length === 0) return null;
  return (
    <div className={cn("flex items-center gap-0.5", className)}>
      {actions.map((action) => (
        <Button
          key={action.label}
          type="button"
          variant="ghost"
          size="icon-xs"
          aria-label={action.label}
          title={action.label}
          onClick={action.onClick}
        >
          {action.icon}
        </Button>
      ))}
    </div>
  );
}
