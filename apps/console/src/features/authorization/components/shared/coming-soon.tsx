import { Card, CardContent } from "@qeetrix/ui";
import { ConstructionIcon, type LucideIcon } from "lucide-react";

/**
 * Honest placeholder for surfaces whose backend does not exist yet (batch
 * simulation history, authorization analytics time-series, server-side
 * rollback, AI provider). We never fabricate data — we say so and explain why.
 */
export function ComingSoon({
  icon: Icon = ConstructionIcon,
  title,
  description,
  note,
}: {
  icon?: LucideIcon;
  title: string;
  description: string;
  note?: string;
}) {
  return (
    <Card className="border-dashed">
      <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
        <div className="rounded-full bg-muted p-3">
          <Icon className="size-6 text-muted-foreground" aria-hidden />
        </div>
        <div className="space-y-1">
          <p className="text-sm font-medium">{title}</p>
          <p className="mx-auto max-w-md text-sm text-muted-foreground">{description}</p>
        </div>
        {note && (
          <p className="rounded-md bg-muted/50 px-3 py-1.5 font-mono text-[11px] text-muted-foreground">
            {note}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
