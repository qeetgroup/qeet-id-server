import { cn } from "@qeetrix/ui";
import { SparklesIcon } from "lucide-react";
import { useMemo } from "react";

import { useCapabilities } from "@/features/access-control/capability-provider";

import { useConsoleContext } from "../../context/use-console-context";
import { rankSuggestions } from "../../suggestions/suggestion-engine";

/**
 * Proactive, route-aware suggestions (spec §7): the capability-visible, ranked
 * actions for wherever the operator currently is — selection-boosted (e.g. on a
 * user page, "Disable user" floats up). Picking one seeds a turn: prompt
 * suggestions send their text; tool suggestions send their label as a natural
 * trigger. Renders nothing when the current route has no relevant suggestions.
 */
export function SuggestedActions({
  onPick,
  className,
}: {
  onPick: (text: string) => void;
  className?: string;
}) {
  const context = useConsoleContext();
  const access = useCapabilities();
  const suggestions = useMemo(() => rankSuggestions(context, access.can), [context, access.can]);

  if (suggestions.length === 0) return null;

  return (
    <div className={cn("flex flex-wrap gap-1.5 px-3 pt-2", className)}>
      {suggestions.map((suggestion, i) => (
        <button
          key={`${suggestion.type}-${suggestion.label}-${i}`}
          type="button"
          title={suggestion.description}
          onClick={() => onPick(suggestion.type === "prompt" ? suggestion.text : suggestion.label)}
          className="inline-flex items-center gap-1.5 rounded-full border bg-card/60 px-2.5 py-1 text-xs text-muted-foreground transition-colors hover:border-primary/40 hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <SparklesIcon className="size-3 text-primary" aria-hidden />
          {suggestion.label}
        </button>
      ))}
    </div>
  );
}
