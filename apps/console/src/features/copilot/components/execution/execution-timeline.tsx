import type { ToolExecution } from "../../tools/tool-types";
import { ToolCallCard } from "./tool-call-card";

/**
 * The tool executions of a single assistant turn, stacked in order. The
 * turn-level "thinking" phase is shown by the message's streaming indicator;
 * this renders the concrete tool steps (calling → executing → finished) with
 * their results and any retry affordance.
 */
export function ExecutionTimeline({
  executions,
  onRetry,
}: {
  executions: ToolExecution[];
  onRetry?: (executionId: string) => void;
}) {
  if (executions.length === 0) return null;
  return (
    <div className="flex flex-col gap-2">
      {executions.map((execution) => (
        <ToolCallCard
          key={execution.id}
          execution={execution}
          onRetry={onRetry ? () => onRetry(execution.id) : undefined}
        />
      ))}
    </div>
  );
}
