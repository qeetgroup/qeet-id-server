import { Button, cn, Spinner } from "@qeetrix/ui";
import {
  AlertTriangleIcon,
  CheckIcon,
  ChevronDownIcon,
  CircleDotIcon,
  CopyIcon,
  EyeIcon,
  EyeOffIcon,
  RotateCcwIcon,
  ShieldAlertIcon,
  XIcon,
} from "lucide-react";
import { useCallback, useState } from "react";

import { useSensitiveArtifact } from "../../store/secrets-store";
import type { ExecutionStatus, ToolExecution } from "../../tools/tool-types";

type Tone = "pending" | "running" | "success" | "error";

const STATUS_META: Record<ExecutionStatus, { label: string; tone: Tone }> = {
  queued: { label: "Queued", tone: "pending" },
  validating: { label: "Validating input", tone: "running" },
  awaiting_confirmation: { label: "Awaiting confirmation", tone: "pending" },
  authorizing: { label: "Checking permissions", tone: "running" },
  executing: { label: "Executing", tone: "running" },
  succeeded: { label: "Done", tone: "success" },
  failed: { label: "Failed", tone: "error" },
  timed_out: { label: "Timed out", tone: "error" },
  cancelled: { label: "Cancelled", tone: "pending" },
};

const TONE_TEXT: Record<Tone, string> = {
  pending: "text-muted-foreground",
  running: "text-primary",
  success: "text-success",
  error: "text-destructive",
};

/** snake_case tool name → readable label (registry-free, so this stays decoupled). */
function humanize(name: string): string {
  return name
    .split("_")
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join(" ");
}

function StatusGlyph({ tone }: { tone: Tone }) {
  if (tone === "running") return <Spinner size="sm" className="text-primary" />;
  if (tone === "success") return <CheckIcon className="size-4 text-success" />;
  if (tone === "error") return <AlertTriangleIcon className="size-4 text-destructive" />;
  return <CircleDotIcon className="size-4 text-muted-foreground" />;
}

/**
 * One tool execution rendered inline in the transcript: the action, its live
 * status, the (redacted) result, and — for secret-bearing tools — a one-time
 * reveal of the sensitive artifact that is NEVER sent back to the model.
 */
export function ToolCallCard({
  execution,
  onRetry,
}: {
  execution: ToolExecution;
  onRetry?: () => void;
}) {
  const [showInput, setShowInput] = useState(false);
  const meta = STATUS_META[execution.status];
  const result = execution.result;
  // Secret artifacts live in the in-memory secrets store (never localStorage).
  const artifact = useSensitiveArtifact(execution.id);
  const retryable = execution.status === "failed" || execution.status === "timed_out";

  return (
    <div className="rounded-lg border bg-card/50 text-sm">
      <div className="flex items-center gap-2 px-3 py-2">
        <StatusGlyph tone={meta.tone} />
        <span className="min-w-0 flex-1">
          <span className="font-medium">{humanize(execution.toolName)}</span>
          <span className={cn("ms-2 text-xs", TONE_TEXT[meta.tone])}>{meta.label}</span>
        </span>
        {execution.status === "cancelled" ? (
          <XIcon className="size-3.5 text-muted-foreground" aria-hidden />
        ) : null}
        <button
          type="button"
          onClick={() => setShowInput((v) => !v)}
          aria-expanded={showInput}
          aria-label={showInput ? "Hide input" : "Show input"}
          className="rounded p-1 text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <ChevronDownIcon
            className={cn("size-4 transition-transform", showInput && "rotate-180")}
          />
        </button>
      </div>

      {showInput ? (
        <pre className="mx-3 mb-2 overflow-x-auto rounded-md bg-muted/50 p-2 text-xs">
          <code className="font-mono">{JSON.stringify(execution.input, null, 2)}</code>
        </pre>
      ) : null}

      {result?.summary ? (
        <p className="border-t px-3 py-2 text-[13px] text-muted-foreground">{result.summary}</p>
      ) : null}

      {execution.error ? (
        <div className="flex items-center justify-between gap-2 border-t px-3 py-2">
          <p className="flex items-center gap-1.5 text-xs text-destructive" role="alert">
            <AlertTriangleIcon className="size-3.5 shrink-0" />
            {execution.error.message}
          </p>
          {retryable && onRetry ? (
            <Button size="xs" variant="ghost" onClick={onRetry}>
              <RotateCcwIcon className="size-3.5" /> Retry
            </Button>
          ) : null}
        </div>
      ) : null}

      {artifact ? <SensitiveArtifact artifact={artifact} /> : null}
    </div>
  );
}

function SensitiveArtifact({
  artifact,
}: {
  artifact: NonNullable<ToolExecution["result"]>["sensitiveArtifact"];
}) {
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);
  const value = artifact?.value ?? "";

  const copy = useCallback(() => {
    void navigator.clipboard?.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [value]);

  if (!artifact) return null;

  return (
    <div className="border-t bg-warning/5 px-3 py-2">
      <p className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-warning">
        <ShieldAlertIcon className="size-3.5 shrink-0" />
        {artifact.label} — shown once, never sent to the model. Store it securely now.
      </p>
      <div className="flex items-center gap-2">
        <code className="min-w-0 flex-1 truncate rounded bg-muted px-2 py-1 font-mono text-xs">
          {revealed ? value : "•".repeat(Math.min(value.length, 32))}
        </code>
        <Button
          size="icon-xs"
          variant="ghost"
          aria-label={revealed ? "Hide" : "Reveal"}
          onClick={() => setRevealed((v) => !v)}
        >
          {revealed ? <EyeOffIcon className="size-3.5" /> : <EyeIcon className="size-3.5" />}
        </Button>
        <Button
          size="icon-xs"
          variant="ghost"
          aria-label={copied ? "Copied" : "Copy"}
          onClick={copy}
        >
          {copied ? (
            <CheckIcon className="size-3.5 text-success" />
          ) : (
            <CopyIcon className="size-3.5" />
          )}
        </Button>
      </div>
    </div>
  );
}
