import { Button, cn } from "@qeetrix/ui";
import { CheckIcon, CopyIcon } from "lucide-react";
import { useCallback, useState } from "react";

interface CodeBlockProps {
  code: string;
  lang?: string;
  className?: string;
}

/**
 * Fenced code block with a copy button and a language chip. Rendered as
 * monospace with horizontal scroll; token-level syntax highlighting (shiki) is a
 * deferred enhancement tracked in the copilot spec — the block is fully usable
 * (readable + copyable) without it.
 */
export function CodeBlock({ code, lang, className }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(() => {
    void navigator.clipboard?.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [code]);

  return (
    <div
      className={cn(
        "group/code relative my-2 overflow-hidden rounded-lg border bg-muted/40",
        className,
      )}
    >
      <div className="flex items-center justify-between border-b bg-muted/60 px-3 py-1">
        <span className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
          {lang || "code"}
        </span>
        <Button
          variant="ghost"
          size="icon-xs"
          aria-label={copied ? "Copied" : "Copy code"}
          title="Copy code"
          onClick={copy}
        >
          {copied ? (
            <CheckIcon className="size-3.5 text-success" />
          ) : (
            <CopyIcon className="size-3.5" />
          )}
        </Button>
      </div>
      <pre className="overflow-x-auto p-3 text-[13px] leading-relaxed">
        <code className="font-mono">{code}</code>
      </pre>
    </div>
  );
}
