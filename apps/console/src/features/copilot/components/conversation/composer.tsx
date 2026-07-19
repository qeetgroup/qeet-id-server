import { Button, Textarea } from "@qeetrix/ui";
import { ArrowUpIcon, SquareIcon } from "lucide-react";
import { useCallback, useLayoutEffect, useRef, useState } from "react";

interface ComposerProps {
  onSend: (text: string) => void;
  onStop: () => void;
  isStreaming: boolean;
}

const MAX_TEXTAREA_HEIGHT = 200;

/**
 * The message input. Enter sends; Shift+Enter inserts a newline. While a turn is
 * streaming the send button becomes a stop button. The textarea auto-grows up to
 * a cap, then scrolls.
 */
export function Composer({ onSend, onStop, isStreaming }: ComposerProps) {
  const [draft, setDraft] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const autosize = useCallback(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, MAX_TEXTAREA_HEIGHT)}px`;
  }, []);

  useLayoutEffect(autosize, [autosize, draft]);

  const submit = useCallback(() => {
    const text = draft.trim();
    if (!text || isStreaming) return;
    onSend(text);
    setDraft("");
  }, [draft, isStreaming, onSend]);

  return (
    <div className="border-t bg-background/60 p-3">
      <div className="mx-auto flex max-w-3xl items-end gap-2 rounded-2xl border bg-card px-3 py-2 shadow-sm focus-within:border-primary/40 focus-within:ring-2 focus-within:ring-ring/40">
        <Textarea
          ref={textareaRef}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
              e.preventDefault();
              submit();
            }
          }}
          rows={1}
          placeholder="Ask the Copilot, or describe an action…"
          aria-label="Message the Copilot"
          className="max-h-[200px] min-h-9 flex-1 resize-none border-0 bg-transparent p-0 shadow-none focus-visible:ring-0"
        />
        {isStreaming ? (
          <Button
            type="button"
            size="icon"
            variant="secondary"
            onClick={onStop}
            aria-label="Stop generating"
            title="Stop generating"
          >
            <SquareIcon className="size-4" />
          </Button>
        ) : (
          <Button
            type="button"
            size="icon"
            onClick={submit}
            disabled={!draft.trim()}
            aria-label="Send message"
            title="Send (Enter)"
          >
            <ArrowUpIcon className="size-4" />
          </Button>
        )}
      </div>
    </div>
  );
}
