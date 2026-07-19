import { useEffect, useRef } from "react";

import type { UseCopilotChat } from "../../hooks/use-copilot-chat";
import type { Message } from "../../types";
import { MessageItem } from "./message-item";

/**
 * Scrolling transcript. Auto-follows the tail while the user is already near the
 * bottom; if they've scrolled up to read history, new tokens don't yank them
 * back down. A native scroll container (not ScrollArea) so we can own scrollTop.
 */
export function MessageList({ messages, chat }: { messages: Message[]; chat: UseCopilotChat }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const pinnedToBottom = useRef(true);

  // biome-ignore lint/correctness/useExhaustiveDependencies: `messages` is the re-run trigger (follow the tail on new/streamed content); it is intentionally not read in the body.
  useEffect(() => {
    const el = containerRef.current;
    if (!el || !pinnedToBottom.current) return;
    el.scrollTop = el.scrollHeight;
  }, [messages]);

  function handleScroll() {
    const el = containerRef.current;
    if (!el) return;
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    pinnedToBottom.current = distanceFromBottom < 80;
  }

  return (
    <div
      ref={containerRef}
      onScroll={handleScroll}
      className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-4 py-4"
    >
      {/* Polite live region so screen readers hear the assistant's reply as it
          streams in (WCAG 2.2 AA). additions+text: announce new turns and the
          growing streamed content, not removals. */}
      <div
        className="mx-auto flex max-w-3xl flex-col gap-5"
        role="log"
        aria-live="polite"
        aria-relevant="additions text"
      >
        {messages.map((message, i) => (
          <MessageItem
            key={message.id}
            message={message}
            isLast={i === messages.length - 1}
            chat={chat}
          />
        ))}
      </div>
    </div>
  );
}
