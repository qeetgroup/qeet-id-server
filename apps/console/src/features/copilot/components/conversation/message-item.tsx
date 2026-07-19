import { Button, Textarea } from "@qeetrix/ui";
import {
  AlertTriangleIcon,
  CheckIcon,
  CopyIcon,
  PencilIcon,
  RotateCcwIcon,
  SparklesIcon,
} from "lucide-react";
import { useCallback, useState } from "react";

import type { UseCopilotChat } from "../../hooks/use-copilot-chat";
import type { Message } from "../../types";
import { ExecutionTimeline } from "../execution/execution-timeline";
import { MarkdownMessage } from "../markdown-message/markdown-message";
import { type MessageAction, MessageActions } from "./message-actions";

function useCopy(text: string): { copied: boolean; copy: () => void } {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(() => {
    void navigator.clipboard?.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [text]);
  return { copied, copy };
}

interface MessageItemProps {
  message: Message;
  isLast: boolean;
  chat: UseCopilotChat;
}

/**
 * A single turn. User messages sit in a right-aligned bubble (editable inline);
 * assistant messages render as Markdown with hover actions (copy, regenerate).
 */
export function MessageItem({ message, isLast, chat }: MessageItemProps) {
  const { copied, copy } = useCopy(message.content);

  if (message.role === "user") {
    return <UserMessage message={message} copied={copied} copy={copy} chat={chat} />;
  }

  const streaming = message.status === "streaming";
  const errored = message.status === "error";

  const actions: MessageAction[] = [
    {
      icon: copied ? (
        <CheckIcon className="size-3.5 text-success" />
      ) : (
        <CopyIcon className="size-3.5" />
      ),
      label: copied ? "Copied" : "Copy",
      onClick: copy,
    },
  ];
  if (isLast && !streaming) {
    actions.push({
      icon: <RotateCcwIcon className="size-3.5" />,
      label: "Regenerate",
      onClick: chat.regenerate,
    });
  }

  return (
    <div className="group flex gap-3">
      <span
        className="mt-0.5 grid size-7 shrink-0 place-items-center rounded-full bg-primary/10 text-primary ring-1 ring-primary/15"
        aria-hidden
      >
        <SparklesIcon className="size-3.5" />
      </span>
      <div className="min-w-0 flex-1 space-y-1.5 pt-0.5">
        {message.content ? (
          <MarkdownMessage content={message.content} />
        ) : streaming ? (
          <span className="text-sm text-muted-foreground">Thinking…</span>
        ) : null}
        {streaming && message.content ? (
          <span
            className="ms-0.5 inline-block h-4 w-0.5 translate-y-0.5 animate-pulse bg-primary align-middle motion-reduce:animate-none"
            aria-hidden
          />
        ) : null}
        {message.toolExecutions && message.toolExecutions.length > 0 ? (
          <ExecutionTimeline executions={message.toolExecutions} />
        ) : null}
        {errored ? (
          <p className="flex items-center gap-1.5 text-xs text-destructive" role="alert">
            <AlertTriangleIcon className="size-3.5 shrink-0" />
            {message.error ?? "The assistant could not complete this turn."}
          </p>
        ) : null}
        {!streaming ? (
          <MessageActions
            actions={actions}
            className="opacity-0 transition-opacity group-hover:opacity-100 focus-within:opacity-100"
          />
        ) : null}
      </div>
    </div>
  );
}

function UserMessage({
  message,
  copied,
  copy,
  chat,
}: {
  message: Message;
  copied: boolean;
  copy: () => void;
  chat: UseCopilotChat;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(message.content);

  if (editing) {
    return (
      <div className="flex flex-col items-end gap-2">
        <Textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          rows={3}
          aria-label="Edit message"
          className="w-full max-w-[85%]"
          autoFocus
        />
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setDraft(message.content);
              setEditing(false);
            }}
          >
            Cancel
          </Button>
          <Button
            size="sm"
            onClick={() => {
              chat.editAndResend(message.id, draft);
              setEditing(false);
            }}
            disabled={!draft.trim()}
          >
            Send
          </Button>
        </div>
      </div>
    );
  }

  const actions: MessageAction[] = [
    {
      icon: copied ? (
        <CheckIcon className="size-3.5 text-success" />
      ) : (
        <CopyIcon className="size-3.5" />
      ),
      label: copied ? "Copied" : "Copy",
      onClick: copy,
    },
    {
      icon: <PencilIcon className="size-3.5" />,
      label: "Edit",
      onClick: () => {
        setDraft(message.content);
        setEditing(true);
      },
    },
  ];

  return (
    <div className="group flex flex-col items-end gap-1">
      <div className="max-w-[85%] whitespace-pre-wrap wrap-break-word rounded-2xl rounded-ee-sm bg-primary px-3.5 py-2 text-sm text-primary-foreground">
        {message.content}
      </div>
      <MessageActions
        actions={actions}
        className="opacity-0 transition-opacity group-hover:opacity-100 focus-within:opacity-100"
      />
    </div>
  );
}
