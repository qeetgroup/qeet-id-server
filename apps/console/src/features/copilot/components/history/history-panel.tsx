import { Button, cn, Input } from "@qeetrix/ui";
import { useStore } from "@tanstack/react-store";
import {
  CheckIcon,
  MessageSquareTextIcon,
  PencilIcon,
  PinIcon,
  SearchIcon,
  Trash2Icon,
  XIcon,
} from "lucide-react";
import { useMemo, useState } from "react";
import { useCopilotRuntime } from "../../copilot-provider";
import {
  conversationActions,
  conversationStore,
  searchConversations,
  sortConversations,
} from "../../store/conversation-store";
import { workspaceActions } from "../../store/workspace-store";
import type { Conversation } from "../../types";

function formatRelative(ts: number): string {
  const diff = Date.now() - ts;
  const min = Math.floor(diff / 60_000);
  if (min < 1) return "just now";
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 7) return `${day}d ago`;
  return new Date(ts).toLocaleDateString();
}

/** Conversation history: search, then pin / rename / delete / select. */
export function HistoryPanel() {
  const conversations = useStore(conversationStore, (s) => s.conversations);
  const activeId = useStore(conversationStore, (s) => s.activeId);
  const [query, setQuery] = useState("");

  const rows = useMemo(
    () => sortConversations(searchConversations(conversations, query)),
    [conversations, query],
  );

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center gap-2 border-b p-3">
        <div className="relative flex-1">
          <SearchIcon
            className="pointer-events-none absolute inset-s-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search conversations…"
            aria-label="Search conversations"
            className="ps-8"
          />
        </div>
        <Button
          variant="ghost"
          size="icon"
          aria-label="Close history"
          title="Close history"
          onClick={() => workspaceActions.closeHistory()}
        >
          <XIcon />
        </Button>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-2">
        {rows.length === 0 ? (
          <p className="p-6 text-center text-sm text-muted-foreground">
            {query ? "No conversations match your search." : "No conversations yet."}
          </p>
        ) : (
          <ul className="flex flex-col gap-0.5">
            {rows.map((conversation) => (
              <ConversationRow
                key={conversation.id}
                conversation={conversation}
                active={conversation.id === activeId}
              />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function ConversationRow({
  conversation,
  active,
}: {
  conversation: Conversation;
  active: boolean;
}) {
  const [renaming, setRenaming] = useState(false);
  const [draft, setDraft] = useState(conversation.title);
  const { confirm } = useCopilotRuntime();

  async function remove() {
    const ok = await confirm({
      title: "Delete conversation?",
      body: "This permanently removes the conversation and its messages from this browser.",
      affected: [{ label: "Conversation", value: conversation.title }],
      confirmText: "Delete",
      tone: "destructive",
    });
    if (ok) conversationActions.remove(conversation.id);
  }

  function select() {
    conversationActions.setActive(conversation.id);
    workspaceActions.closeHistory();
  }

  function commitRename() {
    conversationActions.rename(conversation.id, draft);
    setRenaming(false);
  }

  if (renaming) {
    return (
      <li className="flex items-center gap-1 rounded-md bg-accent/50 p-1.5">
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") commitRename();
            if (e.key === "Escape") setRenaming(false);
          }}
          aria-label="Conversation title"
          className="h-8"
          autoFocus
        />
        <Button size="icon-sm" variant="ghost" aria-label="Save title" onClick={commitRename}>
          <CheckIcon className="size-4" />
        </Button>
      </li>
    );
  }

  return (
    <li>
      <div
        className={cn(
          "group flex items-center gap-2 rounded-md px-2 py-1.5 transition-colors hover:bg-accent",
          active && "bg-accent",
        )}
      >
        <button
          type="button"
          onClick={select}
          className="flex min-w-0 flex-1 items-center gap-2 text-start focus-visible:outline-none"
        >
          <MessageSquareTextIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
          <span className="min-w-0 flex-1">
            <span className="flex items-center gap-1">
              {conversation.pinned ? (
                <PinIcon className="size-3 shrink-0 text-primary" aria-label="Pinned" />
              ) : null}
              <span className="truncate text-sm font-medium">{conversation.title}</span>
            </span>
            <span className="block truncate text-xs text-muted-foreground">
              {formatRelative(conversation.updatedAt)} · {conversation.messages.length} messages
            </span>
          </span>
        </button>

        <div className="flex items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100 focus-within:opacity-100">
          <Button
            size="icon-xs"
            variant="ghost"
            aria-label={conversation.pinned ? "Unpin" : "Pin"}
            title={conversation.pinned ? "Unpin" : "Pin"}
            onClick={() => conversationActions.togglePin(conversation.id)}
            className={conversation.pinned ? "text-primary" : undefined}
          >
            <PinIcon className="size-3.5" />
          </Button>
          <Button
            size="icon-xs"
            variant="ghost"
            aria-label="Rename"
            title="Rename"
            onClick={() => {
              setDraft(conversation.title);
              setRenaming(true);
            }}
          >
            <PencilIcon className="size-3.5" />
          </Button>
          <Button
            size="icon-xs"
            variant="ghost"
            aria-label="Delete conversation"
            title="Delete"
            onClick={remove}
          >
            <Trash2Icon className="size-3.5" />
          </Button>
        </div>
      </div>
    </li>
  );
}
