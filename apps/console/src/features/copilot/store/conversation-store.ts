// Conversation state for the Copilot: the list of conversations, which one is
// active, and every message within them. Persisted to localStorage so a thread
// survives reloads. A standalone TanStack Store (module singleton) for the same
// reason as the workspace store — multiple, disconnected parts of the UI read
// and mutate it.

import { Store } from "@tanstack/react-store";

import type { ToolExecution } from "../tools/tool-types";
import type { Conversation, Message, MessageStatus } from "../types";

const STORE_KEY = "qeetid.copilot.conversations";
const MAX_CONVERSATIONS = 100;

export interface ConversationState {
  conversations: Conversation[];
  activeId: string | null;
}

export const conversationStore = new Store<ConversationState>({
  conversations: [],
  activeId: null,
});

function uid(prefix: string): string {
  try {
    if (typeof crypto !== "undefined" && crypto.randomUUID)
      return `${prefix}_${crypto.randomUUID()}`;
  } catch {
    /* fall through to the time-based id */
  }
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

/** A conversation's title is derived from its first user message until renamed. */
export function deriveTitle(text: string): string {
  const trimmed = text.trim().replace(/\s+/g, " ");
  if (!trimmed) return "New conversation";
  return trimmed.length > 48 ? `${trimmed.slice(0, 47)}…` : trimmed;
}

function persist(state: ConversationState) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORE_KEY, JSON.stringify(state));
  } catch {
    /* best-effort persistence */
  }
}

function touch(conversation: Conversation): Conversation {
  return { ...conversation, updatedAt: Date.now() };
}

/**
 * Sort key: pinned first, then most-recently-updated. Returned as a new array
 * so callers can render a stable, ordered history list.
 */
export function sortConversations(list: Conversation[]): Conversation[] {
  return [...list].sort((a, b) => {
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
    return b.updatedAt - a.updatedAt;
  });
}

export const conversationActions = {
  /** Create a fresh, empty conversation and make it active. */
  create(): string {
    const id = uid("conv");
    const now = Date.now();
    const conversation: Conversation = {
      id,
      title: "New conversation",
      messages: [],
      pinned: false,
      createdAt: now,
      updatedAt: now,
    };
    conversationStore.setState((s) => {
      const conversations = [conversation, ...s.conversations].slice(0, MAX_CONVERSATIONS);
      const next = { conversations, activeId: id };
      persist(next);
      return next;
    });
    return id;
  },

  /** Remember the server-side UUID once a conversation is created on the backend. */
  setServerConversationId(localId: string, serverId: string) {
    conversationStore.setState((s) => {
      const conversations = s.conversations.map((c) => (c.id === localId ? { ...c, serverId } : c));
      const next = { ...s, conversations };
      persist(next);
      return next;
    });
  },

  setActive(id: string | null) {
    conversationStore.setState((s) => {
      if (s.activeId === id) return s;
      const next = { ...s, activeId: id };
      persist(next);
      return next;
    });
  },

  /** Append a message, creating an active conversation if none exists. */
  appendMessage(input: {
    role: Message["role"];
    content: string;
    status?: MessageStatus;
    contextPath?: string;
  }): { conversationId: string; messageId: string } {
    let conversationId = conversationStore.state.activeId;
    if (
      !conversationId ||
      !conversationStore.state.conversations.some((c) => c.id === conversationId)
    ) {
      conversationId = conversationActions.create();
    }
    const messageId = uid("msg");
    const message: Message = {
      id: messageId,
      role: input.role,
      content: input.content,
      status: input.status ?? "complete",
      createdAt: Date.now(),
      contextPath: input.contextPath,
    };
    conversationStore.setState((s) => {
      const conversations = s.conversations.map((c) => {
        if (c.id !== conversationId) return c;
        const titled =
          c.messages.length === 0 && input.role === "user"
            ? { ...c, title: deriveTitle(input.content) }
            : c;
        return touch({ ...titled, messages: [...titled.messages, message] });
      });
      const next = { ...s, conversations };
      persist(next);
      return next;
    });
    return { conversationId, messageId };
  },

  /** Replace a message's streamed content and/or lifecycle status. */
  updateMessage(
    conversationId: string,
    messageId: string,
    patch: Partial<Pick<Message, "content" | "status" | "error">>,
  ) {
    conversationStore.setState((s) => {
      const conversations = s.conversations.map((c) => {
        if (c.id !== conversationId) return c;
        return touch({
          ...c,
          messages: c.messages.map((m) => (m.id === messageId ? { ...m, ...patch } : m)),
        });
      });
      const next = { ...s, conversations };
      persist(next);
      return next;
    });
  },

  /** Append a text chunk to a streaming message (the streaming hot path). */
  appendChunk(conversationId: string, messageId: string, chunk: string) {
    conversationStore.setState((s) => {
      const conversations = s.conversations.map((c) => {
        if (c.id !== conversationId) return c;
        return touch({
          ...c,
          messages: c.messages.map((m) =>
            m.id === messageId ? { ...m, content: m.content + chunk } : m,
          ),
        });
      });
      const next = { ...s, conversations };
      persist(next);
      return next;
    });
  },

  /** Insert or update a tool execution on a message (drives the live timeline). */
  upsertMessageExecution(conversationId: string, messageId: string, exec: ToolExecution) {
    conversationStore.setState((s) => {
      const conversations = s.conversations.map((c) => {
        if (c.id !== conversationId) return c;
        return touch({
          ...c,
          messages: c.messages.map((m) => {
            if (m.id !== messageId) return m;
            const existing = m.toolExecutions ?? [];
            const idx = existing.findIndex((e) => e.id === exec.id);
            const toolExecutions =
              idx === -1 ? [...existing, exec] : existing.map((e) => (e.id === exec.id ? exec : e));
            return { ...m, toolExecutions };
          }),
        });
      });
      const next = { ...s, conversations };
      persist(next);
      return next;
    });
  },

  /** Drop every message after `messageId` (keeping it) — for edit/regenerate. */
  truncateAfter(conversationId: string, messageId: string) {
    conversationStore.setState((s) => {
      const conversations = s.conversations.map((c) => {
        if (c.id !== conversationId) return c;
        const idx = c.messages.findIndex((m) => m.id === messageId);
        if (idx === -1) return c;
        return touch({ ...c, messages: c.messages.slice(0, idx + 1) });
      });
      const next = { ...s, conversations };
      persist(next);
      return next;
    });
  },

  /** Replace a user message's text and drop everything after it (edit + resend). */
  editUserMessage(conversationId: string, messageId: string, content: string) {
    const clean = content.trim();
    if (!clean) return;
    conversationStore.setState((s) => {
      const conversations = s.conversations.map((c) => {
        if (c.id !== conversationId) return c;
        const idx = c.messages.findIndex((m) => m.id === messageId);
        if (idx === -1) return c;
        const messages = c.messages
          .slice(0, idx + 1)
          .map((m) => (m.id === messageId ? { ...m, content: clean } : m));
        return touch({ ...c, messages });
      });
      const next = { ...s, conversations };
      persist(next);
      return next;
    });
  },

  rename(conversationId: string, title: string) {
    const clean = title.trim();
    if (!clean) return;
    conversationStore.setState((s) => {
      const conversations = s.conversations.map((c) =>
        c.id === conversationId ? { ...c, title: clean.slice(0, 80) } : c,
      );
      const next = { ...s, conversations };
      persist(next);
      return next;
    });
  },

  togglePin(conversationId: string) {
    conversationStore.setState((s) => {
      const conversations = s.conversations.map((c) =>
        c.id === conversationId ? { ...c, pinned: !c.pinned } : c,
      );
      const next = { ...s, conversations };
      persist(next);
      return next;
    });
  },

  remove(conversationId: string) {
    conversationStore.setState((s) => {
      const conversations = s.conversations.filter((c) => c.id !== conversationId);
      const activeId = s.activeId === conversationId ? (conversations[0]?.id ?? null) : s.activeId;
      const next = { conversations, activeId };
      persist(next);
      return next;
    });
  },

  clearAll() {
    const next: ConversationState = { conversations: [], activeId: null };
    conversationStore.setState(() => next);
    persist(next);
  },
};

/**
 * Rehydrate conversations from storage. Call once from a client mount effect —
 * never during render, to keep SSR output deterministic.
 */
export function hydrateConversations() {
  if (typeof window === "undefined") return;
  try {
    const raw = window.localStorage.getItem(STORE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw) as Partial<ConversationState>;
    if (!parsed || !Array.isArray(parsed.conversations)) return;
    conversationStore.setState(() => ({
      conversations: parsed.conversations as Conversation[],
      activeId: parsed.activeId ?? null,
    }));
  } catch {
    /* corrupt payload — start clean rather than crash the console */
  }
}

/** Case-insensitive search over titles and message content. */
export function searchConversations(list: Conversation[], query: string): Conversation[] {
  const q = query.trim().toLowerCase();
  if (!q) return list;
  return list.filter(
    (c) =>
      c.title.toLowerCase().includes(q) ||
      c.messages.some((m) => m.content.toLowerCase().includes(q)),
  );
}
