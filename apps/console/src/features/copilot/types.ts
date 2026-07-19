// Shared type contracts for the Copilot workspace. These are the seams every
// other module (stores, AI provider, tools, UI) compiles against, so they live
// in one place and stay dependency-free.

import type { ToolExecution } from "./tools/tool-types";

/** How the workspace panel is presented. */
export type CopilotMode = "docked" | "floating" | "fullscreen";

/** Who authored a message in a conversation. */
export type MessageRole = "user" | "assistant" | "system";

/**
 * Lifecycle of an assistant message as it is produced. `streaming` drives the
 * live typing indicator; `error` renders the retry affordance; `complete` is a
 * settled turn. User/system messages are always `complete`.
 */
export type MessageStatus = "streaming" | "complete" | "error" | "cancelled";

export interface Message {
  id: string;
  role: MessageRole;
  content: string;
  createdAt: number;
  status: MessageStatus;
  /** Set when `status === "error"` so the UI can explain what went wrong. */
  error?: string;
  /**
   * The route the user was on when they sent this message. Captured so a
   * conversation stays intelligible after the operator navigates away.
   */
  contextPath?: string;
  /**
   * Tool executions the assistant performed on this turn (client-side, under the
   * operator's own permissions). Rendered as the execution timeline.
   */
  toolExecutions?: ToolExecution[];
}

export interface Conversation {
  id: string;
  title: string;
  messages: Message[];
  pinned: boolean;
  createdAt: number;
  updatedAt: number;
  /**
   * Server-side conversation UUID, assigned lazily the first time a turn streams
   * from the backend. Absent until then (and always, when no provider is
   * configured). The local `id` remains the UI's stable key.
   */
  serverId?: string;
}

/** Persisted UI preferences for the panel (mode, width, collapsed rail). */
export interface WorkspacePrefs {
  mode: CopilotMode;
  /** Docked-panel width in px. Clamped to [MIN_DOCK_WIDTH, MAX_DOCK_WIDTH]. */
  dockWidth: number;
  /** Collapsed to a slim rail (docked mode only). */
  collapsed: boolean;
}
