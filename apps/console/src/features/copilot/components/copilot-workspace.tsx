import { Button, useFloatingWindow, useIsMobile } from "@qeetrix/ui";
import { useStore } from "@tanstack/react-store";
import { SparklesIcon } from "lucide-react";
import { useCallback } from "react";

import { useCopilotChat } from "../hooks/use-copilot-chat";
import { conversationStore } from "../store/conversation-store";
import {
  clampDockWidth,
  MAX_DOCK_WIDTH,
  MIN_DOCK_WIDTH,
  workspaceActions,
  workspaceStore,
} from "../store/workspace-store";
import { Composer } from "./conversation/composer";
import { ConversationEmptyState } from "./conversation/empty-state";
import { MessageList } from "./conversation/message-list";
import { CopilotHeader } from "./copilot-header";
import { HistoryPanel } from "./history/history-panel";
import { SuggestedActions } from "./suggestions/suggested-actions";

const RESIZE_STEP = 24;

/**
 * The AI workspace panel. One component, four presentations driven by the
 * workspace store:
 *   • docked     — an in-flow flex sibling of `.console-workspace`, so opening it
 *                  reflows the page instead of covering it; resizable + collapsible.
 *   • floating   — a draggable, non-modal window (useFloatingWindow).
 *   • fullscreen — an immersive overlay.
 *   • collapsed  — a slim rail (docked only) that keeps the panel one click away.
 */
export function CopilotWorkspace() {
  const open = useStore(workspaceStore, (s) => s.open);
  const mode = useStore(workspaceStore, (s) => s.mode);
  const dockWidth = useStore(workspaceStore, (s) => s.dockWidth);
  const collapsed = useStore(workspaceStore, (s) => s.collapsed);
  const floating = useFloatingWindow({ defaultPosition: { x: 96, y: 96 } });
  const isMobile = useIsMobile();

  if (!open) return null;

  if (mode === "docked" && collapsed && !isMobile) {
    return <CollapsedRail />;
  }

  const body = <PanelBody />;

  // On a phone viewport — or in fullscreen mode — present as a full-screen
  // overlay. Docked (a ≥340px in-flow sibling) and floating can't fit a small
  // screen, so mobile always gets the immersive layout.
  if (isMobile || mode === "fullscreen") {
    return (
      <section
        aria-label="Copilot"
        className="fixed inset-0 z-50 flex flex-col bg-background motion-safe:animate-in motion-safe:fade-in-0"
      >
        <CopilotHeader />
        {body}
      </section>
    );
  }

  if (mode === "floating") {
    // Clamp width to the viewport so the window can't render partly off-screen.
    const vw = typeof window !== "undefined" ? window.innerWidth : 1280;
    const width = Math.min(dockWidth, vw - 32);
    return (
      <section
        aria-label="Copilot"
        style={{ left: floating.position.x, top: floating.position.y, width }}
        className="fixed z-50 flex h-[min(70vh,640px)] flex-col overflow-hidden rounded-xl border bg-background shadow-2xl motion-safe:animate-in motion-safe:fade-in-0 motion-safe:zoom-in-95"
      >
        <CopilotHeader dragHandleProps={floating.dragHandleProps} />
        {body}
      </section>
    );
  }

  // Docked: in-flow flex sibling that reflows the shell.
  return (
    <section
      aria-label="Copilot"
      style={{ width: dockWidth }}
      className="relative z-30 flex h-dvh shrink-0 flex-col border-s bg-background motion-safe:animate-in motion-safe:slide-in-from-right-4"
    >
      <DockResizeHandle width={dockWidth} />
      <CopilotHeader />
      {body}
    </section>
  );
}

function PanelBody() {
  const chat = useCopilotChat();
  const historyOpen = useStore(workspaceStore, (s) => s.historyOpen);
  const activeId = useStore(conversationStore, (s) => s.activeId);
  const messages = useStore(
    conversationStore,
    (s) => s.conversations.find((c) => c.id === activeId)?.messages ?? [],
  );

  if (historyOpen) return <HistoryPanel />;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {messages.length === 0 ? (
        <ConversationEmptyState onPick={chat.send} />
      ) : (
        <MessageList messages={messages} chat={chat} />
      )}
      {messages.length > 0 ? <SuggestedActions onPick={chat.send} /> : null}
      <Composer onSend={chat.send} onStop={chat.stop} isStreaming={chat.isStreaming} />
    </div>
  );
}

/** Slim rail shown when the docked panel is collapsed. */
function CollapsedRail() {
  return (
    <div className="relative z-30 flex h-dvh w-14 shrink-0 flex-col items-center gap-2 border-s bg-card/60 py-3">
      <Button
        variant="ghost"
        size="icon"
        aria-label="Expand Copilot"
        title="Expand Copilot (⌘J)"
        onClick={() => workspaceActions.setCollapsed(false)}
        className="text-primary"
      >
        <SparklesIcon className="size-5" />
      </Button>
    </div>
  );
}

/**
 * Draggable divider on the docked panel's inner edge. Pointer drag resizes;
 * ArrowLeft/Right nudge for keyboard users (WCAG 2.2 — the panel must be
 * resizable without a pointer).
 */
function DockResizeHandle({ width }: { width: number }) {
  const onPointerDown = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    e.preventDefault();
    const target = e.currentTarget;
    target.setPointerCapture(e.pointerId);
    const move = (ev: PointerEvent) => {
      workspaceActions.setDockWidth(window.innerWidth - ev.clientX);
    };
    const up = (ev: PointerEvent) => {
      target.releasePointerCapture(ev.pointerId);
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }, []);

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      if (e.key === "ArrowLeft") {
        e.preventDefault();
        workspaceActions.setDockWidth(width + RESIZE_STEP);
      } else if (e.key === "ArrowRight") {
        e.preventDefault();
        workspaceActions.setDockWidth(width - RESIZE_STEP);
      }
    },
    [width],
  );

  return (
    // biome-ignore lint/a11y/useSemanticElements: a focusable window-splitter needs role="separator" + tabIndex + aria-valuenow (ARIA APG); <hr> cannot express a resizable value
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label="Resize Copilot panel"
      aria-valuemin={MIN_DOCK_WIDTH}
      aria-valuemax={MAX_DOCK_WIDTH}
      aria-valuenow={clampDockWidth(width)}
      tabIndex={0}
      onPointerDown={onPointerDown}
      onKeyDown={onKeyDown}
      className="group absolute inset-y-0 -inset-s-1 z-10 w-2 cursor-col-resize touch-none focus-visible:outline-none"
    >
      <span className="absolute inset-y-0 inset-s-1 w-px bg-transparent transition-colors group-hover:bg-primary/50 group-focus-visible:bg-primary" />
    </div>
  );
}
