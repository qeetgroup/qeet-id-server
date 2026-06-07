import { useEffect } from "react";

// Global keyboard layer for power users: `?` opens the cheat-sheet and a
// `g`-prefixed sequence jumps between sections (GitHub/Linear style). Keys
// are ignored while typing in a field so they never hijack form input.

export type ShortcutGroup = {
  title: string;
  items: { keys: string[]; description: string }[];
};

export const SHORTCUT_GROUPS: ShortcutGroup[] = [
  {
    title: "General",
    items: [
      { keys: ["⌘", "K"], description: "Open command palette / search" },
      { keys: ["?"], description: "Show this shortcuts panel" },
      { keys: ["Esc"], description: "Close any drawer or dialog" },
    ],
  },
  {
    title: "Go to",
    items: [
      { keys: ["g", "d"], description: "Dashboard" },
      { keys: ["g", "u"], description: "Users" },
      { keys: ["g", "r"], description: "Roles & permissions" },
      { keys: ["g", "i"], description: "Invitations" },
      { keys: ["g", "t"], description: "Tenants" },
      { keys: ["g", "w"], description: "Webhooks" },
      { keys: ["g", "a"], description: "Audit logs" },
      { keys: ["g", "s"], description: "Workspace settings" },
    ],
  },
];

const GO_TO: Record<string, string> = {
  d: "/",
  u: "/users",
  r: "/access/roles",
  i: "/invitations",
  t: "/organizations/tenants",
  w: "/developer/webhooks",
  a: "/security/audit-logs",
  s: "/settings/workspace/general",
};

function isTypingTarget(el: EventTarget | null): boolean {
  if (!(el instanceof HTMLElement)) return false;
  const tag = el.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
}

type Options = {
  onHelp: () => void;
  navigate: (path: string) => void;
};

export function useGlobalShortcuts({ onHelp, navigate }: Options) {
  useEffect(() => {
    let awaitingGo = false;
    let goTimer: ReturnType<typeof setTimeout> | undefined;

    function clearGo() {
      awaitingGo = false;
      if (goTimer) clearTimeout(goTimer);
    }

    function onKeyDown(e: KeyboardEvent) {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (isTypingTarget(e.target)) return;

      if (awaitingGo) {
        const path = GO_TO[e.key.toLowerCase()];
        clearGo();
        if (path) {
          e.preventDefault();
          navigate(path);
        }
        return;
      }

      if (e.key === "?") {
        e.preventDefault();
        onHelp();
        return;
      }

      if (e.key.toLowerCase() === "g") {
        awaitingGo = true;
        goTimer = setTimeout(clearGo, 1500);
      }
    }

    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      clearGo();
    };
  }, [onHelp, navigate]);
}
