import { useEffect } from "react";

import { workspaceActions } from "../store/workspace-store";

/**
 * Owns the global ⌘J / Ctrl-J shortcut that toggles the workspace — mirroring
 * how CommandPaletteLauncher owns ⌘K. Handled here (not in useGlobalShortcuts,
 * which ignores modifier keys and typing targets) so it fires everywhere,
 * including from inside the composer. Renders nothing.
 */
export function CopilotLauncher() {
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && !e.altKey && e.key.toLowerCase() === "j") {
        e.preventDefault();
        workspaceActions.toggle();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return null;
}
