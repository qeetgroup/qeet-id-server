import { Button } from "@qeetrix/ui";
import { useStore } from "@tanstack/react-store";
import { SparklesIcon } from "lucide-react";

import { workspaceActions, workspaceStore } from "../store/workspace-store";

/** Header affordance that toggles the Copilot workspace (also bound to ⌘J). */
export function CopilotTrigger() {
  const open = useStore(workspaceStore, (s) => s.open);
  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label="Toggle Copilot"
      aria-pressed={open}
      aria-keyshortcuts="Meta+J Control+J"
      title="Copilot (⌘J)"
      onClick={() => workspaceActions.toggle()}
      className={open ? "text-primary" : undefined}
    >
      <SparklesIcon />
    </Button>
  );
}
