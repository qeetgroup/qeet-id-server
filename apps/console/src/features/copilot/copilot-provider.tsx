// Root of the copilot runtime. Mounted once inside CapabilityProvider (so it can
// read capabilities) and inside SidebarProvider (so the docked panel can reflow
// the shell). Responsibilities:
//   • hydrate the workspace + conversation stores from storage on the client
//     (never during render — SSR output stays deterministic);
//   • expose a promise-based confirm() used by destructive tools, backed by the
//     same AlertDialog the rest of the console uses.
// The stores themselves are module singletons, so trigger/panel/launcher read
// them directly without prop-drilling; this provider only owns lifecycle + confirm.

import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  Button,
} from "@qeetrix/ui";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";

import { hydrateConversations } from "./store/conversation-store";
import { hydrateWorkspace } from "./store/workspace-store";
import type { ConfirmRequest } from "./tools/tool-types";

interface CopilotContextValue {
  /** Opens a confirmation dialog; resolves true on approval, false otherwise. */
  confirm: (req: ConfirmRequest) => Promise<boolean>;
}

const CopilotContext = createContext<CopilotContextValue | null>(null);

interface PendingConfirm {
  req: ConfirmRequest;
  resolve: (approved: boolean) => void;
}

export function CopilotProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingConfirm | null>(null);
  // Guards against a settle-after-unmount and double-resolve on the same prompt.
  const settleRef = useRef<((approved: boolean) => void) | null>(null);

  useEffect(() => {
    hydrateConversations();
    const unsubscribe = hydrateWorkspace();
    return unsubscribe;
  }, []);

  const settle = useCallback((approved: boolean) => {
    settleRef.current?.(approved);
    settleRef.current = null;
    setPending(null);
  }, []);

  const confirm = useCallback((req: ConfirmRequest) => {
    return new Promise<boolean>((resolve) => {
      settleRef.current = resolve;
      setPending({ req, resolve });
    });
  }, []);

  const req = pending?.req;

  return (
    <CopilotContext.Provider value={{ confirm }}>
      {children}
      <AlertDialog open={!!pending} onOpenChange={(open) => !open && settle(false)}>
        {req ? (
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{req.title}</AlertDialogTitle>
              <AlertDialogDescription>{req.body}</AlertDialogDescription>
            </AlertDialogHeader>
            {req.affected.length > 0 ? (
              <ul className="flex flex-col gap-1.5 rounded-md border bg-muted/30 p-3 text-sm">
                {req.affected.map((item) => (
                  <li key={`${item.label}:${item.value}`} className="flex justify-between gap-4">
                    <span className="text-muted-foreground">{item.label}</span>
                    <span className="truncate font-medium">{item.value}</span>
                  </li>
                ))}
              </ul>
            ) : null}
            <AlertDialogFooter>
              <AlertDialogCancel onClick={() => settle(false)}>Cancel</AlertDialogCancel>
              <Button
                variant={req.tone === "destructive" ? "destructive" : "default"}
                onClick={() => settle(true)}
              >
                {req.confirmText}
              </Button>
            </AlertDialogFooter>
          </AlertDialogContent>
        ) : null}
      </AlertDialog>
    </CopilotContext.Provider>
  );
}

export function useCopilotRuntime(): CopilotContextValue {
  const value = useContext(CopilotContext);
  if (!value) throw new Error("useCopilotRuntime must be used inside CopilotProvider");
  return value;
}
