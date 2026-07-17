import { SidebarProvider } from "@qeetrix/ui";
import { createFileRoute, Outlet, useNavigate } from "@tanstack/react-router";
import { useCallback, useEffect, useState } from "react";

import { CapabilityProvider, useCapabilities } from "@/features/access-control/capability-provider";
import { AccessBoundary } from "@/features/access-control/components/access-boundary";
import { AppSidebar } from "@/features/dashboard/components/app-sidebar";
import { CommandPaletteLauncher } from "@/features/dashboard/components/command-palette-launcher";
import { ConsoleHeader } from "@/features/dashboard/components/console-header";
import { ImpersonationBanner } from "@/features/dashboard/components/impersonation-banner";
import { ShortcutsDialog } from "@/features/dashboard/components/shortcuts-dialog";
import { isAuthenticated } from "@/lib/auth";
import { useGlobalShortcuts } from "@/lib/shortcuts";

export const Route = createFileRoute("/_app")({ component: AppLayout });

// The auth guard runs as a useEffect, not in beforeLoad, because the access
// token lives in localStorage and is therefore invisible to the server.
// Running it in beforeLoad would 302-redirect every hard refresh to
// /sign-in even for users with a valid token (see issue: "after logged in
// and i tried refresh the page, again it went to sign-in page").
function AppLayout() {
  const navigate = useNavigate();

  useEffect(() => {
    if (!isAuthenticated()) {
      navigate({ to: "/sign-in", replace: true });
    }
  }, [navigate]);

  return (
    <CapabilityProvider>
      <ConsoleFrame />
    </CapabilityProvider>
  );
}

function ConsoleFrame() {
  const navigate = useNavigate();
  const access = useCapabilities();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);

  useGlobalShortcuts({
    onHelp: useCallback(() => setShortcutsOpen(true), []),
    navigate: useCallback((path: string) => navigate({ to: path }), [navigate]),
    canNavigate: access.canAccessPath,
  });

  return (
    <SidebarProvider
      className="console-shell"
      style={
        {
          "--sidebar-width": "17.5rem",
          "--sidebar-width-icon": "4rem",
        } as React.CSSProperties
      }
    >
      {/* Skip link: first focusable element, visually hidden until focused so
          keyboard users can jump straight past the sidebar/header to content. */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:inset-s-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-background focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:shadow-md focus:ring-2 focus:ring-ring focus:outline-none"
      >
        Skip to main content
      </a>
      <AppSidebar />
      <div className="console-workspace">
        <ImpersonationBanner />
        <ConsoleHeader
          onOpenPalette={() => setPaletteOpen(true)}
          onOpenShortcuts={() => setShortcutsOpen(true)}
          searchAvailable={access.state === "ready"}
        />
        <main id="main-content" tabIndex={-1} className="console-content focus:outline-none">
          <AccessBoundary>
            <Outlet />
          </AccessBoundary>
        </main>
      </div>
      <CommandPaletteLauncher open={paletteOpen} onOpenChange={setPaletteOpen} />
      <ShortcutsDialog open={shortcutsOpen} onOpenChange={setShortcutsOpen} />
    </SidebarProvider>
  );
}
