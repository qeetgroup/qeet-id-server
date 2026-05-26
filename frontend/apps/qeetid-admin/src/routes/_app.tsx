import {
  Button,
  Separator,
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@qeetid/ui";
import { Outlet, createFileRoute, useNavigate } from "@tanstack/react-router";
import { SearchIcon } from "lucide-react";
import { useEffect, useState } from "react";

import { AppSidebar } from "@/features/dashboard/components/app-sidebar";
import { CommandPaletteLauncher } from "@/features/dashboard/components/command-palette-launcher";
import { DynamicBreadcrumb } from "@/features/dashboard/components/dynamic-breadcrumb";
import { HeaderUser } from "@/features/dashboard/components/header-user";
import { ImpersonationBanner } from "@/features/dashboard/components/impersonation-banner";
import { NotificationsInbox } from "@/features/dashboard/components/notifications-inbox";
import { ThemeToggle } from "@/features/dashboard/components/theme-toggle";
import { isAuthenticated } from "@/lib/auth";

export const Route = createFileRoute("/_app")({ component: AppLayout });

// The auth guard runs as a useEffect, not in beforeLoad, because the access
// token lives in localStorage and is therefore invisible to the server.
// Running it in beforeLoad would 302-redirect every hard refresh to
// /sign-in even for users with a valid token (see issue: "after logged in
// and i tried refresh the page, again it went to sign-in page").
function AppLayout() {
  const navigate = useNavigate();
  const [paletteOpen, setPaletteOpen] = useState(false);

  useEffect(() => {
    if (!isAuthenticated()) {
      navigate({ to: "/sign-in", replace: true });
    }
  }, [navigate]);

  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <ImpersonationBanner />
        <header className="flex h-16 shrink-0 items-center gap-2 border-b px-3 sm:px-4">
          {/* Left */}
          <div className="flex min-w-0 items-center gap-2">
            <SidebarTrigger className="-ml-1" />
            <Separator orientation="vertical" className="mr-2 hidden h-4 lg:block" />
            <DynamicBreadcrumb />
          </div>

          {/* Center — search-as-button that opens the cmd-K palette */}
          <button
            type="button"
            onClick={() => setPaletteOpen(true)}
            className="relative mx-auto hidden h-9 w-full max-w-md items-center rounded-lg border bg-background ps-9 pe-12 text-left text-sm text-muted-foreground transition-colors hover:bg-muted/50 md:flex"
            aria-label="Open command palette"
          >
            <SearchIcon className="pointer-events-none absolute inset-s-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <span>Search users, roles, audit logs…</span>
            <kbd className="pointer-events-none absolute inset-e-2 top-1/2 hidden h-5 -translate-y-1/2 select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium text-muted-foreground sm:inline-flex">
              ⌘K
            </kbd>
          </button>

          {/* Right */}
          <div className="ml-auto flex shrink-0 items-center gap-1">
            <Button
              variant="ghost"
              size="icon"
              className="md:hidden"
              aria-label="Search"
              onClick={() => setPaletteOpen(true)}
            >
              <SearchIcon />
            </Button>
            <NotificationsInbox />
            <ThemeToggle />
            <Separator orientation="vertical" className="mx-1 hidden h-6 sm:block" />
            <HeaderUser />
          </div>
        </header>
        <div className="flex min-w-0 flex-1 flex-col gap-4 p-4">
          <Outlet />
        </div>
      </SidebarInset>
      <CommandPaletteLauncher open={paletteOpen} onOpenChange={setPaletteOpen} />
    </SidebarProvider>
  );
}
