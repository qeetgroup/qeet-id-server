import {
  Button,
  Input,
  Separator,
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@qeetid/ui";
import { Outlet, createFileRoute, useNavigate } from "@tanstack/react-router";
import { BellIcon, SearchIcon } from "lucide-react";
import { useEffect } from "react";

import { AppSidebar } from "@/features/dashboard/components/app-sidebar";
import { DynamicBreadcrumb } from "@/features/dashboard/components/dynamic-breadcrumb";
import { HeaderUser } from "@/features/dashboard/components/header-user";
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

  useEffect(() => {
    if (!isAuthenticated()) {
      navigate({ to: "/sign-in", replace: true });
    }
  }, [navigate]);

  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2 border-b px-3 sm:px-4">
          {/* Left */}
          <div className="flex min-w-0 items-center gap-2">
            <SidebarTrigger className="-ml-1" />
            <Separator orientation="vertical" className="mr-2 hidden h-4 lg:block" />
            <DynamicBreadcrumb />
          </div>

          {/* Center — search */}
          <div className="relative mx-auto hidden w-full max-w-md md:block">
            <SearchIcon className="pointer-events-none absolute inset-s-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              type="search"
              placeholder="Search users, roles, audit logs…"
              className="h-9 ps-9 pe-12"
              aria-label="Search"
            />
            <kbd className="pointer-events-none absolute inset-e-2 top-1/2 hidden h-5 -translate-y-1/2 select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium text-muted-foreground sm:inline-flex">
              ⌘K
            </kbd>
          </div>

          {/* Right */}
          <div className="ml-auto flex shrink-0 items-center gap-1">
            <Button variant="ghost" size="icon" className="md:hidden" aria-label="Search">
              <SearchIcon />
            </Button>
            <Button variant="ghost" size="icon" aria-label="Notifications" className="relative">
              <BellIcon />
              <span className="absolute inset-e-2 top-2 size-1.5 rounded-full bg-rose-500" />
            </Button>
            <ThemeToggle />
            <Separator orientation="vertical" className="mx-1 hidden h-6 sm:block" />
            <HeaderUser />
          </div>
        </header>
        <div className="flex min-w-0 flex-1 flex-col gap-4 p-4">
          <Outlet />
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
}
