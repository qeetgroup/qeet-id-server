import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  Skeleton,
  cn,
  useSidebar,
} from "@qeetrix/ui";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Building2Icon, CheckIcon, ChevronsUpDownIcon, PlusIcon } from "lucide-react";

import { api, tokenStore } from "@/lib/api";
import { switchToTenant } from "@/lib/auth";

type Tenant = {
  id: string;
  slug: string;
  name: string;
  plan: string;
  region: string;
};

// GET /v1/tenants is scoped to the caller; clicking one switches via switchToTenant().
function initialOf(name: string) {
  const trimmed = name.trim();
  return trimmed ? trimmed.charAt(0).toUpperCase() : "?";
}

export function TeamSwitcher() {
  const { isMobile } = useSidebar();
  const activeId = tokenStore.getTenantId();

  const tenantsQ = useQuery({
    queryKey: ["tenants", "switcher"],
    queryFn: () => api<{ items: Tenant[] }>("/v1/tenants"),
    staleTime: 60_000,
  });

  const tenants = tenantsQ.data?.items ?? [];
  const active = tenants.find((t) => t.id === activeId) ?? tenants[0];

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <SidebarMenuButton
                size="lg"
                className="data-open:bg-sidebar-accent data-open:text-sidebar-accent-foreground"
              />
            }
          >
            <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-sidebar-primary text-sm font-semibold text-sidebar-primary-foreground">
              {active ? initialOf(active.name) : <Building2Icon className="size-4" />}
            </div>
            <div className="grid flex-1 text-start text-sm leading-tight">
              {tenantsQ.isLoading ? (
                <>
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="mt-1 h-3 w-16" />
                </>
              ) : active ? (
                <>
                  <span className="truncate font-medium">{active.name}</span>
                  <span className="truncate text-xs capitalize">{active.plan}</span>
                </>
              ) : (
                <span className="truncate font-medium text-muted-foreground">No workspace</span>
              )}
            </div>
            <ChevronsUpDownIcon className="ms-auto" />
          </DropdownMenuTrigger>
          <DropdownMenuContent
            className="min-w-56 rounded-lg"
            align="start"
            side={isMobile ? "bottom" : "right"}
            sideOffset={4}
          >
            <DropdownMenuGroup>
              <DropdownMenuLabel className="text-xs text-muted-foreground">
                Workspaces
              </DropdownMenuLabel>
              {tenants.length === 0 && !tenantsQ.isLoading ? (
                <DropdownMenuItem disabled className="gap-2 p-2">
                  <span className="text-sm text-muted-foreground">No workspaces yet</span>
                </DropdownMenuItem>
              ) : (
                tenants.slice(0, 9).map((t) => {
                  const isActive = t.id === activeId;
                  return (
                    <DropdownMenuItem
                      key={t.id}
                      onClick={() => {
                        if (!isActive) void switchToTenant(t.id);
                      }}
                      className={cn("gap-2 p-2", isActive && "bg-accent/40")}
                      aria-current={isActive ? "true" : undefined}
                    >
                      <div className="flex size-6 items-center justify-center rounded-md border text-xs font-semibold">
                        {initialOf(t.name)}
                      </div>
                      <span className="truncate">{t.name}</span>
                      {isActive && (
                        <CheckIcon
                          aria-label="Current workspace"
                          className="ms-auto size-4 text-emerald-600 dark:text-emerald-400"
                        />
                      )}
                    </DropdownMenuItem>
                  );
                })
              )}
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuGroup>
              <DropdownMenuItem render={<Link to="/organizations/tenants" />} className="gap-2 p-2">
                <div className="flex size-6 items-center justify-center rounded-md border bg-transparent">
                  <PlusIcon className="size-4" />
                </div>
                <div className="font-medium text-muted-foreground">Add workspace</div>
              </DropdownMenuItem>
            </DropdownMenuGroup>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
