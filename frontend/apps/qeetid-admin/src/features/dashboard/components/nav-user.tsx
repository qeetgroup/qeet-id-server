import {
  Avatar,
  AvatarFallback,
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
  useSidebar,
} from "@qeetid/ui";
import { Link } from "@tanstack/react-router";
import {
  BadgeCheckIcon,
  ChevronsUpDownIcon,
  CreditCardIcon,
  KeyRoundIcon,
  Loader2Icon,
  LogOutIcon,
  ShieldCheckIcon,
} from "lucide-react";

import { useLogout, useMe } from "@/lib/auth";

function initials(name: string) {
  return (
    name
      .split(/[\s@.]+/)
      .map((p) => p[0])
      .filter(Boolean)
      .slice(0, 2)
      .join("")
      .toUpperCase() || "?"
  );
}

export function NavUser() {
  const { isMobile } = useSidebar();
  const meQ = useMe();
  const logout = useLogout();

  const name = meQ.data?.display_name || meQ.data?.email?.split("@")[0] || "—";
  const email = meQ.data?.email ?? "";

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger
            render={<SidebarMenuButton size="lg" className="aria-expanded:bg-muted" />}
          >
            <Avatar>
              <AvatarFallback>{initials(name)}</AvatarFallback>
            </Avatar>
            <div className="grid flex-1 text-start text-sm leading-tight">
              {meQ.isLoading ? (
                <>
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="mt-1 h-3 w-32" />
                </>
              ) : (
                <>
                  <span className="truncate font-medium">{name}</span>
                  <span className="truncate text-xs text-muted-foreground">{email}</span>
                </>
              )}
            </div>
            <ChevronsUpDownIcon className="ms-auto size-4" />
          </DropdownMenuTrigger>
          <DropdownMenuContent
            className="min-w-56 rounded-lg"
            side={isMobile ? "bottom" : "right"}
            align="end"
            sideOffset={4}
          >
            <DropdownMenuGroup>
              <DropdownMenuLabel className="p-0 font-normal">
                <div className="flex items-center gap-2 px-1 py-1.5 text-start text-sm">
                  <Avatar>
                    <AvatarFallback>{initials(name)}</AvatarFallback>
                  </Avatar>
                  <div className="grid flex-1 text-start text-sm leading-tight">
                    {meQ.isLoading ? (
                      <>
                        <Skeleton className="h-4 w-24" />
                        <Skeleton className="mt-1 h-3 w-32" />
                      </>
                    ) : (
                      <>
                        <span className="truncate font-medium">{name}</span>
                        <span className="truncate text-xs text-muted-foreground">
                          {email}
                        </span>
                      </>
                    )}
                  </div>
                </div>
              </DropdownMenuLabel>
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuGroup>
              <DropdownMenuItem render={<Link to="/settings/workspace/general" />}>
                <BadgeCheckIcon />
                Workspace settings
              </DropdownMenuItem>
              <DropdownMenuItem render={<Link to="/auth/mfa/totp" />}>
                <ShieldCheckIcon />
                Security & MFA
              </DropdownMenuItem>
              <DropdownMenuItem render={<Link to="/auth/api/keys" />}>
                <KeyRoundIcon />
                API Keys
              </DropdownMenuItem>
              <DropdownMenuItem render={<Link to="/settings/billing" />}>
                <CreditCardIcon />
                Billing
              </DropdownMenuItem>
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              variant="destructive"
              onClick={() => logout.mutate()}
              disabled={logout.isPending}
            >
              {logout.isPending ? <Loader2Icon className="animate-spin" /> : <LogOutIcon />}
              {logout.isPending ? "Signing out…" : "Sign out"}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
