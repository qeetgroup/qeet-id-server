import {
  Avatar,
  AvatarFallback,
  AvatarImage,
  Button,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  Skeleton,
} from "@qeetrix/ui";
import { Link } from "@tanstack/react-router";
import {
  BadgeCheckIcon,
  CreditCardIcon,
  KeyRoundIcon,
  Loader2Icon,
  LogOutIcon,
  ShieldCheckIcon,
  UserIcon,
} from "lucide-react";

import { useLogout, useMe } from "@/lib/auth";

function initials(name: string) {
  return name
    .split(" ")
    .map((p) => p[0])
    .filter(Boolean)
    .slice(0, 2)
    .join("")
    .toUpperCase();
}

export function HeaderUser() {
  const meQ = useMe();
  const logout = useLogout();

  const name = meQ.data?.display_name || meQ.data?.email?.split("@")[0] || "—";
  const email = meQ.data?.email ?? "";
  const avatarSrc = meQ.data?.avatar_url ?? undefined;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button variant="ghost" size="icon" className="rounded-full" aria-label="Account menu">
            <Avatar className="size-8">
              <AvatarImage src={avatarSrc} alt={name} />
              <AvatarFallback className="text-xs">{initials(name)}</AvatarFallback>
            </Avatar>
          </Button>
        }
      />
      <DropdownMenuContent align="end" sideOffset={8} className="min-w-64 rounded-lg">
        <DropdownMenuGroup>
          <DropdownMenuLabel className="p-0 font-normal">
            <div className="flex items-center gap-3 px-2 py-2 text-sm">
              <Avatar className="size-10">
                <AvatarImage src={avatarSrc} alt={name} />
                <AvatarFallback>{initials(name)}</AvatarFallback>
              </Avatar>
              <div className="grid flex-1 leading-tight">
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
            </div>
          </DropdownMenuLabel>
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuGroup>
          <DropdownMenuItem render={<Link to="/account/profile" />}>
            <UserIcon />
            My account
          </DropdownMenuItem>
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
  );
}
