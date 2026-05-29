import { Avatar, AvatarFallback, AvatarImage, cn } from "@qeetid/ui";
import {
  Link,
  Outlet,
  createFileRoute,
  useNavigate,
  useRouterState,
} from "@tanstack/react-router";
import {
  DatabaseIcon,
  MonitorSmartphoneIcon,
  ShieldCheckIcon,
  UserIcon,
} from "lucide-react";
import { useEffect } from "react";

import { isAuthenticated, useMe } from "@/lib/auth";

export const Route = createFileRoute("/account")({ component: AccountLayout });

const NAV = [
  { to: "/account/profile", label: "Profile", icon: UserIcon },
  { to: "/account/security", label: "Security", icon: ShieldCheckIcon },
  { to: "/account/sessions", label: "Sessions", icon: MonitorSmartphoneIcon },
  { to: "/account/data", label: "Data & deletion", icon: DatabaseIcon },
] as const;

/**
 * AccountLayout hosts the end-user self-service surface ("My Account").
 * It's intentionally separate from the admin `_app` shell — no
 * sidebar, simpler chrome — because the audience is the human whose
 * identity Qeet ID manages, not a tenant operator.
 *
 * Auth guard mirrors `_app`: a stored access token is required;
 * otherwise route to sign-in.
 */
function AccountLayout() {
  const navigate = useNavigate();
  const me = useMe();
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  useEffect(() => {
    if (!isAuthenticated()) {
      navigate({ to: "/sign-in", replace: true });
    }
  }, [navigate]);

  return (
    <div className="mx-auto flex min-h-screen w-full max-w-5xl flex-col gap-6 px-4 py-8 sm:px-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 border-b pb-4">
        <div className="flex items-center gap-3">
          <Avatar className="size-10">
            <AvatarImage src={undefined} alt="" />
            <AvatarFallback>
              {(me.data?.display_name ?? me.data?.email ?? "?").charAt(0).toUpperCase()}
            </AvatarFallback>
          </Avatar>
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold">
              {me.data?.display_name || me.data?.email || "Your account"}
            </p>
            {me.data?.email && me.data.email !== me.data?.display_name && (
              <p className="truncate text-xs text-muted-foreground">{me.data.email}</p>
            )}
          </div>
        </div>
        <Link
          to="/dashboard"
          className="text-sm text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
        >
          Back to admin →
        </Link>
      </div>

      {/* Tabs */}
      <nav aria-label="Account sections" className="flex flex-wrap gap-1 border-b">
        {NAV.map((item) => {
          const Icon = item.icon;
          const active = pathname === item.to;
          return (
            <Link
              key={item.to}
              to={item.to}
              className={cn(
                "-mb-px flex items-center gap-2 border-b-2 px-3 py-2 text-sm transition-colors",
                active
                  ? "border-primary font-medium text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              <Icon className="size-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      <Outlet />
    </div>
  );
}
