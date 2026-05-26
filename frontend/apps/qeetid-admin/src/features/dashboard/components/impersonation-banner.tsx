import { Button } from "@qeetid/ui";
import { useMutation } from "@tanstack/react-query";
import { LogOutIcon, UserCogIcon } from "lucide-react";

import { api } from "@/lib/api";
import { useImpersonationActor, useLogout } from "@/lib/auth";

/**
 * Sticky banner shown whenever the current access token carries an RFC
 * 8693 `act` claim, i.e. the admin is signed in as another user. The
 * banner is deliberately loud (rose background, prominent exit button)
 * so the admin can't forget they're acting on behalf of someone else.
 *
 * Returns null when not impersonating, so it's safe to render
 * unconditionally near the top of the layout.
 */
export function ImpersonationBanner() {
  const actor = useImpersonationActor();
  const logout = useLogout();

  // POST /v1/admin/impersonate/exit is the planned endpoint (IMPROVEMENTS
  // §4.5). Until it ships, fall back to a hard logout: the admin signs in
  // again as themselves. The exit mutation is suppressed from the global
  // success toast — the page reload is feedback enough.
  const exit = useMutation({
    mutationFn: () =>
      api<void>("/v1/admin/impersonate/exit", { method: "POST" }).catch(() => undefined),
    onSettled: () => logout.mutate(),
    meta: { silent: true },
  });

  if (!actor) return null;

  const adminLabel = actor.actorDisplayName || actor.actorEmail || actor.actorSubject;

  return (
    <div
      role="alert"
      className="sticky top-0 z-50 flex items-center justify-between gap-3 border-b border-rose-700 bg-rose-600 px-4 py-2 text-sm text-white shadow-sm dark:border-rose-500 dark:bg-rose-700"
    >
      <div className="flex min-w-0 items-center gap-2">
        <UserCogIcon className="size-4 shrink-0" />
        <span className="truncate">
          You are impersonating <strong>{actor.targetSubject}</strong>
          <span className="opacity-80"> — signed in as {adminLabel}.</span>
        </span>
      </div>
      <Button
        variant="outline"
        size="sm"
        onClick={() => exit.mutate()}
        disabled={exit.isPending}
        className="border-white/40 bg-white/10 text-white hover:bg-white/20"
      >
        <LogOutIcon /> Exit impersonation
      </Button>
    </div>
  );
}
