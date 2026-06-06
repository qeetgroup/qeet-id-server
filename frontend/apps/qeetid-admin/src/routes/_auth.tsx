import { Outlet, createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect } from "react";

import { isAuthenticated } from "@/lib/auth";

export const Route = createFileRoute("/_auth")({ component: AuthLayout });

// Mirror of _app.tsx's guard, in reverse: bounce authenticated visitors
// out of the sign-in / sign-up screens. Has to run client-side because
// the token lives in localStorage.
function AuthLayout() {
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated()) {
      navigate({ to: "/", replace: true });
    }
  }, [navigate]);

  return (
    <div className="grid min-h-svh place-items-center bg-muted p-6 md:p-10">
      <div className="flex w-full max-w-sm flex-col gap-6 md:max-w-3xl">
        <div className="flex items-center justify-center gap-2 self-center font-heading text-lg font-semibold tracking-tight"></div>
        <Outlet />
      </div>
    </div>
  );
}
