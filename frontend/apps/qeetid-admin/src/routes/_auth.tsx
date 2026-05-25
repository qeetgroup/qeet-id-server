import { Outlet, createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/_auth")({ component: AuthLayout });

function AuthLayout() {
  return (
    <div className="grid min-h-svh place-items-center bg-muted p-6 md:p-10">
      <div className="flex w-full max-w-sm flex-col gap-6 md:max-w-3xl">
        <div className="flex items-center justify-center gap-2 self-center font-heading text-lg font-semibold tracking-tight"></div>
        <Outlet />
      </div>
    </div>
  );
}
