import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/")({
  // Always send to /dashboard. If the user isn't actually authenticated,
  // the _app layout's client-side guard will bounce them to /sign-in on
  // mount. We can't decide here because the token is in localStorage,
  // which the server can't see.
  beforeLoad: () => {
    throw redirect({ to: "/dashboard" });
  },
});
