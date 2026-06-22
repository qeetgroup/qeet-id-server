// /organizations/members is a navigation alias for /users — same underlying
// table, just framed under the Organizations group in the sidebar.

import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/_app/organizations/members")({
  beforeLoad: () => {
    throw redirect({ to: "/users" });
  },
});
