// /users/invitations is a navigation alias for /invitations — same underlying
// resource. We redirect rather than duplicate the screen so future changes to
// the invite UI live in one place.

import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/_app/users/invitations")({
  beforeLoad: () => {
    throw redirect({ to: "/invitations" });
  },
});
