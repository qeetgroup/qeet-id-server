import { AuthShell } from "@/components/auth-shell";

import { LoggedOutContent } from "./logged-out-content";

// Shown after RP-initiated logout when no post_logout_redirect_uri was supplied.
export default function LoggedOutPage() {
  return (
    <AuthShell>
      <LoggedOutContent />
    </AuthShell>
  );
}
