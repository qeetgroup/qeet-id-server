import { Card, CardContent } from "@qeetrix/ui";

import { LoggedOutContent } from "./logged-out-content";

// Shown after RP-initiated logout when no post_logout_redirect_uri was supplied.
export default function LoggedOutPage() {
  return (
    <Card className="w-full max-w-sm">
      <CardContent className="space-y-2 pt-6 text-center">
        <LoggedOutContent />
      </CardContent>
    </Card>
  );
}
