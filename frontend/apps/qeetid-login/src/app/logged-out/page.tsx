import { Card, CardContent } from "@qeetrix/ui";

// Shown after RP-initiated logout when no post_logout_redirect_uri was supplied.
export default function LoggedOutPage() {
  return (
    <Card className="w-full max-w-sm">
      <CardContent className="space-y-2 pt-6 text-center">
        <h1 className="text-xl font-semibold tracking-tight">You&apos;re signed out</h1>
        <p className="text-muted-foreground text-sm">You can close this window.</p>
      </CardContent>
    </Card>
  );
}
