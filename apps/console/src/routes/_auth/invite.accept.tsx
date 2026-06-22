import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
} from "@qeetrix/ui";
import { Link, createFileRoute } from "@tanstack/react-router";
import { Loader2Icon } from "lucide-react";
import { useState } from "react";

import { useAcceptInvite } from "@/lib/auth";

export const Route = createFileRoute("/_auth/invite/accept")({
  component: AcceptInvitePage,
  validateSearch: (search: Record<string, unknown>): { token: string } => ({
    token: typeof search.token === "string" ? search.token : "",
  }),
});

function AcceptInvitePage() {
  const { token } = Route.useSearch();
  const accept = useAcceptInvite();
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");

  if (!token) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Invalid invite link</CardTitle>
          <CardDescription>
            This link is missing its token. Ask your workspace admin to resend the invite.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Link to="/sign-in" className="text-sm underline">
            Back to sign in
          </Link>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Accept your invite</CardTitle>
        <CardDescription>
          Set a password to finish joining the workspace — you&apos;ll be signed in afterwards.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            accept.mutate({
              token,
              password,
              display_name: displayName.trim() || undefined,
            });
          }}
        >
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="display_name">Display name</FieldLabel>
              <Input
                id="display_name"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="How you'd like to be addressed"
                autoComplete="name"
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="password">Password</FieldLabel>
              <Input
                id="password"
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
              />
              <FieldDescription>At least 8 characters.</FieldDescription>
            </Field>
            {accept.error && <FieldError>{accept.error.message}</FieldError>}
            <Field>
              <Button type="submit" disabled={accept.isPending || password.length < 8}>
                {accept.isPending && <Loader2Icon className="animate-spin" />}
                {accept.isPending ? "Joining…" : "Accept invite"}
              </Button>
            </Field>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  );
}
