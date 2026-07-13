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
import { createFileRoute, Link } from "@tanstack/react-router";
import { Loader2Icon } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useAcceptInvite } from "@/lib/auth";

export const Route = createFileRoute("/_auth/invite/accept")({
  component: AcceptInvitePage,
  validateSearch: (search: Record<string, unknown>): { token: string } => ({
    token: typeof search.token === "string" ? search.token : "",
  }),
});

function AcceptInvitePage() {
  const { t } = useTranslation("authFlow");
  const { token } = Route.useSearch();
  const accept = useAcceptInvite();
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");

  if (!token) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>{t("invite.invalidTitle")}</CardTitle>
          <CardDescription>{t("invite.invalidDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Link to="/sign-in" className="text-sm underline">
            {t("invite.backToSignIn")}
          </Link>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("invite.acceptTitle")}</CardTitle>
        <CardDescription>{t("invite.acceptDescription")}</CardDescription>
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
              <FieldLabel htmlFor="display_name">{t("invite.displayNameLabel")}</FieldLabel>
              <Input
                id="display_name"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder={t("invite.displayNamePlaceholder")}
                autoComplete="name"
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="password">{t("invite.passwordLabel")}</FieldLabel>
              <Input
                id="password"
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
              />
              <FieldDescription>{t("invite.passwordHelp")}</FieldDescription>
            </Field>
            {accept.error && <FieldError>{accept.error.message}</FieldError>}
            <Field>
              <Button type="submit" disabled={accept.isPending || password.length < 8}>
                {accept.isPending && <Loader2Icon className="animate-spin" />}
                {accept.isPending ? t("invite.joiningBtn") : t("invite.acceptBtn")}
              </Button>
            </Field>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  );
}
