import {
  Button,
  Card,
  CardContent,
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { LoginForm } from "@/features/auth/components/signin-form";
import { isMfaChallenge, useCompleteMfaLogin, useLogin } from "@/lib/auth";

export const Route = createFileRoute("/_auth/sign-in")({ component: SignInPage });

function SignInPage() {
  const login = useLogin();
  const mfa = useCompleteMfaLogin();

  // After a correct password, an MFA-enrolled account returns a challenge
  // instead of tokens; show the second-factor step.
  const challenge = login.data && isMfaChallenge(login.data) ? login.data : null;

  if (challenge) {
    return (
      <MfaStep
        isLoading={mfa.isPending}
        errorMessage={mfa.error?.message}
        onSubmit={(code) => mfa.mutate({ mfa_token: challenge.mfa_token, code })}
      />
    );
  }

  return (
    <LoginForm
      isLoading={login.isPending}
      errorMessage={login.error?.message}
      onLogin={(values) => login.mutate(values)}
    />
  );
}

function MfaStep({
  isLoading,
  errorMessage,
  onSubmit,
}: {
  isLoading: boolean;
  errorMessage?: string;
  onSubmit: (code: string) => void;
}) {
  const { t } = useTranslation("authFlow");
  const [code, setCode] = useState("");
  // Move focus to the verification code field on mount — replaces autoFocus
  // (flagged by jsx-a11y/no-autofocus) with an explicit effect.
  const codeRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    codeRef.current?.focus();
  }, []);

  return (
    <div className="mx-auto flex w-full max-w-sm flex-col gap-6">
      <Card>
        <CardContent className="p-6 md:p-8">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              onSubmit(code.trim());
            }}
          >
            <FieldGroup>
              <div className="flex flex-col items-center gap-2 text-center">
                <h1 className="text-2xl font-bold">{t("signIn.mfa.title")}</h1>
                <p className="text-balance text-muted-foreground">{t("signIn.mfa.subtitle")}</p>
              </div>

              <Field>
                <FieldLabel htmlFor="code">{t("signIn.mfa.codeLabel")}</FieldLabel>
                <Input
                  ref={codeRef}
                  id="code"
                  name="code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  required
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />
              </Field>

              {errorMessage && (
                <Field>
                  <FieldError>{errorMessage}</FieldError>
                </Field>
              )}

              <Field>
                <Button type="submit" disabled={isLoading || code.trim().length === 0}>
                  {isLoading && <Loader2Icon className="animate-spin" />}
                  {isLoading ? t("signIn.mfa.verifyingBtn") : t("signIn.mfa.verifyBtn")}
                </Button>
              </Field>
            </FieldGroup>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
