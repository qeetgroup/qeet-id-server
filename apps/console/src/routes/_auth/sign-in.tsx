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
import { useState } from "react";

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
  const [code, setCode] = useState("");

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
                <h1 className="text-2xl font-bold">Two-factor authentication</h1>
                <p className="text-balance text-muted-foreground">
                  Enter the 6-digit code from your authenticator app, or a recovery code.
                </p>
              </div>

              <Field>
                <FieldLabel htmlFor="code">Verification code</FieldLabel>
                <Input
                  id="code"
                  name="code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  autoFocus
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
                  {isLoading ? "Verifying…" : "Verify"}
                </Button>
              </Field>
            </FieldGroup>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
