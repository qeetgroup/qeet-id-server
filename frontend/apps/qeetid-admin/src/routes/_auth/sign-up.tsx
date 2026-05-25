import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";

import { SignupForm } from "@/features/auth/components/signup-form";
import { useSignup } from "@/lib/auth";

export const Route = createFileRoute("/_auth/sign-up")({ component: SignupPage });

function SignupPage() {
  const signup = useSignup();
  const [localError, setLocalError] = useState<string | undefined>(undefined);

  return (
    <SignupForm
      isLoading={signup.isPending}
      errorMessage={localError ?? signup.error?.message}
      onSignup={(values) => {
        // Client-side guard for the password-mismatch case the form
        // flags by submitting empty strings.
        if (!values.email || !values.password) {
          setLocalError("Passwords don't match.");
          return;
        }
        setLocalError(undefined);
        signup.mutate({
          email: values.email,
          password: values.password,
          display_name: values.display_name || undefined,
          tenant: values.tenant,
        });
      }}
    />
  );
}
