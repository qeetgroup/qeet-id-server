import { createFileRoute } from "@tanstack/react-router";

import { SignupForm } from "@/features/auth/components/signup-form";
import { useSignup } from "@/lib/auth";

export const Route = createFileRoute("/_auth/sign-up")({ component: SignupPage });

function SignupPage() {
  const signup = useSignup();

  return (
    <SignupForm
      isLoading={signup.isPending}
      errorMessage={signup.error?.message}
      onSignup={(values) => {
        signup.mutate({
          email: values.email,
          password: values.password,
          display_name: values.display_name || undefined,
        });
      }}
    />
  );
}
