import { createFileRoute } from "@tanstack/react-router";

import { LoginForm } from "@/features/auth/components/signin-form";
import { useLogin } from "@/lib/auth";

export const Route = createFileRoute("/_auth/sign-in")({ component: SignInPage });

function SignInPage() {
  const login = useLogin();

  return (
    <LoginForm
      isLoading={login.isPending}
      errorMessage={login.error?.message}
      onLogin={(values) => login.mutate(values)}
    />
  );
}
