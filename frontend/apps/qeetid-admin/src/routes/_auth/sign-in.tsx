import { createFileRoute } from "@tanstack/react-router";

import { LoginForm } from "@/features/auth/components/signin-form";
import { tokenStore } from "@/lib/api";
import { useLogin } from "@/lib/auth";

export const Route = createFileRoute("/_auth/sign-in")({ component: SignInPage });

function SignInPage() {
  const login = useLogin();
  const defaultTenantId = tokenStore.getTenantId() ?? "";

  return (
    <LoginForm
      defaultTenantId={defaultTenantId}
      isLoading={login.isPending}
      errorMessage={login.error?.message}
      onLogin={(values) => login.mutate(values)}
    />
  );
}
