import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { LoginForm } from "@/features/auth/components/signin-form";

export const Route = createFileRoute("/_auth/sign-in")({ component: SignInPage });

function SignInPage() {
  const navigate = useNavigate();
  return (
    <LoginForm
      onSubmit={(event) => {
        event.preventDefault();
        navigate({ to: "/dashboard" });
      }}
    />
  );
}
