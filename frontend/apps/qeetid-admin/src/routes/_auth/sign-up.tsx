import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { SignupForm } from "@/features/auth/components/signup-form";

export const Route = createFileRoute("/_auth/sign-up")({ component: SignupPage });

function SignupPage() {
  const navigate = useNavigate();
  return (
    <SignupForm
      onSubmit={(event) => {
        event.preventDefault();
        navigate({ to: "/dashboard" });
      }}
    />
  );
}
