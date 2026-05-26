import {
  Button,
  buttonVariants,
  Card,
  CardContent,
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  Input,
} from "@qeetid/ui";
import { Link, createFileRoute } from "@tanstack/react-router";
import { CheckCircle2Icon, Loader2Icon } from "lucide-react";
import { useState } from "react";

import { BrandHero } from "@/features/auth/components/brand-hero";
import { useForgotPassword } from "@/lib/auth";

export const Route = createFileRoute("/_auth/forgot-password")({
  component: ForgotPasswordPage,
});

function ForgotPasswordPage() {
  const forgot = useForgotPassword();
  const [submitted, setSubmitted] = useState(false);

  return (
    <div className="flex flex-col gap-6">
      <Card className="overflow-hidden p-0">
        <CardContent className="grid p-0 md:grid-cols-2">
          <div className="p-6 md:p-8">
            {submitted ? (
              <SuccessPanel />
            ) : (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const data = new FormData(e.currentTarget);
                  const email = String(data.get("email") ?? "").trim();
                  if (!email) return;
                  forgot.mutate(
                    { email },
                    {
                      // We always show success — the endpoint is constant-time so
                      // a 4xx from the server (e.g. tenant_id required) shouldn't
                      // leak whether the email exists.
                      onSettled: () => setSubmitted(true),
                    },
                  );
                }}
              >
                <FieldGroup>
                  <div className="flex flex-col items-center gap-2 text-center">
                    <h1 className="text-2xl font-bold">Reset your password</h1>
                    <p className="text-balance text-muted-foreground">
                      Enter the email address tied to your Qeetid account and we&apos;ll send
                      you a reset link.
                    </p>
                  </div>

                  <Field>
                    <FieldLabel htmlFor="email">Email</FieldLabel>
                    <Input
                      id="email"
                      name="email"
                      type="email"
                      placeholder="m@example.com"
                      required
                      autoFocus
                    />
                  </Field>

                  <Field>
                    <Button type="submit" disabled={forgot.isPending}>
                      {forgot.isPending && <Loader2Icon className="animate-spin" />}
                      {forgot.isPending ? "Sending reset link…" : "Send reset link"}
                    </Button>
                  </Field>

                  <FieldDescription className="text-center">
                    Remembered it?{" "}
                    <Link to="/sign-in" className="underline-offset-2 hover:underline">
                      Back to sign in
                    </Link>
                  </FieldDescription>
                </FieldGroup>
              </form>
            )}
          </div>
          <BrandHero />
        </CardContent>
      </Card>
    </div>
  );
}

function SuccessPanel() {
  return (
    <div className="flex flex-col items-center gap-3 text-center">
      <CheckCircle2Icon className="size-10 text-emerald-500" />
      <h1 className="text-2xl font-bold">Check your inbox</h1>
      <p className="text-balance text-muted-foreground">
        If an account exists for that email, we&apos;ve sent a one-time reset link.
        The link expires in 60 minutes.
      </p>
      <p className="mt-2 text-sm text-muted-foreground">
        Didn&apos;t get it? Check spam, or{" "}
        <Link to="/forgot-password" className="underline-offset-2 hover:underline">
          try again
        </Link>
        .
      </p>
      <Link to="/sign-in" className={buttonVariants({ variant: "outline" }) + " mt-4"}>
        Back to sign in
      </Link>
    </div>
  );
}
