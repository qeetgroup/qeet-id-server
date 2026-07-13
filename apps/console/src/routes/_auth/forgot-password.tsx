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
} from "@qeetrix/ui";
import { createFileRoute, Link } from "@tanstack/react-router";
import { CheckCircle2Icon, Loader2Icon } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { BrandHero } from "@/features/auth/components/brand-hero";
import { useForgotPassword } from "@/lib/auth";

export const Route = createFileRoute("/_auth/forgot-password")({
  component: ForgotPasswordPage,
});

function ForgotPasswordPage() {
  const { t } = useTranslation("authFlow");
  const forgot = useForgotPassword();
  const [submitted, setSubmitted] = useState(false);
  // Move focus to the email field on mount — replaces autoFocus which
  // jsx-a11y/no-autofocus flags, with an explicit effect that fires after
  // the page has fully rendered.
  const emailRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    emailRef.current?.focus();
  }, []);

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
                    <h1 className="text-2xl font-bold">{t("forgotPassword.title")}</h1>
                    <p className="text-balance text-muted-foreground">
                      {t("forgotPassword.subtitle")}
                    </p>
                  </div>

                  <Field>
                    <FieldLabel htmlFor="email">{t("forgotPassword.emailLabel")}</FieldLabel>
                    <Input
                      ref={emailRef}
                      id="email"
                      name="email"
                      type="email"
                      placeholder="m@example.com"
                      required
                    />
                  </Field>

                  <Field>
                    <Button type="submit" disabled={forgot.isPending}>
                      {forgot.isPending && <Loader2Icon className="animate-spin" />}
                      {forgot.isPending
                        ? t("forgotPassword.sendingBtn")
                        : t("forgotPassword.sendBtn")}
                    </Button>
                  </Field>

                  <FieldDescription className="text-center">
                    {t("forgotPassword.rememberedIt")}{" "}
                    <Link to="/sign-in" className="underline-offset-2 hover:underline">
                      {t("forgotPassword.backToSignIn")}
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
  const { t } = useTranslation("authFlow");
  return (
    <div className="flex flex-col items-center gap-3 text-center">
      <CheckCircle2Icon className="size-10 text-emerald-500" />
      <h1 className="text-2xl font-bold">{t("forgotPassword.successTitle")}</h1>
      <p className="text-balance text-muted-foreground">{t("forgotPassword.successText")}</p>
      <p className="mt-2 text-sm text-muted-foreground">
        {t("forgotPassword.successResend")}{" "}
        <Link to="/forgot-password" className="underline-offset-2 hover:underline">
          {t("forgotPassword.successResendLink")}
        </Link>
        .
      </p>
      <Link to="/sign-in" className={buttonVariants({ variant: "outline" }) + " mt-4"}>
        {t("forgotPassword.successBackBtn")}
      </Link>
    </div>
  );
}
