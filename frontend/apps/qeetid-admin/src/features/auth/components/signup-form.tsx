import {
  Button,
  Card,
  CardContent,
  cn,
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldSeparator,
  Input,
  PasswordStrengthMeter,
  scorePassword,
} from "@qeetid/ui";
import { Link } from "@tanstack/react-router";
import { Apple, Github, Google, Microsoft } from "@thesvg/react";
import { Loader2Icon } from "lucide-react";
import type * as React from "react";
import { useState } from "react";

import { BrandHero } from "./brand-hero";

export type SignupFormValues = {
  email: string;
  password: string;
  display_name: string;
};

type SignupFormProps = React.ComponentProps<"div"> & {
  isLoading?: boolean;
  errorMessage?: string;
  onSignup?: (values: SignupFormValues) => void;
};

export function SignupForm({
  className,
  isLoading = false,
  errorMessage,
  onSignup,
  ...props
}: SignupFormProps) {
  const [mismatch, setMismatch] = useState(false);
  const [password, setPassword] = useState("");
  const passwordScore = scorePassword(password);

  return (
    <div className={cn("flex flex-col gap-6", className)} {...props}>
      <Card className="overflow-hidden p-0">
        <CardContent className="grid p-0 md:grid-cols-2">
          <form
            className="p-6 md:p-8"
            onSubmit={(e) => {
              e.preventDefault();
              const data = new FormData(e.currentTarget);
              const password = String(data.get("password") ?? "");
              const confirm = String(data.get("confirm_password") ?? "");
              if (password !== confirm) {
                setMismatch(true);
                return;
              }
              setMismatch(false);
              onSignup?.({
                email: String(data.get("email") ?? "").trim(),
                password,
                display_name: String(data.get("display_name") ?? "").trim(),
              });
            }}
          >
            <FieldGroup>
              <div className="flex flex-col items-center gap-2 text-center">
                <h1 className="text-2xl font-bold">Create your account</h1>
                <p className="text-sm text-balance text-muted-foreground">
                  We&apos;ll set up a personal workspace for you automatically. You can rename it
                  or create more later.
                </p>
              </div>

              <Field>
                <FieldLabel htmlFor="display_name">Your name</FieldLabel>
                <Input
                  id="display_name"
                  name="display_name"
                  type="text"
                  placeholder="Jane Doe"
                  required
                />
              </Field>

              <Field>
                <FieldLabel htmlFor="email">Email</FieldLabel>
                <Input id="email" name="email" type="email" placeholder="jane@acme.test" required />
                <FieldDescription>We&apos;ll use this for sign-in and notifications.</FieldDescription>
              </Field>

              <Field className="grid grid-cols-2 gap-4">
                <Field>
                  <FieldLabel htmlFor="password">Password</FieldLabel>
                  <Input
                    id="password"
                    name="password"
                    type="password"
                    minLength={8}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    aria-describedby="password-strength"
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="confirm_password">Confirm</FieldLabel>
                  <Input
                    id="confirm_password"
                    name="confirm_password"
                    type="password"
                    minLength={8}
                    required
                  />
                </Field>
              </Field>
              {password.length > 0 && (
                <PasswordStrengthMeter
                  value={password}
                  className="mt-1"
                  feedback={
                    passwordScore < 3
                      ? ["Use 12+ characters mixing upper/lower case, digits, and symbols."]
                      : undefined
                  }
                />
              )}
              <FieldDescription>At least 8 characters.</FieldDescription>

              {mismatch && (
                <Field>
                  <FieldError>Passwords don&apos;t match.</FieldError>
                </Field>
              )}
              {errorMessage && !mismatch && (
                <Field>
                  <FieldError>{errorMessage}</FieldError>
                </Field>
              )}

              <Field>
                <Button type="submit" disabled={isLoading}>
                  {isLoading && <Loader2Icon className="animate-spin" />}
                  {isLoading ? "Creating account…" : "Create account"}
                </Button>
              </Field>

              <FieldSeparator className="*:data-[slot=field-separator-content]:bg-card">
                Or continue with
              </FieldSeparator>

              <Field className="grid grid-cols-4 gap-4">
                <Button variant="outline" type="button" disabled>
                  <Apple className="invert dark:invert-0" />
                  <span className="sr-only">Sign up with Apple</span>
                </Button>
                <Button variant="outline" type="button" disabled>
                  <Google />
                  <span className="sr-only">Sign up with Google</span>
                </Button>
                <Button variant="outline" type="button" disabled>
                  <Github className="dark:invert" />
                  <span className="sr-only">Sign up with GitHub</span>
                </Button>
                <Button variant="outline" type="button" disabled>
                  <Microsoft />
                  <span className="sr-only">Sign up with Microsoft</span>
                </Button>
              </Field>

              <FieldDescription className="text-center">
                Already have an account? <Link to="/sign-in">Sign in</Link>
              </FieldDescription>
            </FieldGroup>
          </form>
          <BrandHero />
        </CardContent>
      </Card>
      <FieldDescription className="px-6 text-center">
        By clicking continue, you agree to our <a href="#">Terms of Service</a> and{" "}
        <a href="#">Privacy Policy</a>.
      </FieldDescription>
    </div>
  );
}
