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
} from "@qeetid/ui";
import { Link } from "@tanstack/react-router";
import { Apple, Github, Google, Microsoft } from "@thesvg/react";
import { Loader2Icon } from "lucide-react";
import type * as React from "react";

import { BrandHero } from "./brand-hero";

export type LoginFormValues = {
  email: string;
  password: string;
};

type LoginFormProps = React.ComponentProps<"div"> & {
  isLoading?: boolean;
  errorMessage?: string;
  onLogin?: (values: LoginFormValues) => void;
};

export function LoginForm({
  className,
  isLoading = false,
  errorMessage,
  onLogin,
  ...props
}: LoginFormProps) {
  return (
    <div className={cn("flex flex-col gap-6", className)} {...props}>
      <Card className="overflow-hidden p-0">
        <CardContent className="grid p-0 md:grid-cols-2">
          <form
            className="p-6 md:p-8"
            onSubmit={(e) => {
              e.preventDefault();
              const data = new FormData(e.currentTarget);
              onLogin?.({
                email: String(data.get("email") ?? "").trim(),
                password: String(data.get("password") ?? ""),
              });
            }}
          >
            <FieldGroup>
              <div className="flex flex-col items-center gap-2 text-center">
                <h1 className="text-2xl font-bold">Welcome back</h1>
                <p className="text-balance text-muted-foreground">
                  Login to your Qeetid admin account
                </p>
              </div>

              <Field>
                <FieldLabel htmlFor="email">Email</FieldLabel>
                <Input id="email" name="email" type="email" placeholder="m@example.com" required />
              </Field>

              <Field>
                <div className="flex items-center">
                  <FieldLabel htmlFor="password">Password</FieldLabel>
                  <Link
                    to="/forgot-password"
                    className="ms-auto text-sm underline-offset-2 hover:underline"
                  >
                    Forgot your password?
                  </Link>
                </div>
                <Input id="password" name="password" type="password" required />
              </Field>

              {errorMessage && (
                <Field>
                  <FieldError>{errorMessage}</FieldError>
                </Field>
              )}

              <Field>
                <Button type="submit" disabled={isLoading}>
                  {isLoading && <Loader2Icon className="animate-spin" />}
                  {isLoading ? "Signing in…" : "Login"}
                </Button>
              </Field>

              <FieldSeparator className="*:data-[slot=field-separator-content]:bg-card">
                Or continue with
              </FieldSeparator>

              <Field className="grid grid-cols-4 gap-4">
                <Button variant="outline" type="button" disabled>
                  <Apple className="invert dark:invert-0" />
                  <span className="sr-only">Login with Apple</span>
                </Button>
                <Button variant="outline" type="button" disabled>
                  <Google />
                  <span className="sr-only">Login with Google</span>
                </Button>
                <Button variant="outline" type="button" disabled>
                  <Github className="dark:invert" />
                  <span className="sr-only">Login with GitHub</span>
                </Button>
                <Button variant="outline" type="button" disabled>
                  <Microsoft />
                  <span className="sr-only">Login with Microsoft</span>
                </Button>
              </Field>

              <FieldDescription className="text-center">
                Don&apos;t have an account? <Link to="/sign-up">Sign up</Link>
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
