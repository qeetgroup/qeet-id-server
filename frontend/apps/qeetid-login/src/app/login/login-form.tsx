"use client";

import { Button, Card, CardContent, Input } from "@qeetrix/ui";
import { useState, type FormEvent } from "react";

import { API_BASE_URL, ApiError, apiPost } from "@/lib/api";

// safeReturnTo guards against open redirects: we only ever bounce back to our
// own backend's /oauth/authorize endpoint.
function safeReturnTo(returnTo: string): string | null {
  if (!returnTo) return null;
  try {
    const u = new URL(returnTo);
    const base = new URL(API_BASE_URL);
    if (u.origin === base.origin && u.pathname.endsWith("/oauth/authorize")) {
      return u.toString();
    }
  } catch {
    /* malformed — fall through */
  }
  return null;
}

export function LoginForm({ returnTo }: { returnTo: string }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await apiPost("/v1/auth/session", { email, password });
      const dest = safeReturnTo(returnTo);
      // No valid return_to (e.g. visited directly) → nothing to continue to.
      window.location.href = dest ?? "/login";
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Please try again.");
      setLoading(false);
    }
  }

  return (
    <Card className="w-full max-w-sm">
      <CardContent className="space-y-6 pt-6">
        <div className="space-y-1 text-center">
          <h1 className="text-xl font-semibold tracking-tight">Sign in to continue</h1>
          <p className="text-muted-foreground text-sm">Use your Qeet ID account.</p>
        </div>

        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="email" className="text-sm font-medium">
              Email
            </label>
            <Input
              id="email"
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
            />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="password" className="text-sm font-medium">
              Password
            </label>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          {error && (
            <p role="alert" className="text-destructive text-sm">
              {error}
            </p>
          )}

          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? "Signing in…" : "Sign in"}
          </Button>
        </form>

        <p className="text-muted-foreground text-center text-xs">
          Passkey and social sign-in are coming soon.
        </p>
      </CardContent>
    </Card>
  );
}
