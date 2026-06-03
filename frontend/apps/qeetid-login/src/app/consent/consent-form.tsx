"use client";

import { Button, Card, CardContent } from "@qeetrix/ui";
import { useState } from "react";

import { ApiError, apiPost } from "@/lib/api";

export type ConsentParams = {
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  nonce: string;
  code_challenge: string;
  code_challenge_method: string;
};

// Human-readable descriptions for the standard OIDC scopes.
const SCOPE_LABELS: Record<string, string> = {
  openid: "Verify your identity",
  profile: "See your basic profile (name)",
  email: "See your email address",
  offline_access: "Stay signed in (refresh access)",
};

export function ConsentForm({ params }: { params: ConsentParams }) {
  const scopes = params.scope.split(/\s+/).filter(Boolean);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function decide(approve: boolean) {
    setError(null);
    setLoading(true);
    try {
      const res = await apiPost<{ redirect: string }>("/v1/oauth/authorize/decision", {
        approve,
        ...params,
      });
      window.location.href = res.redirect;
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Please try again.");
      setLoading(false);
    }
  }

  return (
    <Card className="w-full max-w-md">
      <CardContent className="space-y-5 pt-6">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold tracking-tight">Authorize access</h1>
          <p className="text-muted-foreground text-sm">
            <span className="text-foreground font-medium">{params.client_id || "An application"}</span>{" "}
            wants permission to:
          </p>
        </div>

        <ul className="space-y-2 text-sm">
          {scopes.length === 0 && <li className="text-muted-foreground">Sign you in</li>}
          {scopes.map((s) => (
            <li key={s} className="flex gap-2">
              <span aria-hidden>•</span>
              <span>{SCOPE_LABELS[s] ?? s}</span>
            </li>
          ))}
        </ul>

        {error && (
          <p role="alert" className="text-destructive text-sm">
            {error}
          </p>
        )}

        <div className="flex gap-3">
          <Button variant="outline" className="flex-1" disabled={loading} onClick={() => decide(false)}>
            Deny
          </Button>
          <Button className="flex-1" disabled={loading} onClick={() => decide(true)}>
            {loading ? "…" : "Allow"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
