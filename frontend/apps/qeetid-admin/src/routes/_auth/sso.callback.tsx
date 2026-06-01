import { Button, Card, CardContent, buttonVariants } from "@qeetrix/ui";
import { Link, createFileRoute } from "@tanstack/react-router";
import { AlertTriangleIcon, CheckCircle2Icon, Loader2Icon, ShieldXIcon } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { BrandHero } from "@/features/auth/components/brand-hero";
import { ApiError } from "@/lib/api";
import { useConsumeSamlCode } from "@/lib/auth";

export const Route = createFileRoute("/_auth/sso/callback")({ component: SsoCallbackPage });

// The SAML ACS redirects here with the one-time code in the URL fragment
// (#saml_code=…), which — unlike a query string — is never sent to the server
// or written to access logs.
function readSamlCode(): string | null {
  if (typeof window === "undefined") return null;
  const hash = window.location.hash.replace(/^#/, "");
  return new URLSearchParams(hash).get("saml_code");
}

function SsoCallbackPage() {
  const consume = useConsumeSamlCode();
  const [code] = useState(readSamlCode);

  const firedRef = useRef(false);
  useEffect(() => {
    if (!code || firedRef.current) return;
    firedRef.current = true;
    // Drop the code from the URL so it isn't left in history.
    window.history.replaceState(null, "", window.location.pathname);
    consume.mutate(code);
  }, [code, consume]);

  return (
    <div className="flex flex-col gap-6">
      <Card className="overflow-hidden p-0">
        <CardContent className="grid p-0 md:grid-cols-2">
          <div className="flex flex-col items-center justify-center gap-3 p-8 text-center">
            {renderStatus({ code, consume })}
          </div>
          <BrandHero />
        </CardContent>
      </Card>
    </div>
  );
}

function renderStatus({
  code,
  consume,
}: {
  code: string | null;
  consume: ReturnType<typeof useConsumeSamlCode>;
}) {
  if (!code) {
    return (
      <>
        <AlertTriangleIcon className="size-10 text-amber-500" />
        <h1 className="text-2xl font-bold">No sign-in code</h1>
        <p className="text-balance text-muted-foreground">
          This page completes a SAML single sign-on. Start the flow from your identity provider, or
          sign in directly.
        </p>
        <Link to="/sign-in" className={buttonVariants({ variant: "outline" }) + " mt-2"}>
          Back to sign in
        </Link>
      </>
    );
  }

  if (consume.isPending || consume.isIdle) {
    return (
      <>
        <Loader2Icon className="size-10 animate-spin text-sky-500" />
        <h1 className="text-2xl font-bold">Signing you in…</h1>
        <p className="text-balance text-muted-foreground">Completing single sign-on.</p>
      </>
    );
  }

  if (consume.isSuccess) {
    return (
      <>
        <CheckCircle2Icon className="size-10 text-emerald-500" />
        <h1 className="text-2xl font-bold">Signed in</h1>
        <p className="text-balance text-muted-foreground">Redirecting to your dashboard…</p>
      </>
    );
  }

  const detail = consume.error instanceof ApiError ? consume.error.message : "Single sign-on failed.";
  return (
    <>
      <ShieldXIcon className="size-10 text-rose-500" />
      <h1 className="text-2xl font-bold">Couldn&apos;t complete sign-in</h1>
      <p className="text-balance text-muted-foreground">
        {detail} The code is single-use and short-lived — start the SSO flow again from your identity
        provider.
      </p>
      <div className="mt-4 flex gap-2">
        <Link to="/sign-in" className={buttonVariants({ variant: "outline", size: "sm" })}>
          Back to sign in
        </Link>
        <Button size="sm" variant="ghost" onClick={() => window.location.reload()}>
          Try again
        </Button>
      </div>
    </>
  );
}
