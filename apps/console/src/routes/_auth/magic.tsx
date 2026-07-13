import { Button, buttonVariants, Card, CardContent } from "@qeetrix/ui";
import { createFileRoute, Link, useSearch } from "@tanstack/react-router";
import { AlertTriangleIcon, CheckCircle2Icon, Loader2Icon, MailIcon } from "lucide-react";
import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";

import { BrandHero } from "@/features/auth/components/brand-hero";
import { ApiError } from "@/lib/api";
import { useConsumeMagicLink } from "@/lib/auth";

interface MagicSearch {
  token?: string;
}

export const Route = createFileRoute("/_auth/magic")({
  component: MagicLinkPage,
  validateSearch: (search: Record<string, unknown>): MagicSearch => ({
    token: typeof search.token === "string" ? search.token : undefined,
  }),
});

function MagicLinkPage() {
  const { t } = useTranslation("authFlow");
  const { token } = useSearch({ from: "/_auth/magic" });
  const consume = useConsumeMagicLink();

  // Auto-consume on mount when the URL carries a token. useRef guards
  // against double-fire from React 19 strict mode.
  const firedRef = useRef(false);
  useEffect(() => {
    if (!token || firedRef.current) return;
    firedRef.current = true;
    consume.mutate(token);
  }, [token, consume]);

  return (
    <div className="flex flex-col gap-6">
      <Card className="overflow-hidden p-0">
        <CardContent className="grid p-0 md:grid-cols-2">
          <div className="flex flex-col items-center justify-center gap-3 p-8 text-center">
            {renderStatus({ token, consume, t })}
          </div>
          <BrandHero />
        </CardContent>
      </Card>
    </div>
  );
}

function renderStatus({
  token,
  consume,
  t,
}: {
  token: string | undefined;
  consume: ReturnType<typeof useConsumeMagicLink>;
  t: (key: string) => string;
}) {
  if (!token) {
    return (
      <>
        <AlertTriangleIcon className="size-10 text-amber-500" />
        <h1 className="text-2xl font-bold">{t("magic.missingTitle")}</h1>
        <p className="text-balance text-muted-foreground">{t("magic.missingText")}</p>
        <Link to="/sign-in" className={buttonVariants({ variant: "outline" }) + " mt-2"}>
          {t("magic.backToSignIn")}
        </Link>
      </>
    );
  }

  if (consume.isPending || consume.isIdle) {
    return (
      <>
        <Loader2Icon className="size-10 animate-spin text-sky-500" />
        <h1 className="text-2xl font-bold">{t("magic.loadingTitle")}</h1>
        <p className="text-balance text-muted-foreground">{t("magic.loadingText")}</p>
      </>
    );
  }

  if (consume.isSuccess) {
    return (
      <>
        <CheckCircle2Icon className="size-10 text-emerald-500" />
        <h1 className="text-2xl font-bold">{t("magic.successTitle")}</h1>
        <p className="text-balance text-muted-foreground">{t("magic.successText")}</p>
      </>
    );
  }

  // Error path. Distinguish expired/used vs everything else so the user
  // sees actionable copy.
  const status = consume.error instanceof ApiError ? consume.error.status : undefined;
  const detail = consume.error instanceof Error ? consume.error.message : "Unknown error";
  const isExpiredOrUsed = status === 400;

  return (
    <>
      <MailIcon className="size-10 text-rose-500" />
      <h1 className="text-2xl font-bold">
        {isExpiredOrUsed ? t("magic.expiredTitle") : t("magic.errorTitle")}
      </h1>
      <p className="text-balance text-muted-foreground">
        {isExpiredOrUsed ? t("magic.expiredText") : detail}
      </p>
      <div className="mt-4 flex gap-2">
        <Link to="/sign-in" className={buttonVariants({ variant: "outline", size: "sm" })}>
          {t("magic.backToSignIn")}
        </Link>
        {/* The "request a new link" entry point is the sign-in form's
            magic-link flow — for now we route there. Future: a dedicated
            /magic/start UI. */}
        <Button
          size="sm"
          variant="ghost"
          onClick={() => {
            window.location.href = "/sign-in?from=magic";
          }}
        >
          {t("magic.sendNewLink")}
        </Button>
      </div>
    </>
  );
}
