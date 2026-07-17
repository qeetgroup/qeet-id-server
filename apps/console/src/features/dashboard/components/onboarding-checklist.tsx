import {
  Button,
  buttonVariants,
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
  cn,
} from "@qeetrix/ui";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  CheckCircle2Icon,
  CircleIcon,
  KeyRoundIcon,
  PaletteIcon,
  PartyPopperIcon,
  ShieldCheckIcon,
  UsersIcon,
  WebhookIcon,
  XIcon,
} from "lucide-react";
import { useState } from "react";

import * as apiClient from "@/lib/api";
import { useTenantId } from "@/lib/auth";

const DISMISS_KEY = "qeetid-admin-onboarding-dismissed";

// ---- Backend probes ----
//
// Each step is "done" when a simple existence query against the
// backend succeeds. Queries that return 404 (endpoint not shipped
// yet) treat the step as not-done so the checklist quietly waits for
// the backend rather than throwing.

function isDoneSafe<T>(
  data: T | undefined,
  err: unknown,
  predicate: (d: T) => boolean,
): boolean | "loading" {
  if (err instanceof apiClient.ApiError && err.status === 404) return false;
  if (err) return false;
  if (data === undefined) return "loading";
  return predicate(data);
}

interface Step {
  id: string;
  icon: typeof UsersIcon;
  title: string;
  description: string;
  ctaLabel: string;
  ctaHref: string;
  done: boolean | "loading";
}

function useSteps(): Step[] {
  const tenantId = useTenantId();
  const enabled = !!tenantId;

  const branding = useQuery({
    queryKey: ["onboarding", "branding", tenantId],
    queryFn: () =>
      apiClient.api<{ logo_url?: string | null; primary_color?: string | null }>(
        `/v1/tenants/${tenantId}/branding`,
      ),
    enabled,
    meta: { silent: true },
    staleTime: 30_000,
    retry: false,
  });
  const users = useQuery({
    queryKey: ["onboarding", "users", tenantId],
    // Tenant is scoped via the JWT principal, not the URL — there is no
    // /v1/tenants/{tenantId}/users route (QID-02: the checklist previously
    // called that nonexistent path, so "Invite your team" could never
    // check itself off).
    queryFn: () =>
      apiClient.api<{ items: unknown[] }>(`/v1/users`, {
        query: { limit: 2 },
      }),
    enabled,
    meta: { silent: true },
    staleTime: 30_000,
    retry: false,
  });
  const webhooks = useQuery({
    queryKey: ["onboarding", "webhooks", tenantId],
    queryFn: () => apiClient.api<{ items: unknown[] }>(`/v1/tenants/${tenantId}/webhooks`),
    enabled,
    meta: { silent: true },
    staleTime: 30_000,
    retry: false,
  });
  const oidc = useQuery({
    queryKey: ["onboarding", "oidc", tenantId],
    queryFn: () => apiClient.api<{ items: unknown[] }>(`/v1/tenants/${tenantId}/oidc/clients`),
    enabled,
    meta: { silent: true },
    staleTime: 30_000,
    retry: false,
  });
  const apiKeys = useQuery({
    queryKey: ["onboarding", "api-keys", tenantId],
    queryFn: () => apiClient.api<{ items: unknown[] }>(`/v1/tenants/${tenantId}/api-keys`),
    enabled,
    meta: { silent: true },
    staleTime: 30_000,
    retry: false,
  });

  return [
    {
      id: "branding",
      icon: PaletteIcon,
      title: "Set your brand",
      description: "Upload a logo and pick your brand colours.",
      ctaLabel: "Open branding",
      ctaHref: "/settings/branding",
      done: isDoneSafe(branding.data, branding.error, (d) => !!(d.logo_url || d.primary_color)),
    },
    {
      id: "invite",
      icon: UsersIcon,
      title: "Invite your team",
      description: "Bring in admins, engineers, or support staff.",
      ctaLabel: "Invite teammates",
      ctaHref: "/invitations",
      done: isDoneSafe(users.data, users.error, (d) => (d.items?.length ?? 0) > 1),
    },
    {
      id: "oauth-app",
      icon: ShieldCheckIcon,
      title: "Register an application",
      description: "Hook up your first OAuth/OIDC client to start signing users in.",
      ctaLabel: "Add application",
      ctaHref: "/auth/connections/oidc",
      done: isDoneSafe(oidc.data, oidc.error, (d) => (d.items?.length ?? 0) > 0),
    },
    {
      id: "api-key",
      icon: KeyRoundIcon,
      title: "Create an API key",
      description: "Service-to-service auth for your backend integrations.",
      ctaLabel: "Create key",
      ctaHref: "/auth/api/keys",
      done: isDoneSafe(apiKeys.data, apiKeys.error, (d) => (d.items?.length ?? 0) > 0),
    },
    {
      id: "webhook",
      icon: WebhookIcon,
      title: "Subscribe to an event webhook",
      description: "Listen for sign-ins, role changes, audit events.",
      ctaLabel: "Add webhook",
      ctaHref: "/developer/webhooks",
      done: isDoneSafe(webhooks.data, webhooks.error, (d) => (d.items?.length ?? 0) > 0),
    },
  ];
}

/**
 * OnboardingChecklist nudges a fresh workspace through the five most
 * common first-day tasks. It introspects existing API queries to mark
 * steps done — no backend coordination required. Auto-hides once
 * every step is complete; the user can also dismiss it explicitly
 * (state persisted in localStorage so it doesn't reappear on refresh).
 */
export function OnboardingChecklist() {
  const [dismissed, setDismissed] = useState(
    () => typeof window !== "undefined" && localStorage.getItem(DISMISS_KEY) === "1",
  );
  const steps = useSteps();

  if (dismissed) return null;

  const total = steps.length;
  const doneCount = steps.filter((s) => s.done === true).length;
  const allDone = doneCount === total;
  const stillLoading = steps.some((s) => s.done === "loading");

  function handleDismiss() {
    setDismissed(true);
    try {
      localStorage.setItem(DISMISS_KEY, "1");
    } catch {
      // localStorage may be disabled (private mode); accept the in-memory
      // dismissal for this session and move on.
    }
  }

  if (allDone) {
    return (
      <Card className="border-success/25 bg-success/5 shadow-none hover:shadow-none">
        <CardHeader className="flex flex-row items-start justify-between">
          <div className="flex items-center gap-3">
            <span className="grid size-9 place-items-center rounded-lg bg-success/10 text-success ring-1 ring-success/15">
              <PartyPopperIcon className="size-4" />
            </span>
            <div>
              <CardTitle className="text-base">Workspace fully set up</CardTitle>
              <CardDescription>Every control-plane setup task is complete.</CardDescription>
            </div>
          </div>
          <Button variant="ghost" size="icon" aria-label="Dismiss" onClick={handleDismiss}>
            <XIcon />
          </Button>
        </CardHeader>
      </Card>
    );
  }

  return (
    <Card className="border-border/80 bg-card/80 shadow-none hover:shadow-none">
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="text-sm font-semibold">Workspace readiness</CardTitle>
          <CardDescription>
            {stillLoading ? "Checking your setup…" : `${doneCount} of ${total} steps complete.`}
          </CardDescription>
          <div
            className="mt-3 h-1.5 w-48 max-w-full overflow-hidden rounded-full bg-muted"
            role="progressbar"
            aria-label="Workspace setup progress"
            aria-valuemin={0}
            aria-valuemax={total}
            aria-valuenow={doneCount}
          >
            <div
              className="h-full bg-primary transition-[width] duration-300 ease-(--ease-decelerate)"
              style={{ width: `${(doneCount / total) * 100}%` }}
              aria-hidden="true"
            />
          </div>
        </div>
        <Button variant="ghost" size="icon" aria-label="Dismiss" onClick={handleDismiss}>
          <XIcon />
        </Button>
      </CardHeader>
      <ul className="divide-y divide-border/70 border-t border-border/70">
        {steps.map((step) => {
          const Icon = step.icon;
          const isDone = step.done === true;
          return (
            <li
              key={step.id}
              className={cn(
                "flex items-center gap-3 px-4 py-3 transition-colors duration-150 hover:bg-muted/25",
                isDone && "text-muted-foreground",
              )}
            >
              <div className="shrink-0">
                {isDone ? (
                  <CheckCircle2Icon className="size-5 text-success" />
                ) : (
                  <CircleIcon className="size-5 text-muted-foreground/50" />
                )}
              </div>
              <Icon className="size-4 shrink-0 text-muted-foreground" />
              <div className="min-w-0 flex-1">
                <p className={cn("text-sm font-medium", isDone && "line-through")}>{step.title}</p>
                {!isDone && <p className="text-xs text-muted-foreground">{step.description}</p>}
              </div>
              {!isDone && (
                <Link
                  to={step.ctaHref}
                  className={buttonVariants({ variant: "outline", size: "sm" })}
                >
                  {step.ctaLabel}
                </Link>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
