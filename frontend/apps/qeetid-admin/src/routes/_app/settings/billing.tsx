import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Skeleton,
} from "@qeetrix/ui";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { CheckIcon, ConstructionIcon, CreditCardIcon } from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/settings/billing")({ component: BillingPage });

type Tenant = {
  id: string;
  name: string;
  plan: string;
  region: string;
};

const PLANS = [
  {
    name: "Free",
    id: "free",
    price: "$0",
    period: "forever",
    features: [
      "Up to 10K monthly active users",
      "Email + social + magic-link auth",
      "Basic RBAC",
      "Community support",
      "7-day audit log retention",
    ],
  },
  {
    name: "Pro",
    id: "pro",
    price: "$0.025",
    period: "per MAU / month",
    features: [
      "Everything in Free",
      "Webhooks + audit log export",
      "Custom branding + custom domain",
      "Email support, 24h SLA",
      "90-day audit log retention",
    ],
    highlighted: true,
  },
  {
    name: "Enterprise",
    id: "enterprise",
    price: "Custom",
    period: "annual contract",
    features: [
      "Everything in Pro",
      "SAML SSO + SCIM provisioning",
      "Dedicated tenant-level rate limits",
      "Slack channel + dedicated CSM",
      "Unlimited audit log retention",
      "SOC 2 / GDPR DPA review",
    ],
  },
];

function BillingPage() {
  const tenantId = useTenantId();
  const tenantQ = useQuery({
    queryKey: ["tenant", tenantId],
    queryFn: () => api<Tenant>(`/v1/tenants/${tenantId}`),
    enabled: !!tenantId,
  });

  const currentPlan = tenantQ.data?.plan ?? "free";

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="Your subscription plan and usage. Stripe-backed self-serve checkout is on the v1.0 punch list (GAP-ANALYSIS P1-9)." />

      <Card className="border-amber-500/40 bg-amber-50/30 dark:bg-amber-950/20">
        <CardContent className="flex items-start gap-3 p-4">
          <ConstructionIcon className="size-5 text-amber-700 dark:text-amber-500" />
          <div className="text-sm">
            <p className="font-medium">Stripe integration not yet wired.</p>
            <p className="text-muted-foreground">
              Plans are stored on the tenant row but there&apos;s no real billing backend today.
              Switching plans below uses the existing{" "}
              <Link to="/settings/workspace/general" className="underline">Workspace settings</Link>{" "}
              endpoint as a stop-gap.
            </p>
          </div>
        </CardContent>
      </Card>

      {tenantQ.isLoading ? (
        <Card><CardContent className="p-6"><Skeleton className="h-10 w-full" /></CardContent></Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Current plan</CardTitle>
            <CardDescription>{tenantQ.data?.name ?? "—"} · {tenantQ.data?.region ?? "—"}</CardDescription>
          </CardHeader>
          <CardContent className="flex items-center gap-3">
            <Badge variant="success" className="text-sm">{currentPlan}</Badge>
            <span className="text-sm text-muted-foreground">
              {currentPlan === "free" && "No charges. Upgrade to unlock branding + webhooks."}
              {currentPlan === "pro" && "Per-MAU pricing — see invoices in Stripe (TBD)."}
              {currentPlan === "enterprise" && "Custom annual contract."}
            </span>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-3">
        {PLANS.map((plan) => {
          const isCurrent = plan.id === currentPlan;
          return (
            <Card key={plan.id} className={plan.highlighted ? "border-primary" : undefined}>
              <CardHeader>
                <div className="flex items-baseline justify-between">
                  <CardTitle className="text-base">{plan.name}</CardTitle>
                  {plan.highlighted && <Badge variant="default">Popular</Badge>}
                </div>
                <CardDescription>
                  <span className="text-2xl font-bold text-foreground">{plan.price}</span>{" "}
                  <span className="text-xs">{plan.period}</span>
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 text-sm">
                  {plan.features.map((f) => (
                    <li key={f} className="flex items-start gap-2">
                      <CheckIcon className="mt-0.5 size-3.5 text-emerald-600 dark:text-emerald-400" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
                <Button
                  variant={plan.highlighted ? "default" : "outline"}
                  className="mt-4 w-full"
                  disabled={isCurrent}
                >
                  <CreditCardIcon />
                  {isCurrent ? "Current plan" : `Switch to ${plan.name}`}
                </Button>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
