import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  StatusPill,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
  cn,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { CheckIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import {
  formatMoney,
  useCancelSubscription,
  useCheckout,
  useInvoices,
  usePlans,
  useSubscription,
} from "@/lib/billing";

export const Route = createFileRoute("/_app/settings/billing")({ component: BillingPage });

// Static plan display data — pricing, features, and visual decoration.
// The backend still controls checkout / subscription state; we match on plan.code.
const PLANS = [
  {
    code: "free",
    name: "Free",
    price: "$0",
    period: "forever",
    mau: "Up to 5,000 MAU",
    featured: false,
    badge: null as string | null,
    features: [
      "5,000 monthly active users",
      "Unlimited social providers",
      "Passkeys + TOTP MFA",
      "RBAC — up to 5 roles",
      "7-day audit log retention",
      "Community support",
      "Hosted US or EU",
    ],
  },
  {
    code: "starter",
    name: "Starter",
    price: "$29",
    period: "/ month",
    mau: "Up to 15,000 MAU",
    featured: false,
    badge: null as string | null,
    features: [
      "15,000 monthly active users",
      "All social providers + magic link",
      "Passkeys + all MFA methods",
      "RBAC — unlimited roles",
      "30-day audit log retention",
      "Email support, 48h SLA",
      "99.9% uptime SLA",
    ],
  },
  {
    code: "pro",
    name: "Pro",
    price: "$99",
    period: "/ month + $0.02 / MAU",
    mau: "Up to 50,000 MAU included",
    featured: true,
    badge: "Most popular" as string | null,
    features: [
      "50,000 MAU included",
      "All providers + magic link",
      "Unlimited RBAC + ABAC policies",
      "Audit log export — 90-day retention",
      "Email + chat support, 24h SLA",
      "99.95% uptime SLA",
      "US, EU, APAC data residency",
    ],
  },
  {
    code: "enterprise",
    name: "Enterprise",
    price: "Custom",
    period: "annual contract",
    mau: "Unlimited MAU & tenants",
    featured: false,
    badge: null as string | null,
    features: [
      "Unlimited MAU and tenants",
      "SAML, OIDC, SCIM, LDAP",
      "Dedicated single-tenant deploy",
      "Audit log → your S3 / SIEM",
      "Named CSM + 24/7 phone support",
      "99.99% uptime SLA + custom DPA",
      "SOC 2 Type II, ISO 27001, HIPAA BAA",
    ],
  },
];

function BillingPage() {
  const { t } = useTranslation("settings");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const plansQ = usePlans();
  const subQ = useSubscription();
  const invoicesQ = useInvoices();
  const checkoutM = useCheckout();
  const cancelM = useCancelSubscription();

  const apiPlans = useMemo(() => plansQ.data?.items ?? [], [plansQ.data]);
  const sub = subQ.data;

  // Currencies offered = union of every plan's priced currencies (still used for checkout).
  const currencies = useMemo(() => {
    const set = new Set<string>();
    for (const p of apiPlans) for (const c of Object.keys(p.prices)) set.add(c);
    return [...set].sort();
  }, [apiPlans]);

  const [currency, setCurrency] = useState<string | null>(null);
  const activeCurrency =
    currency ?? sub?.currency ?? (currencies.includes("USD") ? "USD" : currencies[0]) ?? "USD";

  return (
    <div className="flex min-w-0 flex-col gap-6">
      {confirmDialog}
      <PageHeader
        description={t("billing.description")}
        actions={
          currencies.length > 0 ? (
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">{t("billing.currency")}</span>
              <Select value={activeCurrency} onValueChange={setCurrency}>
                <SelectTrigger className="w-27.5">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {currencies.map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          ) : undefined
        }
      />

      <DataState
        isLoading={plansQ.isLoading || subQ.isLoading}
        isError={plansQ.isError}
        error={plansQ.error}
        isEmpty={false}
        emptyTitle={t("billing.empty")}
        skeletonRows={3}
      >
        {/* Current subscription */}
        {sub && sub.status !== "none" && (
          <Card>
            <CardHeader>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <CardTitle className="text-base">{t("billing.currentPlan.title")}</CardTitle>
                  <CardDescription className="mt-1">
                    <span className="font-medium text-foreground">{sub.plan_name}</span>
                    {" · "}
                    {formatMoney(sub.amount_minor, sub.currency)} / {sub.interval}
                  </CardDescription>
                  {sub.current_period_end && (
                    <p className="mt-1 text-xs text-muted-foreground">
                      {sub.cancel_at_period_end ? t("billing.currentPlan.cancels") : t("billing.currentPlan.renews")}{" "}
                      <TimeSince value={sub.current_period_end} />
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <StatusPill status={sub.status} />
                  {!sub.cancel_at_period_end && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        openConfirm({
                          title: t("billing.currentPlan.cancelConfirmTitle"),
                          description: t("billing.currentPlan.cancelConfirmDescription"),
                          variant: "destructive",
                          confirmLabel: t("billing.currentPlan.cancelConfirmLabel"),
                          onConfirm: () => cancelM.mutate(),
                        })
                      }
                      disabled={cancelM.isPending}
                    >
                      {t("billing.currentPlan.cancelPlan")}
                    </Button>
                  )}
                </div>
              </div>
            </CardHeader>
          </Card>
        )}

        {/* Plan picker — rendered from static PLANS, isCurrent matched via API subscription */}
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 xl:grid-cols-4">
          {PLANS.map((plan) => {
            const isCurrent = sub?.plan_code === plan.code && !sub?.cancel_at_period_end;
            const isEnterprise = plan.code === "enterprise";

            return (
              <Card
                key={plan.code}
                className={cn(
                  "relative flex flex-col overflow-hidden transition-shadow",
                  plan.featured
                    ? "border-primary shadow-lg shadow-primary/10"
                    : "border-border/60",
                  isCurrent && "ring-2 ring-primary/30",
                )}
              >
                {/* Top gradient stripe for featured plan */}
                {plan.featured && (
                  <span
                    aria-hidden
                    className="absolute inset-x-0 top-0 h-0.5 bg-linear-to-r from-primary/60 via-primary to-primary/60"
                  />
                )}

                <CardHeader className="pb-4">
                  <div className="flex items-start justify-between gap-2">
                    <CardTitle className="text-base font-semibold">{plan.name}</CardTitle>
                    <div className="flex flex-col items-end gap-1">
                      {plan.badge && (
                        <Badge
                          variant={plan.featured ? "default" : "secondary"}
                          className="text-[10px]"
                        >
                          {plan.badge}
                        </Badge>
                      )}
                      {isCurrent && (
                        <Badge
                          variant="outline"
                          className="border-primary/40 text-[10px] text-primary"
                        >
                          {t("billing.plan.current")}
                        </Badge>
                      )}
                    </div>
                  </div>

                  {/* Price */}
                  <div className="pt-3">
                    <div className="flex items-baseline gap-1">
                      <span
                        className={cn(
                          "font-display text-3xl font-bold tracking-tight",
                          plan.featured && "text-primary",
                        )}
                      >
                        {plan.price}
                      </span>
                      {plan.price !== "Custom" && (
                        <span className="text-xs text-muted-foreground">{plan.period}</span>
                      )}
                    </div>
                    {plan.price === "Custom" && (
                      <p className="text-xs text-muted-foreground capitalize">{plan.period}</p>
                    )}
                    <p className="mt-1 text-xs text-muted-foreground">{plan.mau}</p>
                  </div>
                </CardHeader>

                <CardContent className="flex flex-1 flex-col gap-5">
                  {/* Feature list */}
                  <ul className="flex flex-1 flex-col gap-2 text-sm">
                    {plan.features.map((f) => (
                      <li key={f} className="flex items-start gap-2">
                        <CheckIcon className="mt-0.5 size-3.5 shrink-0 text-emerald-500" />
                        <span className="text-muted-foreground">{f}</span>
                      </li>
                    ))}
                  </ul>

                  {/* CTA */}
                  {isEnterprise ? (
                    <div className="mt-auto pt-2">
                      <p className="text-center text-xs text-muted-foreground">
                        Need Enterprise?{" "}
                        <a
                          href="mailto:sales@qeet.in"
                          className="underline underline-offset-2 hover:text-foreground"
                        >
                          {t("billing.plan.salesEmail")}
                        </a>
                      </p>
                    </div>
                  ) : (
                    <Button
                      variant={plan.featured ? "default" : "outline"}
                      className="w-full"
                      disabled={isCurrent || checkoutM.isPending}
                      onClick={() =>
                        checkoutM.mutate({ plan_code: plan.code, currency: activeCurrency })
                      }
                    >
                      {isCurrent ? t("billing.plan.isCurrent") : t("billing.plan.switchTo", { name: plan.name })}
                    </Button>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* Invoices */}
        <Card>
          <CardHeader>
            <CardTitle>{t("billing.invoices.title")}</CardTitle>
            <CardDescription>{t("billing.invoices.description")}</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <DataState
              isLoading={invoicesQ.isLoading}
              isError={invoicesQ.isError}
              error={invoicesQ.error}
              isEmpty={(invoicesQ.data?.items?.length ?? 0) === 0}
              emptyTitle={t("billing.invoices.empty")}
              skeletonRows={2}
            >
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("billing.invoices.columns.issued")}</TableHead>
                    <TableHead>{t("billing.invoices.columns.period")}</TableHead>
                    <TableHead>{t("billing.invoices.columns.plan")}</TableHead>
                    <TableHead>{t("billing.invoices.columns.amount")}</TableHead>
                    <TableHead>{t("billing.invoices.columns.status")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(invoicesQ.data?.items ?? []).map((inv) => (
                    <TableRow key={inv.id}>
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                        <TimeSince value={inv.issued_at} />
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                        <TimeSince value={inv.period_start} />
                        {" – "}
                        <TimeSince value={inv.period_end} />
                      </TableCell>
                      <TableCell className="capitalize">{inv.plan_code}</TableCell>
                      <TableCell className="font-medium">
                        {formatMoney(inv.amount_minor, inv.currency)}
                      </TableCell>
                      <TableCell>
                        <StatusPill status={inv.status} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </DataState>
          </CardContent>
        </Card>
      </DataState>
    </div>
  );
}
