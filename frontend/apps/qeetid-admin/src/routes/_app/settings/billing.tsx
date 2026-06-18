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
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { CheckIcon } from "lucide-react";
import { useMemo, useState } from "react";

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

function BillingPage() {
  const plansQ = usePlans();
  const subQ = useSubscription();
  const invoicesQ = useInvoices();
  const checkoutM = useCheckout();
  const cancelM = useCancelSubscription();

  const plans = useMemo(() => plansQ.data?.items ?? [], [plansQ.data]);
  const sub = subQ.data;

  // Currencies offered = union of every plan's priced currencies.
  const currencies = useMemo(() => {
    const set = new Set<string>();
    for (const p of plans) for (const c of Object.keys(p.prices)) set.add(c);
    return [...set].sort();
  }, [plans]);

  const [currency, setCurrency] = useState<string | null>(null);
  const activeCurrency =
    currency ?? sub?.currency ?? (currencies.includes("USD") ? "USD" : currencies[0]) ?? "USD";

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Your subscription plan, billed in your chosen currency. Invoices are generated each period."
        actions={
          currencies.length > 0 ? (
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Currency</span>
              <Select value={activeCurrency} onValueChange={setCurrency}>
                <SelectTrigger className="w-[110px]">
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
        isEmpty={plans.length === 0}
        emptyTitle="No plans configured."
        skeletonRows={3}
      >
        {/* Current subscription */}
        {sub && sub.status !== "none" && (
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base">Current plan — {sub.plan_name}</CardTitle>
                  <CardDescription>
                    {formatMoney(sub.amount_minor, sub.currency)} / {sub.interval}
                    {sub.current_period_end && (
                      <>
                        {" · "}
                        {sub.cancel_at_period_end ? "cancels" : "renews"}{" "}
                        <TimeSince value={sub.current_period_end} />
                      </>
                    )}
                  </CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <StatusPill status={sub.status} />
                  {!sub.cancel_at_period_end && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        if (confirm("Cancel at the end of the current period?")) cancelM.mutate();
                      }}
                      disabled={cancelM.isPending}
                    >
                      Cancel
                    </Button>
                  )}
                </div>
              </div>
            </CardHeader>
          </Card>
        )}

        {/* Plan picker */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {plans.map((plan) => {
            const isCurrent = sub?.plan_code === plan.code && !sub?.cancel_at_period_end;
            const priceMinor = plan.prices[activeCurrency];
            const priced = priceMinor !== undefined;
            return (
              <Card key={plan.code} className={plan.code === "pro" ? "border-primary" : undefined}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base">{plan.name}</CardTitle>
                    {plan.code === "pro" && <Badge variant="default">Popular</Badge>}
                  </div>
                  <CardDescription>{plan.description}</CardDescription>
                  <div className="pt-2">
                    <span className="text-2xl font-bold text-foreground">
                      {priced ? formatMoney(priceMinor, activeCurrency) : "—"}
                    </span>{" "}
                    <span className="text-xs text-muted-foreground">/ {plan.interval}</span>
                  </div>
                </CardHeader>
                <CardContent className="flex flex-col gap-4">
                  <ul className="flex flex-col gap-2 text-sm">
                    {plan.features.map((f) => (
                      <li key={f} className="flex items-start gap-2">
                        <CheckIcon className="mt-0.5 size-4 shrink-0 text-emerald-500" />
                        {f}
                      </li>
                    ))}
                  </ul>
                  <Button
                    variant={plan.code === "pro" ? "default" : "outline"}
                    disabled={isCurrent || !priced || checkoutM.isPending}
                    onClick={() =>
                      checkoutM.mutate({ plan_code: plan.code, currency: activeCurrency })
                    }
                  >
                    {isCurrent
                      ? "Current plan"
                      : !priced
                        ? `Not priced in ${activeCurrency}`
                        : `Switch to ${plan.name}`}
                  </Button>
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* Invoices */}
        <Card>
          <CardHeader>
            <CardTitle>Invoices</CardTitle>
            <CardDescription>Generated at the start of each billing period.</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <DataState
              isLoading={invoicesQ.isLoading}
              isError={invoicesQ.isError}
              error={invoicesQ.error}
              isEmpty={(invoicesQ.data?.items?.length ?? 0) === 0}
              emptyTitle="No invoices yet."
              skeletonRows={2}
            >
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Issued</TableHead>
                    <TableHead>Plan</TableHead>
                    <TableHead>Amount</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(invoicesQ.data?.items ?? []).map((inv) => (
                    <TableRow key={inv.id}>
                      <TableCell className="text-xs text-muted-foreground">
                        <TimeSince value={inv.issued_at} />
                      </TableCell>
                      <TableCell className="capitalize">{inv.plan_code}</TableCell>
                      <TableCell>{formatMoney(inv.amount_minor, inv.currency)}</TableCell>
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
