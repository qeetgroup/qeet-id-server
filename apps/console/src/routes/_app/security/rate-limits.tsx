import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Skeleton,
} from "@qeetrix/ui";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { GaugeIcon } from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/security/rate-limits")({ component: RateLimitsPage });

type Policy = {
  ip_allowlist: string[] | null;
  ip_denylist: string[] | null;
};

// These are the per-IP defaults baked into platform/cache/ratelimit/limiter.go.
// Per-tenant / per-user / per-api-key overrides now ship backend-side
// (migration 0064_rate_limit_overrides, domains/operations/ratelimits); this
// admin screen isn't wired to that override API yet.
const STATIC_LIMITS: { endpoint: string; limit: string; window: string }[] = [
  { endpoint: "POST /v1/auth/login", limit: "5 req / 20 burst", window: "per IP, sliding" },
  { endpoint: "POST /v1/auth/refresh", limit: "5 req / 20 burst", window: "per IP, sliding" },
  { endpoint: "POST /v1/auth/signup", limit: "5 req / 20 burst", window: "per IP, sliding" },
  { endpoint: "POST /v1/auth/forgot-password", limit: "5 req / 20 burst", window: "per IP, sliding" },
  { endpoint: "POST /v1/oauth/token (client_credentials)", limit: "5 req / 20 burst", window: "per IP, sliding" },
  { endpoint: "Other authed endpoints", limit: "unlimited", window: "—" },
];

function RateLimitsPage() {
  const tenantId = useTenantId();
  const policyQ = useQuery({
    queryKey: ["policy", tenantId],
    queryFn: () => api<Policy>(`/v1/tenants/${tenantId}/policy`),
    enabled: !!tenantId,
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Per-endpoint rate limits and per-tenant network policy. Per-tenant / per-user / per-api-key overrides are supported by the API; managing them from this screen is coming soon."
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Per-endpoint limits</CardTitle>
          <CardDescription>
            Built-in token-bucket limits applied at the gateway in
            <code> backend/internal/platform/ratelimit/limiter.go</code>.
          </CardDescription>
        </CardHeader>
        <CardContent className="divide-y rounded-md border">
          {STATIC_LIMITS.map((row) => (
            <div key={row.endpoint} className="flex items-center justify-between gap-4 p-3 text-sm">
              <code className="text-xs">{row.endpoint}</code>
              <div className="flex items-center gap-2">
                <Badge variant="muted">{row.limit}</Badge>
                <span className="text-xs text-muted-foreground">{row.window}</span>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Network policy</CardTitle>
          <CardDescription>
            Tenant-level IP filtering. Manage in{" "}
            <Link to="/access/policies" className="underline">Roles & Permissions → Policies</Link>.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {policyQ.isLoading ? (
            <div className="space-y-3">{[...Array(2)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : policyQ.isError ? (
            <div className="text-sm text-destructive">{(policyQ.error as Error).message}</div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <p className="mb-2 text-xs font-medium text-muted-foreground">Allowlist ({policyQ.data?.ip_allowlist?.length ?? 0})</p>
                {policyQ.data?.ip_allowlist?.length ? (
                  <div className="flex flex-wrap gap-1">
                    {policyQ.data.ip_allowlist.map((c) => <Badge key={c} variant="muted">{c}</Badge>)}
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground">No allowlist — open to all source IPs.</p>
                )}
              </div>
              <div>
                <p className="mb-2 text-xs font-medium text-muted-foreground">Denylist ({policyQ.data?.ip_denylist?.length ?? 0})</p>
                {policyQ.data?.ip_denylist?.length ? (
                  <div className="flex flex-wrap gap-1">
                    {policyQ.data.ip_denylist.map((c) => <Badge key={c} variant="destructive">{c}</Badge>)}
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground">No denied CIDRs.</p>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="border-amber-500/40 bg-amber-50/30 dark:bg-amber-950/20">
        <CardContent className="flex items-start gap-3 p-4">
          <GaugeIcon className="size-5 text-amber-700 dark:text-amber-500" />
          <div className="text-sm">
            <p className="font-medium">Per-tenant rate-limit controls coming to this screen.</p>
            <p className="text-muted-foreground">
              The API already supports per-tenant / per-user / per-api-key overrides (migration
              <code> 0064_rate_limit_overrides</code>); a UI to view and edit them from here is on the way.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
