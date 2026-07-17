import { createFileRoute } from "@tanstack/react-router";

import {
  DashboardOverview,
  NoWorkspaceOnboarding,
} from "@/features/dashboard/components/dashboard-overview";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/")({ component: DashboardPage });

/** Route boundary only; dashboard composition lives in the dashboard feature. */
function DashboardPage() {
  const tenantId = useTenantId();
  return tenantId ? <DashboardOverview /> : <NoWorkspaceOnboarding />;
}
