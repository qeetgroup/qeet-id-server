import { Card, CardContent, EmptyState } from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { ServerIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/developer/infrastructure")({
  component: InfrastructurePage,
});

// QID-05: this page previously rendered hardcoded latency/services/datastore
// arrays feeding real-looking charts and tables, despite claiming "real-time
// platform health" — with no backend behind it. Replaced with an honest
// placeholder until platform-health telemetry is actually wired, rather than
// present fabricated metrics an operator might trust.
function InfrastructurePage() {
  const { t } = useTranslation("developer");
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description={t("infrastructure.description")} />
      <Card>
        <CardContent className="py-16">
          <EmptyState
            icon={ServerIcon}
            title={t("infrastructure.comingSoon.title")}
            description={t("infrastructure.comingSoon.description")}
          />
        </CardContent>
      </Card>
    </div>
  );
}
