import { Card, CardContent, EmptyState } from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { BotIcon } from "lucide-react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/developer/bots")({ component: BotsPage });

// QID-04: this page previously rendered a fabricated dashboard (hardcoded
// "Runs (24h): 3,420" stats, a seeded automations table, and New/Play/Edit
// buttons with no handlers) against no backend at all. A convincing fake is
// worse than an honest placeholder for an enterprise evaluator, so until the
// automations backend exists this is a clear "coming soon" surface with no
// fake data and no dead controls.
function BotsPage() {
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="Event-driven automations stitched together from triggers and actions." />
      <Card>
        <CardContent className="py-16">
          <EmptyState
            icon={BotIcon}
            title="Automations are coming soon"
            description="Build no-code automations that react to identity events — sign-ins, role changes, risk signals — and run actions in response. This surface isn't available yet; follow the roadmap for availability."
          />
        </CardContent>
      </Card>
    </div>
  );
}
