import { createFileRoute } from "@tanstack/react-router";

import { ComplianceEvidencePage } from "@/features/compliance/evidence-page";

export const Route = createFileRoute("/_app/security/compliance/soc2")({
  component: Soc2Page,
});

function Soc2Page() {
  return <ComplianceEvidencePage framework="soc2" />;
}
