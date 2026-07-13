import { createFileRoute } from "@tanstack/react-router";

import { ComplianceEvidencePage } from "@/features/compliance/evidence-page";

export const Route = createFileRoute("/_app/security/compliance/iso27001")({
  component: Iso27001Page,
});

function Iso27001Page() {
  return <ComplianceEvidencePage framework="iso27001" />;
}
