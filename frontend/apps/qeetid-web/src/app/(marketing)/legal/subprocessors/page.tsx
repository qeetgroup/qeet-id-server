import { LegalPage } from "@/components/marketing/legal-page";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@qeetrix/ui";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Subprocessors",
  description: "The third-party subprocessors Qeet ID engages to deliver its services.",
};

const subprocessors = [
  { name: "Amazon Web Services", purpose: "Cloud infrastructure & hosting", location: "US, EU, APAC" },
  { name: "Google Cloud Platform", purpose: "Compute & managed databases", location: "US, EU" },
  { name: "Cloudflare", purpose: "Edge network, DNS & DDoS protection", location: "Global" },
  { name: "Datadog", purpose: "Observability & monitoring", location: "US, EU" },
  { name: "Stripe", purpose: "Billing & payment processing", location: "US, EU" },
  { name: "Resend", purpose: "Transactional email delivery", location: "US" },
  { name: "Twilio", purpose: "SMS one-time passcodes", location: "US, EU" },
];

export default function SubprocessorsPage() {
  return (
    <LegalPage
      title="Subprocessors"
      updated="2026-05-01"
      intro="We engage the third parties below to help deliver the Services. Each is bound by data protection terms consistent with our DPA."
    >
      <div className="overflow-hidden rounded-2xl border border-border/60">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Subprocessor</TableHead>
              <TableHead>Purpose</TableHead>
              <TableHead>Region</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {subprocessors.map((s) => (
              <TableRow key={s.name}>
                <TableCell className="font-medium">{s.name}</TableCell>
                <TableCell className="text-muted-foreground">{s.purpose}</TableCell>
                <TableCell className="text-muted-foreground">{s.location}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <p className="text-sm text-muted-foreground">
        We provide advance notice of new subprocessors. To receive updates, email{" "}
        <a className="text-primary underline" href="mailto:privacy@qeetid.com">
          privacy@qeetid.com
        </a>
        .
      </p>
    </LegalPage>
  );
}
