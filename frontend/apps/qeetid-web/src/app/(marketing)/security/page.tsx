import { CTA } from "@/components/marketing/sections/cta";
import type { Metadata } from "next";
import {
  CheckCircle2Icon,
  DatabaseIcon,
  EyeIcon,
  GlobeIcon,
  KeyRoundIcon,
  LockKeyholeIcon,
  ScrollTextIcon,
  ServerIcon,
  ShieldCheckIcon,
} from "lucide-react";

export const metadata: Metadata = {
  title: "Security & compliance",
  description:
    "SOC 2 Type II, ISO 27001, GDPR, HIPAA. Encryption at rest and in transit, zero-trust architecture, immutable audit logs.",
};

const certs = [
  {
    name: "SOC 2 Type II",
    body: "Annual independent audit covering security, availability, confidentiality.",
  },
  {
    name: "ISO 27001",
    body: "Information security management system certified by an accredited body.",
  },
  { name: "GDPR", body: "EU data residency, DPA on every contract, DPO contact published." },
  {
    name: "HIPAA",
    body: "BAA available on Enterprise plans for covered entities and business associates.",
  },
  { name: "CCPA", body: "California privacy compliance with full subject rights workflow." },
  {
    name: "PCI DSS SAQ-A",
    body: "We do not store cardholder data; payments routed through PCI-Level-1 partners.",
  },
];

const practices = [
  {
    icon: LockKeyholeIcon,
    title: "Encryption everywhere",
    body: "TLS 1.3 in transit. AES-256 at rest. Customer-managed keys (CMK) available on Enterprise.",
  },
  {
    icon: KeyRoundIcon,
    title: "Secrets management",
    body: "All secrets stored in HSM-backed vaults. Per-tenant key isolation. Quarterly rotation.",
  },
  {
    icon: EyeIcon,
    title: "Zero-trust internal",
    body: "mTLS between services. SSO + hardware-key MFA for all employees. No standing production access.",
  },
  {
    icon: DatabaseIcon,
    title: "Tenant isolation",
    body: "Postgres row-level security and schema isolation. Per-tenant encryption keys at the data layer.",
  },
  {
    icon: ScrollTextIcon,
    title: "Immutable audit logs",
    body: "Append-only, tamper-evident hashing. Exportable to S3, Splunk, Datadog, Kafka.",
  },
  {
    icon: ServerIcon,
    title: "Infrastructure",
    body: "Multi-region active-active. Automatic failover with 99.99% uptime on Enterprise plans.",
  },
  {
    icon: GlobeIcon,
    title: "Data residency",
    body: "Choose US, EU, or APAC. Data never leaves the region you select.",
  },
  {
    icon: ShieldCheckIcon,
    title: "Threat protection",
    body: "Rate limiting, bot detection, breach-password checks, anomaly alerts.",
  },
];

const program = [
  "Continuous third-party penetration testing",
  "Public security disclosure program with bounty payouts",
  "All commits gated by signed-commit verification",
  "Production deploys require two-person approval",
  "Dependency vulnerability scanning on every PR",
  "Disaster recovery drills run quarterly",
  "Encryption keys rotated on a 90-day schedule",
  "Employee security training mandatory every 6 months",
];

export default function SecurityPage() {
  return (
    <>
      <section className="border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <div className="mx-auto max-w-3xl text-center">
            <p className="text-sm font-medium uppercase tracking-widest text-primary">
              Security & compliance
            </p>
            <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
              Built for the most regulated industries
            </h1>
            <p className="mt-5 text-muted-foreground text-balance sm:text-lg">
              Banks, hospitals, and Fortune 100 platforms run on Qeet ID. Audit-ready by default.
              The whole company is accountable for keeping it that way.
            </p>
          </div>
        </div>
      </section>

      <section className="border-b border-border/60 bg-muted/30">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            Certifications & frameworks
          </h2>
          <p className="mt-4 max-w-2xl text-muted-foreground">
            Independent audits cover every piece of customer data. Report copies available under NDA
            from your account team.
          </p>
          <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {certs.map((c) => (
              <div
                key={c.name}
                className="flex flex-col gap-3 rounded-2xl border border-border/60 bg-background p-6"
              >
                <div className="flex items-center gap-2">
                  <CheckCircle2Icon className="size-5 text-primary" />
                  <h3 className="font-medium">{c.name}</h3>
                </div>
                <p className="text-sm text-muted-foreground">{c.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            How we protect your data
          </h2>
          <div className="mt-12 grid gap-px overflow-hidden rounded-2xl bg-border/60 sm:grid-cols-2 lg:grid-cols-4">
            {practices.map(({ icon: Icon, title, body }) => (
              <div key={title} className="flex flex-col gap-3 bg-background p-6">
                <span className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary">
                  <Icon className="size-5" />
                </span>
                <h3 className="font-medium">{title}</h3>
                <p className="text-sm text-muted-foreground">{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="border-b border-border/60 bg-muted/30">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <div className="grid gap-12 lg:grid-cols-[1fr_1.4fr]">
            <div className="flex flex-col gap-4">
              <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
                Our security program
              </h2>
              <p className="text-muted-foreground">
                Security isn&apos;t a team. It&apos;s how we ship.
              </p>
            </div>
            <ul className="grid gap-3 sm:grid-cols-2">
              {program.map((p) => (
                <li
                  key={p}
                  className="flex items-start gap-3 rounded-xl border border-border/60 bg-background p-4 text-sm"
                >
                  <CheckCircle2Icon className="mt-0.5 size-4 shrink-0 text-primary" />
                  <span>{p}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      <CTA />
    </>
  );
}
