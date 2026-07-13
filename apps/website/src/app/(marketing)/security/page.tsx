import { Badge } from "@qeetrix/ui";
import {
  IconApiKey,
  IconAuditLog,
  IconMfaShield,
  IconPasskey,
  IconScimSync,
  IconTenant,
  IconWebhook,
} from "@qeetrix/ui/brand";
import {
  CheckCircle2Icon,
  FingerprintIcon,
  GlobeIcon,
  KeyRoundIcon,
  LockKeyholeIcon,
  ShieldAlertIcon,
} from "lucide-react";
import type { Metadata } from "next";
import { Reveal, Stagger, StaggerItem } from "@/components/marketing/motion";
import { PageHero } from "@/components/marketing/page-hero";
import { Section, SectionHeader } from "@/components/marketing/section";
import { CTA } from "@/components/marketing/sections/cta";

export const metadata: Metadata = {
  title: "Security & compliance",
  description:
    "Qeet ID's security posture: a hash-chained tamper-evident audit log, ES256 / JWKS token signing, passkeys / WebAuthn, Argon2id hashing, an encrypted secrets vault, RBAC + ABAC, and a compliance roadmap to SOC 2, ISO 27001, and GDPR.",
};

/** The architectural pillars — every one is implemented and verified in source. */
const pillars = [
  {
    icon: IconAuditLog,
    title: "Tamper-evident audit log",
    body: "Every audit event is append-only and SHA-256 hash-chained to the one before it. A /verify endpoint recomputes the chain, so any altered or deleted row is provably detectable — a genuine differentiator over mainstream CIAM.",
    badge: "Hash-chained",
  },
  {
    icon: KeyRoundIcon,
    title: "Asymmetric token signing",
    body: "ID tokens are signed with ES256 (ECDSA P-256), published at a standard JWKS endpoint with RFC 7638 key IDs. A retired-key grace window and an algorithm-confusion guard keep verification safe through rotation.",
    badge: "ES256 · JWKS",
  },
  {
    icon: IconPasskey,
    title: "Passkeys / WebAuthn",
    body: "Phishing-resistant FIDO2 passwordless login and registration, plus WebAuthn as a second factor and step-up verification gating sensitive actions. Built on go-webauthn with full credential management.",
    badge: "FIDO2",
  },
  {
    icon: LockKeyholeIcon,
    title: "Argon2id password hashing",
    body: "Passwords are hashed with Argon2id at OWASP parameters, with format-detecting verification, rehash-on-login (bcrypt migration path), and timing-safe comparison. Breached passwords are rejected via HIBP k-anonymity.",
    badge: "OWASP params",
  },
  {
    icon: KeyRoundIcon,
    title: "Encrypted secrets vault",
    body: "Per-tenant secrets are sealed with AES-256-GCM. Keys are sourced through a KeyProvider abstraction decoupled from the JWT secret, so AWS KMS (BYOK / envelope encryption) drops in without code changes.",
    badge: "AES-256-GCM",
  },
  {
    icon: IconTenant,
    title: "RBAC + ABAC authorization",
    body: "Per-tenant roles and groups with a single-call /check API, effective-permissions queries, and an ABAC policy engine. Explainable authorization returns the exact grant-path trace — which role or group allowed it, or why it was denied.",
    badge: "Explainable",
  },
  {
    icon: IconScimSync,
    title: "Enterprise federation",
    body: "Be a SAML IdP and SP, an OIDC provider, and a SCIM 2.0 Users + Groups endpoint — RSA-SHA256-signed assertions, JIT provisioning, and PatchOp membership sync, none of it paywalled behind an enterprise tier.",
    badge: "SAML · OIDC · SCIM",
  },
  {
    icon: IconMfaShield,
    title: "Hardened by default",
    body: "Refresh-token rotation with theft detection, per-account lockout, distributed Redis rate limiting, CSRF + security headers, and a production boot-gate that refuses to start with insecure defaults.",
    badge: "Secure defaults",
  },
];

/** Compliance frameworks — honest about achieved vs. in-progress. */
const compliance = [
  {
    name: "GDPR",
    status: "Supported" as const,
    body: "Right-to-erasure (async PII purge with the audit trail preserved), data export, and retention auto-purge are implemented today.",
  },
  {
    name: "SOC 2 Type II",
    status: "In progress" as const,
    body: "Controls are in place; an independent Type II audit is scheduled ahead of GA.",
  },
  {
    name: "ISO 27001",
    status: "In progress" as const,
    body: "An ISMS is being formalised toward certification by an accredited body.",
  },
  {
    name: "Data residency",
    status: "Supported" as const,
    body: "Hosted EU / US regions, or self-host anywhere — including a customer VPC or air-gapped network.",
  },
  {
    name: "HIPAA BAA",
    status: "Roadmap" as const,
    body: "Self-hosting already lets covered entities keep PHI inside their own boundary; a managed BAA is planned.",
  },
  {
    name: "Pen test",
    status: "Roadmap" as const,
    body: "An external penetration test is scheduled before GA; findings will be remediated and summarised for customers.",
  },
];

/** Data-handling principles. */
const dataHandling = [
  {
    icon: GlobeIcon,
    title: "Data residency & self-hosting",
    body: "Choose a hosted EU or US region, or run the single Go binary on your own infrastructure. When you self-host, customer data never leaves your boundary — the strongest residency guarantee there is.",
  },
  {
    icon: IconTenant,
    title: "Tenant isolation",
    body: "Everything is partitioned by tenant_id across the user, auth, RBAC, audit, and platform schemas. Switching tenants re-mints a freshly scoped token.",
  },
  {
    icon: IconWebhook,
    title: "Signed event delivery",
    body: "Webhooks are HMAC-SHA256 signed and delivered through a transactional outbox with exponential-backoff retries and a dead-letter queue, so downstream systems get a verifiable, durable event stream.",
  },
  {
    icon: IconApiKey,
    title: "Machine identities",
    body: "Scoped, expirable, hashed API keys plus OAuth client_credentials for service-to-service auth — every machine principal is auditable and revocable.",
  },
];

const disclosure = [
  "Report suspected vulnerabilities to security@qeet.in — we acknowledge within one business day.",
  "We operate a coordinated disclosure policy with a safe-harbour for good-faith research.",
  "Critical fixes are prioritised; we'll keep you updated through remediation and credit you (if you wish) on resolution.",
  "Please don't access or modify other users' data, degrade the service, or run automated scans against shared infrastructure.",
];

export default function SecurityPage() {
  return (
    <>
      <PageHero
        eyebrow="Security & compliance"
        title="Security isn't a feature."
        titleAccent="It's the architecture."
        subtitle="Qeet ID is built for teams that have to prove their controls. Tamper-evident audit, asymmetric token signing, passkeys, and an encrypted vault — secure by default, and open enough to verify yourself."
      />

      {/* Architectural pillars */}
      <Section innerClassName="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-24">
        <SectionHeader
          eyebrow="Posture"
          title="How Qeet ID protects"
          titleAccent="identity"
          subtitle="Each pillar below is implemented and tested in the platform today — not a brochure promise."
        />
        <Stagger staggerDelay={0.06} className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {pillars.map(({ icon: Icon, title, body, badge }) => (
            <StaggerItem key={title} className="h-full">
              <article className="flex h-full flex-col gap-3 rounded-2xl border border-border/60 bg-card p-6">
                <div className="flex items-center justify-between gap-3">
                  <span className="grid size-10 place-items-center rounded-lg bg-brand/10 text-brand">
                    <Icon className="size-5" aria-hidden />
                  </span>
                  <span className="rounded-full border border-border/60 px-2 py-0.5 text-[11px] font-medium text-muted-foreground">
                    {badge}
                  </span>
                </div>
                <h3 className="font-display text-lg font-semibold tracking-tight">{title}</h3>
                <p className="text-sm text-muted-foreground">{body}</p>
              </article>
            </StaggerItem>
          ))}
        </Stagger>
      </Section>

      {/* Compliance */}
      <Section muted innerClassName="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-24">
        <SectionHeader
          eyebrow="Compliance"
          title="Frameworks &"
          titleAccent="certifications"
          subtitle="We're candid about what's achieved versus in progress. Self-hosting also lets you inherit Qeet ID into your own compliance boundary."
        />
        <Stagger staggerDelay={0.06} className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {compliance.map((c) => (
            <StaggerItem key={c.name} className="h-full">
              <div className="flex h-full flex-col gap-3 rounded-2xl border border-border/60 bg-background p-6">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="font-medium">{c.name}</h3>
                  <Badge
                    variant={
                      c.status === "Supported"
                        ? "success"
                        : c.status === "In progress"
                          ? "warning"
                          : "muted"
                    }
                  >
                    {c.status}
                  </Badge>
                </div>
                <p className="text-sm text-muted-foreground">{c.body}</p>
              </div>
            </StaggerItem>
          ))}
        </Stagger>
      </Section>

      {/* Data handling */}
      <Section innerClassName="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-24">
        <SectionHeader
          align="left"
          eyebrow="Data handling"
          title="Your data, your"
          titleAccent="boundary"
        />
        <Stagger
          staggerDelay={0.06}
          className="mt-12 grid gap-px overflow-hidden rounded-2xl bg-border/60 sm:grid-cols-2"
        >
          {dataHandling.map(({ icon: Icon, title, body }) => (
            <StaggerItem key={title} className="h-full">
              <div className="flex h-full flex-col gap-3 bg-background p-6 sm:p-8">
                <span className="grid size-10 place-items-center rounded-lg bg-brand/10 text-brand">
                  <Icon className="size-5" aria-hidden />
                </span>
                <h3 className="font-display text-lg font-semibold tracking-tight">{title}</h3>
                <p className="text-sm text-muted-foreground">{body}</p>
              </div>
            </StaggerItem>
          ))}
        </Stagger>
      </Section>

      {/* Responsible disclosure */}
      <Section muted innerClassName="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-24">
        <div className="grid gap-12 lg:grid-cols-[1fr_1.4fr] lg:items-start">
          <Reveal className="flex flex-col gap-4">
            <span className="grid size-11 place-items-center rounded-xl bg-brand/10 text-brand">
              <ShieldAlertIcon className="size-6" aria-hidden />
            </span>
            <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
              Responsible disclosure
            </h2>
            <p className="text-muted-foreground">
              Found something? We want to hear about it. Good-faith research keeps everyone safer,
              and we&apos;ll work the issue with you.
            </p>
            <a
              href="mailto:security@qeet.in"
              className="inline-flex w-fit items-center gap-2 text-sm font-medium text-brand-text underline focus-ring-brand"
            >
              <FingerprintIcon className="size-4" aria-hidden />
              security@qeet.in
            </a>
          </Reveal>
          <Stagger staggerDelay={0.07} className="grid gap-3">
            {disclosure.map((d) => (
              <StaggerItem key={d}>
                <div className="flex items-start gap-3 rounded-xl border border-border/60 bg-background p-4 text-sm">
                  <CheckCircle2Icon className="mt-0.5 size-4 shrink-0 text-brand" aria-hidden />
                  <span>{d}</span>
                </div>
              </StaggerItem>
            ))}
          </Stagger>
        </div>
      </Section>

      <CTA />
    </>
  );
}
