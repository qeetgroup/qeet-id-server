import { CTA } from "@/components/marketing/sections/cta";
import { Features } from "@/components/marketing/sections/features";
import { Integrations } from "@/components/marketing/sections/integrations";
import type { Metadata } from "next";
import {
  BarChart3Icon,
  Building2Icon,
  CodeIcon,
  FingerprintIcon,
  KeyRoundIcon,
  LockKeyholeIcon,
  ScrollTextIcon,
  ShieldCheckIcon,
  UsersIcon,
  ZapIcon,
} from "lucide-react";

export const metadata: Metadata = {
  title: "Features",
  description:
    "SSO, MFA, passkeys, RBAC, sessions, and audit — every primitive you need to ship secure auth at scale.",
};

const deepDive = [
  {
    icon: KeyRoundIcon,
    title: "Sign-in & SSO",
    points: [
      "Email + password with strong defaults (Argon2id, breach checks)",
      "Social: Google, Microsoft, Apple, GitHub, GitLab, Facebook, Twitter",
      "Enterprise: SAML 2.0, OIDC, Azure AD, Okta, generic IdPs",
      "Magic link and email-code passwordless flows",
    ],
  },
  {
    icon: FingerprintIcon,
    title: "Passkeys & MFA",
    points: [
      "WebAuthn passkeys with platform & cross-device support",
      "TOTP authenticator apps with recovery codes",
      "SMS and email OTP with rate limits and abuse detection",
      "Step-up auth on sensitive actions",
    ],
  },
  {
    icon: UsersIcon,
    title: "RBAC & ABAC",
    points: [
      "Hierarchical roles with permission inheritance",
      "Attribute policies evaluated in under 30ms p99",
      "Group assignments with time-bounded grants",
      "Per-tenant role catalogs",
    ],
  },
  {
    icon: ShieldCheckIcon,
    title: "Sessions",
    points: [
      "Stateful sessions with cluster-wide revocation",
      "Per-device session inventory for end users",
      "Concurrent session limits and idle timeouts",
      "JWT bridge for stateless edge use cases",
    ],
  },
  {
    icon: Building2Icon,
    title: "Multi-tenancy",
    points: [
      "Hard isolation per organization at the data layer",
      "Per-tenant branding, domains, and email templates",
      "Configurable data residency (US, EU, APAC)",
      "Tenant-scoped API keys and webhooks",
    ],
  },
  {
    icon: LockKeyholeIcon,
    title: "Threat protection",
    points: [
      "Adaptive rate limiting and bot detection",
      "Credential stuffing and breach password checks",
      "Suspicious IP geolocation and impossible-travel alerts",
      "Account lockout and recovery workflows",
    ],
  },
  {
    icon: ScrollTextIcon,
    title: "Audit & observability",
    points: [
      "Immutable audit log with tamper-evident hashes",
      "Streaming export to Splunk, Datadog, S3, Kafka",
      "OpenTelemetry traces and metrics out of the box",
      "Per-request structured logs with PII redaction",
    ],
  },
  {
    icon: CodeIcon,
    title: "Developer experience",
    points: [
      "TypeScript, Go, Python, Rust SDKs — all first-class",
      "React, Next.js, Remix, and React Native components",
      "Local dev mode with a single-binary emulator",
      "Codegen for OpenAPI clients and Terraform",
    ],
  },
  {
    icon: BarChart3Icon,
    title: "Insights",
    points: [
      "Login funnels and MFA adoption analytics",
      "Conversion attribution per provider",
      "Anomaly dashboards for security teams",
      "Cohort-level retention by sign-in method",
    ],
  },
  {
    icon: ZapIcon,
    title: "Performance",
    points: [
      "Sub-50ms p99 sign-in across 30+ edge regions",
      "Permission cache with 30s TTL and proactive invalidation",
      "Async fan-out via Kafka for downstream systems",
      "Postgres-backed durability with Redis hot path",
    ],
  },
];

export default function FeaturesPage() {
  return (
    <>
      <section className="border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <div className="mx-auto max-w-3xl text-center">
            <p className="text-sm font-medium uppercase tracking-widest text-primary">Features</p>
            <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
              Every primitive you need.
              <br />
              <span className="text-primary">None you don&apos;t.</span>
            </h1>
            <p className="mt-5 text-muted-foreground text-balance sm:text-lg">
              Qeet ID is built around a small set of opinionated primitives: identity, sign-in,
              permissions, sessions, and audit. Compose them however your product needs.
            </p>
          </div>
        </div>
      </section>

      <Features />

      <section className="border-b border-border/60 bg-muted/30">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <div className="mx-auto max-w-2xl text-center">
            <p className="text-sm font-medium uppercase tracking-widest text-primary">Deep dive</p>
            <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
              The whole platform, in detail
            </h2>
          </div>
          <div className="mt-14 grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {deepDive.map(({ icon: Icon, title, points }) => (
              <div
                key={title}
                className="flex flex-col gap-4 rounded-2xl border border-border/60 bg-background p-6"
              >
                <span className="grid size-10 place-items-center rounded-lg bg-primary/10 text-primary">
                  <Icon className="size-5" />
                </span>
                <h3 className="font-display text-lg font-semibold tracking-tight">{title}</h3>
                <ul className="flex flex-col gap-2 text-sm text-muted-foreground">
                  {points.map((p) => (
                    <li key={p} className="flex gap-2">
                      <span
                        aria-hidden
                        className="mt-1.5 size-1 shrink-0 rounded-full bg-primary"
                      />
                      {p}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </section>

      <Integrations />
      <CTA />
    </>
  );
}
