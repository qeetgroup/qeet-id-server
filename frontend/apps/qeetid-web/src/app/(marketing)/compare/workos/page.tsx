import type { Metadata } from "next";

import { ComparisonPage, type ComparisonData } from "@/components/marketing/comparison-page";

export const metadata: Metadata = {
  title: "Qeet ID vs. WorkOS",
  description:
    "Qeet ID vs. WorkOS: complete identity for B2B SaaS — user store, SSO, SCIM, audit, and a brandable admin, in one open-source binary.",
};

const data: ComparisonData = {
  competitor: "WorkOS",
  competitorBlurb:
    "WorkOS sells enterprise-readiness APIs — SSO, SCIM, Audit Logs, Directory Sync — that you bolt onto your own user store. Qeet ID is the user store too: identity, RBAC, MFA, sessions, admin UI, plus the same enterprise APIs in one binary.",
  pitch: {
    headline: "WorkOS is half the system. Qeet ID is the whole one.",
    subhead:
      "If you already have a user database and just need SSO + SCIM, WorkOS is great. If you're building from scratch — or want to consolidate — Qeet ID gives you the user store, MFA, sessions, admin UI, and the enterprise APIs in a single Postgres-backed service.",
    bullets: [
      "Built-in user store with sessions, MFA, social, and passkeys.",
      "Multi-tenant by default — organisations are first-class.",
      "Open source and self-hostable, including air-gapped deployments.",
    ],
  },
  factsQeetid: [
    { label: "License", value: "MIT (open source)" },
    { label: "What it ships", value: "Full IdP + admin" },
    { label: "User store", value: "Yes (Postgres)" },
    { label: "Self-host", value: "First-class" },
    { label: "Pricing", value: "Linear per-MAU" },
  ],
  factsCompetitor: [
    { label: "License", value: "Proprietary SaaS" },
    { label: "What it ships", value: "Enterprise APIs only" },
    { label: "User store", value: "Bring your own" },
    { label: "Self-host", value: "Not available" },
    { label: "Pricing", value: "Per-connection + per-event" },
  ],
  rows: [
    // ---- Scope ----
    { section: "What you get", feature: "User store (users, sessions, passwords)", qeetid: true, competitor: false, note: "WorkOS doesn't store users — you bring your own DB." },
    { section: "What you get", feature: "Built-in MFA (TOTP, SMS, email, recovery)", qeetid: true, competitor: false },
    { section: "What you get", feature: "Hosted admin dashboard", qeetid: true, competitor: "AdminPortal (per-customer)" },
    { section: "What you get", feature: "RBAC permissions engine", qeetid: true, competitor: false },

    // ---- Federation ----
    { section: "Federation", feature: "SAML 2.0 SSO", qeetid: true, competitor: true },
    { section: "Federation", feature: "OIDC SSO", qeetid: true, competitor: true },
    { section: "Federation", feature: "SCIM 2.0", qeetid: true, competitor: true },
    { section: "Federation", feature: "Directory Sync (Google, Okta, Entra)", qeetid: "Roadmap v1.5", competitor: true },
    { section: "Federation", feature: "Magic links", qeetid: true, competitor: true },

    // ---- Auth methods ----
    { section: "Auth methods", feature: "Email + password", qeetid: true, competitor: "via AuthKit" },
    { section: "Auth methods", feature: "Passkeys / WebAuthn", qeetid: true, competitor: "via AuthKit" },
    { section: "Auth methods", feature: "Social login", qeetid: true, competitor: "via AuthKit" },

    // ---- Compliance ----
    { section: "Compliance", feature: "Audit logs (search, export)", qeetid: true, competitor: true },
    { section: "Compliance", feature: "Tamper-evident audit chain (SHA-256)", qeetid: true, competitor: false, note: "Qeet ID chains every audit row by hash; tampering breaks the chain." },
    { section: "Compliance", feature: "SOC 2 Type II", qeetid: "Roadmap v1.0", competitor: true },
    { section: "Compliance", feature: "Self-hosted = your compliance boundary", qeetid: true, competitor: false },

    // ---- Deployment ----
    { section: "Deployment", feature: "Self-host (single binary + Postgres)", qeetid: true, competitor: false },
    { section: "Deployment", feature: "Bring-your-own database", qeetid: true, competitor: false },
    { section: "Deployment", feature: "Air-gapped / on-prem", qeetid: true, competitor: false },

    // ---- Pricing ----
    { section: "Pricing", feature: "Free tier", qeetid: "5,000 MAU", competitor: "1 million events / month" },
    { section: "Pricing", feature: "B2B SSO included", qeetid: true, competitor: "Per-connection pricing" },
    { section: "Pricing", feature: "SCIM included", qeetid: true, competitor: "Per-connection pricing" },
    { section: "Pricing", feature: "Audit-log export", qeetid: true, competitor: "Paid tier" },
  ],
  cta: {
    headline: "One binary, one bill, one identity stack",
    subhead:
      "Replace your user store, MFA library, session manager, and enterprise-SSO bolt-on with Qeet ID. Or keep what you have and migrate gradually.",
  },
};

export default function Page() {
  return <ComparisonPage data={data} />;
}
