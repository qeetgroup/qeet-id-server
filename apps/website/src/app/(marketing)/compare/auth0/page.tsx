import type { Metadata } from "next";

import { type ComparisonData, ComparisonPage } from "@/components/marketing/comparison-page";

export const metadata: Metadata = {
  title: "Qeet ID vs. Auth0",
  description:
    "How Qeet ID compares to Auth0 (Okta): open-source / self-hostable, transparent per-MAU pricing, and a modern passkeys-first stack.",
};

const data: ComparisonData = {
  competitor: "Auth0",
  competitorBlurb:
    "Auth0 is the enterprise CIAM market leader, acquired by Okta in 2021. It excels at federation and is widely adopted; choose Qeet ID when you want open-source code, single-tenant deployment, and pricing that scales linearly with users.",
  pitch: {
    headline: "Same protocols. Fewer surprises on the bill.",
    subhead:
      "Qeet ID speaks every OAuth / OIDC / SAML / SCIM dialect Auth0 does. The difference is transparency — the code, the pricing, and where your data lives.",
    bullets: [
      "MIT-licensed core you can self-host on your own infrastructure.",
      "Linear per-MAU pricing without sudden tier breakpoints.",
      "Single-tenant deploy option for healthcare, public sector, and on-prem teams.",
    ],
  },
  factsQeetid: [
    { label: "License", value: "MIT (open source)" },
    { label: "Self-host", value: "First-class" },
    { label: "Pricing", value: "Linear per-MAU" },
    { label: "Stack", value: "Go + Postgres" },
    { label: "Data residency", value: "EU / US / self" },
  ],
  factsCompetitor: [
    { label: "License", value: "Proprietary SaaS" },
    { label: "Self-host", value: "Private Cloud (enterprise)" },
    { label: "Pricing", value: "Tier-stepped" },
    { label: "Stack", value: "Closed (managed)" },
    { label: "Data residency", value: "Region picker" },
  ],
  rows: [
    // ---- Authentication ----
    {
      section: "Authentication",
      feature: "Email + password",
      qeetid: true,
      competitor: true,
    },
    {
      section: "Authentication",
      feature: "Passkeys / WebAuthn",
      qeetid: true,
      competitor: true,
    },
    {
      section: "Authentication",
      feature: "Magic links",
      qeetid: true,
      competitor: true,
    },
    {
      section: "Authentication",
      feature: "Social login (Google, Apple, GitHub, Microsoft, …)",
      qeetid: true,
      competitor: true,
    },
    {
      section: "Authentication",
      feature: "MFA (TOTP, SMS, email, recovery codes)",
      qeetid: true,
      competitor: true,
    },

    // ---- Federation ----
    {
      section: "Federation",
      feature: "OAuth 2.0 / OIDC (you are the IdP)",
      qeetid: true,
      competitor: true,
    },
    {
      section: "Federation",
      feature: "SAML 2.0 SP + IdP",
      qeetid: true,
      competitor: true,
    },
    {
      section: "Federation",
      feature: "SCIM 2.0 provisioning",
      qeetid: true,
      competitor: true,
    },
    {
      section: "Federation",
      feature: "Bring-your-own social provider",
      qeetid: true,
      competitor: true,
    },

    // ---- Authorization ----
    {
      section: "Authorization",
      feature: "RBAC + single-call /check API",
      qeetid: true,
      competitor: true,
    },
    {
      section: "Authorization",
      feature: "ABAC policy engine",
      qeetid: true,
      competitor: "partial",
      note: "Qeet ID ships a per-tenant ABAC policy engine; Auth0 leans on Rules/Actions for attribute logic.",
    },
    {
      section: "Authorization",
      feature: "Explainable authz (grant-path “why?” trace)",
      qeetid: true,
      competitor: false,
      note: "Qeet ID returns the role/group grant path (or denial reason) on every check.",
    },
    {
      section: "Authorization",
      feature: "Fine-grained / ReBAC",
      qeetid: "Roadmap",
      competitor: true,
      note: "Auth0 ships FGA; Qeet ID's ReBAC is planned.",
    },
    {
      section: "Authorization",
      feature: "Multi-tenant isolation by default",
      qeetid: true,
      competitor: "Organizations add-on",
    },

    // ---- Deployment ----
    {
      section: "Deployment",
      feature: "Open-source code (MIT)",
      qeetid: true,
      competitor: false,
      note: "Auth0 is closed source. SDKs are open; the core is not.",
    },
    {
      section: "Deployment",
      feature: "Self-host (single binary + Postgres)",
      qeetid: true,
      competitor: "Private Cloud, enterprise only",
    },
    {
      section: "Deployment",
      feature: "Bring-your-own Postgres",
      qeetid: true,
      competitor: false,
    },
    {
      section: "Deployment",
      feature: "Air-gapped / fully offline",
      qeetid: true,
      competitor: false,
    },

    // ---- Pricing ----
    {
      section: "Pricing",
      feature: "Free tier MAU cap",
      qeetid: "5,000",
      competitor: "25,000 (B2C) / 100 (B2B)",
    },
    {
      section: "Pricing",
      feature: "Per-MAU pricing",
      qeetid: "$0.02 / MAU (Pro)",
      competitor: "Tier-stepped, calls for quote at scale",
    },
    {
      section: "Pricing",
      feature: "SSO included on entry plan",
      qeetid: true,
      competitor: false,
      note: "Auth0 reserves SAML/OIDC SSO for paid B2B tiers.",
    },
    {
      section: "Pricing",
      feature: "MAU overage billing",
      qeetid: "Linear",
      competitor: "Tier jump",
    },

    // ---- Security & audit ----
    {
      section: "Security & audit",
      feature: "Tamper-evident hash-chained audit log + /verify",
      qeetid: true,
      competitor: "partial",
      note: "Qeet ID SHA-256 chains every audit row; an integrity endpoint proves no row was altered.",
    },
    {
      section: "Security & audit",
      feature: "Refresh-token theft detection",
      qeetid: true,
      competitor: true,
    },
    {
      section: "Security & audit",
      feature: "Breached-password rejection (HIBP)",
      qeetid: true,
      competitor: true,
    },
    {
      section: "Security & audit",
      feature: "Adaptive / risk-based MFA + bot detection",
      qeetid: "Roadmap",
      competitor: true,
      note: "Auth0 ships attack protection; Qeet ID's adaptive MFA / bot detection are planned.",
    },

    // ---- Compliance ----
    {
      section: "Compliance",
      feature: "SOC 2 Type II",
      qeetid: "Roadmap (pre-GA)",
      competitor: true,
      note: "Independent audit + external pen-test are scheduled before GA.",
    },
    {
      section: "Compliance",
      feature: "GDPR erasure / data export",
      qeetid: true,
      competitor: true,
    },
    {
      section: "Compliance",
      feature: "Self-hosted = your compliance boundary",
      qeetid: true,
      competitor: false,
    },

    // ---- Developer experience ----
    {
      section: "Developer experience",
      feature: "OpenAPI + Postman",
      qeetid: true,
      competitor: true,
    },
    {
      section: "Developer experience",
      feature: "Webhook events with HMAC + retries",
      qeetid: true,
      competitor: true,
    },
    {
      section: "Developer experience",
      feature: "Audit log API + CSV/JSON export",
      qeetid: true,
      competitor: "Paid tiers",
    },
    {
      section: "Developer experience",
      feature: "First-party SDKs",
      qeetid: "TS · Next · React · Go · Python",
      competitor: "20+ languages",
    },
    {
      section: "Developer experience",
      feature: "OpenAPI spec (100% route coverage, CI-guarded)",
      qeetid: true,
      competitor: true,
    },
    {
      section: "Developer experience",
      feature: "Prebuilt React components",
      qeetid: "partial",
      competitor: true,
      note: "Auth0 ships polished hosted UI + Lock; Qeet ID's React component kit is in progress.",
    },
  ],
  cta: {
    headline: "Try Qeet ID in 60 seconds",
    subhead:
      "Spin up a workspace with your email — no credit card. Or run the Docker image on your own laptop right now.",
  },
};

export default function Page() {
  return <ComparisonPage data={data} />;
}
