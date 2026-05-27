import type { Metadata } from "next";

import { ComparisonPage, type ComparisonData } from "@/components/marketing/comparison-page";

export const metadata: Metadata = {
  title: "Qeetid vs. Stytch",
  description:
    "Qeetid vs. Stytch: open-source identity with the same passwordless-first methods, plus a built-in admin and self-hosting.",
};

const data: ComparisonData = {
  competitor: "Stytch",
  competitorBlurb:
    "Stytch is a passwordless-first auth API with strong fraud / device-fingerprinting capabilities. Qeetid covers the same passwordless methods (passkeys, magic links, OTP) and adds a complete admin UI, multi-tenant B2B, and self-hosting on Postgres.",
  pitch: {
    headline: "Passwordless. Plus everything around it.",
    subhead:
      "Get the same modern auth methods Stytch ships — and an admin dashboard, RBAC, audit logs, and a self-hosted deployment, in one open-source binary.",
    bullets: [
      "Passkeys, magic links, and OTP as first-class methods.",
      "Admin UI ships with the product — no need to build your own.",
      "Self-host on Postgres. Your customers' data stays on your infrastructure.",
    ],
  },
  factsQeetid: [
    { label: "License", value: "MIT (open source)" },
    { label: "Self-host", value: "First-class" },
    { label: "Admin UI", value: "Included" },
    { label: "Stack", value: "Go + Postgres" },
    { label: "B2B multi-tenant", value: "Built-in" },
  ],
  factsCompetitor: [
    { label: "License", value: "Proprietary SaaS" },
    { label: "Self-host", value: "Not available" },
    { label: "Admin UI", value: "Build your own" },
    { label: "Stack", value: "Closed (managed)" },
    { label: "B2B multi-tenant", value: "Stytch B2B product" },
  ],
  rows: [
    // ---- Authentication ----
    { section: "Authentication", feature: "Passkeys / WebAuthn", qeetid: true, competitor: true },
    { section: "Authentication", feature: "Magic links", qeetid: true, competitor: true },
    { section: "Authentication", feature: "Email / SMS OTP", qeetid: true, competitor: true },
    { section: "Authentication", feature: "Password (optional)", qeetid: true, competitor: true },
    { section: "Authentication", feature: "Social login", qeetid: true, competitor: true },
    { section: "Authentication", feature: "MFA (TOTP, SMS, email)", qeetid: true, competitor: true },

    // ---- Federation ----
    { section: "Federation", feature: "OAuth 2.0 / OIDC", qeetid: true, competitor: true },
    { section: "Federation", feature: "SAML 2.0", qeetid: true, competitor: "B2B product" },
    { section: "Federation", feature: "SCIM 2.0", qeetid: true, competitor: "B2B product" },
    { section: "Federation", feature: "JIT provisioning", qeetid: true, competitor: true },

    // ---- B2B ----
    { section: "B2B", feature: "Multi-tenant by default", qeetid: true, competitor: "B2B product (separate SKU)" },
    { section: "B2B", feature: "Invitations + role assignment", qeetid: true, competitor: true },
    { section: "B2B", feature: "RBAC engine", qeetid: true, competitor: "Limited" },

    // ---- Operator UX ----
    { section: "Operator UX", feature: "Admin dashboard", qeetid: true, competitor: false, note: "Stytch is API-first; you build the admin." },
    { section: "Operator UX", feature: "Audit log viewer + export", qeetid: true, competitor: "Logs API" },
    { section: "Operator UX", feature: "Webhook events", qeetid: true, competitor: true },
    { section: "Operator UX", feature: "Branding customisation (logo, colours)", qeetid: true, competitor: "Hosted email templates" },

    // ---- Security ----
    { section: "Security", feature: "Tamper-evident audit log (SHA-256 chain)", qeetid: true, competitor: false },
    { section: "Security", feature: "Device fingerprinting", qeetid: "Roadmap v1.5", competitor: true },
    { section: "Security", feature: "Impossible-travel risk signals", qeetid: "Roadmap v1.5", competitor: true },

    // ---- Deployment ----
    { section: "Deployment", feature: "Self-host (single binary + Postgres)", qeetid: true, competitor: false },
    { section: "Deployment", feature: "Bring-your-own database", qeetid: true, competitor: false },
    { section: "Deployment", feature: "Air-gapped / on-prem", qeetid: true, competitor: false },

    // ---- Pricing ----
    { section: "Pricing", feature: "Free tier", qeetid: "5,000 MAU", competitor: "1,000 MAU + 25 orgs (B2B)" },
    { section: "Pricing", feature: "Per-MAU pricing", qeetid: "$0.02 / MAU (Pro)", competitor: "Variable by product" },
  ],
  cta: {
    headline: "Modern auth methods you can self-host",
    subhead:
      "Start free on our hosted plan, or run Qeetid on your own infrastructure with one Docker command.",
  },
};

export default function Page() {
  return <ComparisonPage data={data} />;
}
