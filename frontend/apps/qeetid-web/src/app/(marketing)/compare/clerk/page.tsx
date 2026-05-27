import type { Metadata } from "next";

import { ComparisonPage, type ComparisonData } from "@/components/marketing/comparison-page";

export const metadata: Metadata = {
  title: "Qeetid vs. Clerk",
  description:
    "Qeetid vs. Clerk: open-source identity for full-stack teams who want self-hosting, multi-tenant defaults, and the same drop-in DX.",
};

const data: ComparisonData = {
  competitor: "Clerk",
  competitorBlurb:
    "Clerk is the modern developer-friendly auth-as-a-service for React / Next.js apps. If you live in Vercel and want the polished React components, it's terrific. Qeetid is the choice when you also need self-hosting, multi-tenant SaaS shape, or to own your database.",
  pitch: {
    headline: "The DX you like from Clerk. The deployment story your platform team needs.",
    subhead:
      "Drop-in `<SignIn />` / `<SignedIn />` React primitives + hosted UI, plus a single Go binary you can ship anywhere — including a customer's VPC.",
    bullets: [
      "Multi-tenant by design — tenants, members, invitations are first-class.",
      "Self-host on Postgres. No proprietary database.",
      "Open-source. Audit our code, fork if you need.",
    ],
  },
  factsQeetid: [
    { label: "License", value: "MIT (open source)" },
    { label: "Self-host", value: "First-class" },
    { label: "Stack", value: "Go + Postgres" },
    { label: "Multi-tenant", value: "Built-in" },
    { label: "Frameworks", value: "React, Next, Node, Go" },
  ],
  factsCompetitor: [
    { label: "License", value: "Proprietary SaaS" },
    { label: "Self-host", value: "Not available" },
    { label: "Stack", value: "Closed (managed)" },
    { label: "Multi-tenant", value: "Organizations add-on" },
    { label: "Frameworks", value: "React-first" },
  ],
  rows: [
    // ---- Authentication ----
    { section: "Authentication", feature: "Email + password", qeetid: true, competitor: true },
    { section: "Authentication", feature: "Passkeys / WebAuthn", qeetid: true, competitor: true },
    { section: "Authentication", feature: "Magic links", qeetid: true, competitor: true },
    { section: "Authentication", feature: "Social login (Google, Apple, GitHub, …)", qeetid: true, competitor: true },
    { section: "Authentication", feature: "MFA (TOTP, SMS, email, recovery codes)", qeetid: true, competitor: true },

    // ---- Frontend ----
    { section: "Frontend", feature: "Drop-in React `<SignIn />` components", qeetid: "Roadmap (sdk-react)", competitor: true },
    { section: "Frontend", feature: "Hosted, brandable auth pages", qeetid: "Roadmap v1.1", competitor: true },
    { section: "Frontend", feature: "Headless primitives (useSession, useUser, …)", qeetid: "Roadmap (sdk-react)", competitor: true },
    { section: "Frontend", feature: "Native admin dashboard", qeetid: true, competitor: true },

    // ---- B2B / Tenant model ----
    { section: "B2B / Tenant model", feature: "Multi-tenant by default", qeetid: true, competitor: "Organizations add-on" },
    { section: "B2B / Tenant model", feature: "Invitations + role assignment", qeetid: true, competitor: true },
    { section: "B2B / Tenant model", feature: "SAML / OIDC federation", qeetid: true, competitor: "Paid tier" },
    { section: "B2B / Tenant model", feature: "SCIM provisioning", qeetid: true, competitor: "Paid tier" },

    // ---- Deployment ----
    { section: "Deployment", feature: "Self-host (single binary + Postgres)", qeetid: true, competitor: false },
    { section: "Deployment", feature: "Bring-your-own database", qeetid: true, competitor: false },
    { section: "Deployment", feature: "EU / US data residency", qeetid: true, competitor: true },
    { section: "Deployment", feature: "Air-gapped / on-prem", qeetid: true, competitor: false },

    // ---- Pricing ----
    { section: "Pricing", feature: "Free tier MAU cap", qeetid: "5,000", competitor: "10,000" },
    { section: "Pricing", feature: "Per-MAU pricing", qeetid: "$0.02 / MAU (Pro)", competitor: "$0.02 / MAU after free" },
    { section: "Pricing", feature: "B2B SSO included", qeetid: true, competitor: false, note: "Clerk SSO is reserved for higher tiers." },
    { section: "Pricing", feature: "Audit log retention", qeetid: "7 days / S3 export", competitor: "Paid" },

    // ---- Compliance ----
    { section: "Compliance", feature: "SOC 2 Type II", qeetid: "Roadmap v1.0", competitor: true },
    { section: "Compliance", feature: "GDPR / DPA", qeetid: true, competitor: true },
    { section: "Compliance", feature: "Self-hosted compliance boundary", qeetid: true, competitor: false },
  ],
  cta: {
    headline: "Keep the developer experience. Own the infrastructure.",
    subhead:
      "Pull our Docker image, point it at Postgres, and you're running production-grade identity in one command.",
  },
};

export default function Page() {
  return <ComparisonPage data={data} />;
}
