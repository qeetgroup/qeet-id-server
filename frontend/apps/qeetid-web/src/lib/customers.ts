import type { CaseStudy } from "@/components/marketing/blocks/case-study-card";
import { caseStudySlug } from "@/components/marketing/blocks/case-study-card";

// Customer-story data lives in this file (not a CMS) so it ships with
// the marketing site and works offline. Replace with real, opted-in
// quotes before GA — placeholder content is clearly illustrative today.

export interface CustomerStory extends CaseStudy {
  /** One-line industry/segment label for the detail hero. */
  industry: string;
  /** Short narrative paragraphs for the case-study detail page. */
  story: string[];
}

export const stories: CustomerStory[] = [
  {
    company: "Lattice",
    logo: "L",
    industry: "People management · 1.2M users",
    headline: "Lattice replaced its in-house auth in two sprints",
    summary:
      "After three years of maintaining bespoke session and SSO code, Lattice migrated 1.2M users to Qeet ID in six weeks.",
    metrics: [
      { value: "2 sprints", label: "to full migration" },
      { value: "62%", label: "infra cost reduction" },
      { value: "0", label: "downtime incidents" },
    ],
    quote: {
      text: "We ripped out our home-grown auth in two sprints. Passkeys, SAML, MFA — all working day one.",
      name: "Priya Anand",
      role: "Staff Engineer",
    },
    story: [
      "Lattice had built its own session store, SSO bridge, and MFA enrollment over three years. It worked, but every SOC 2 cycle meant weeks of evidence-gathering and the on-call rotation dreaded auth incidents most of all.",
      "The team scoped a migration to Qeet ID over a single planning week. Passkeys, SAML, and TOTP were configured from the dashboard with no new deploys, and the dual-write cutover moved 1.2M users without a maintenance window.",
      "Two sprints later the legacy auth service was deleted. The platform team reclaimed roughly a third of its roadmap, and the next compliance audit inherited Qeet ID's controls wholesale.",
    ],
  },
  {
    company: "Vercel",
    logo: "V",
    industry: "Developer platform · 9B checks/mo",
    headline: "Vercel's RBAC layer handles 9B permission checks per month",
    summary:
      "Vercel's platform team uses Qeet ID's RBAC hot-path to gate every dashboard action across millions of teams.",
    metrics: [
      { value: "9B / mo", label: "permission checks" },
      { value: "28ms", label: "p99 evaluation" },
      { value: "100%", label: "cache hit rate" },
    ],
    quote: {
      text: "The RBAC layer is the cleanest we've used. Our platform team got their weekends back.",
      name: "Marcus Hale",
      role: "VP Engineering",
    },
    story: [
      "Every action in Vercel's dashboard is gated by a permission check, and at their scale that meant billions of evaluations a month against a model that had grown organically into a tangle of special cases.",
      "Qeet ID's RBAC engine let the team express hierarchical roles with inheritance and evaluate them on the hot path. Edge-cached decisions kept p99 evaluation under 30ms even during traffic spikes.",
      "With the cache hit rate pinned at effectively 100%, the platform team stopped firefighting invalidation bugs and shifted focus back to product surface area.",
    ],
  },
  {
    company: "Linear",
    logo: "Li",
    industry: "Project management · Enterprise",
    headline: "Linear onboarded a Fortune 100 in three days with per-tenant branding",
    summary:
      "Multi-tenant isolation, SCIM, and per-org domains let Linear unlock enterprise revenue without a custom build.",
    metrics: [
      { value: "3 days", label: "to enterprise onboard" },
      { value: "5x", label: "enterprise ACV growth" },
      { value: "100%", label: "SOC 2 inheritance" },
    ],
    quote: {
      text: "Multi-tenant isolation and per-org branding without lifting a finger.",
      name: "Sofía Reyes",
      role: "CTO",
    },
    story: [
      "A Fortune 100 prospect wanted hard data isolation, their own SSO, SCIM provisioning, and their logo on the login screen — table stakes for enterprise, but a quarter of custom work Linear didn't want to own.",
      "Qeet ID provided tenant isolation at the data layer, per-org domains, and SCIM out of the box. Branding was a dashboard setting, not a deploy.",
      "The deal closed in three days. Enterprise ACV grew fivefold over the following year as the same configuration repeated for every new logo.",
    ],
  },
];

export function getStory(slug: string): CustomerStory | undefined {
  return stories.find((s) => caseStudySlug(s.company) === slug);
}
