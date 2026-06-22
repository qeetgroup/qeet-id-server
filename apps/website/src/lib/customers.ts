import type { CaseStudy } from "@/components/marketing/blocks/case-study-card";
import { caseStudySlug } from "@/components/marketing/blocks/case-study-card";

// Customer-story data lives in this file (not a CMS) so it ships with the
// marketing site and works offline.
//
// NOTE ON HONESTY: these stories are *representative composites*, not claims
// about specific named customers. Company names are deliberately generic
// product-archetypes (a "developer platform", a "fintech", etc.) and the
// metrics describe the shape of a typical outcome, not an audited result from
// a real logo. Replace with real, opted-in references and verified numbers
// before any of these is presented as a named customer fact.

export type CustomerSegment =
  | "Developer platform"
  | "Fintech"
  | "B2B SaaS"
  | "Healthcare"
  | "Marketplace";

export interface StorySection {
  /** Section heading, e.g. "The challenge". */
  heading: string;
  /** One or more narrative paragraphs. */
  body: string[];
}

export interface CustomerStory extends CaseStudy {
  /** One-line industry/segment label for cards and the detail hero. */
  industry: string;
  /** Coarse segment used for the index filter chips and related links. */
  segment: CustomerSegment;
  /** Short, representative scale descriptor (deliberately not a hard number). */
  scale: string;
  /** Structured story for the detail page: challenge → solution → results. */
  sections: StorySection[];
  /** Capability tags this story showcases (drives related-link matching). */
  highlights: string[];
}

export const stories: CustomerStory[] = [
  {
    company: "Northwind",
    logo: "N",
    industry: "Developer platform",
    segment: "Developer platform",
    scale: "Millions of API consumers",
    headline: "A developer platform replaced home-grown auth in two sprints",
    summary:
      "After years of maintaining bespoke session and SSO code, a developer-platform team consolidated onto Qeet ID — and deleted the legacy service.",
    metrics: [
      { value: "2 sprints", label: "to cut over" },
      { value: "1 service", label: "retired for good" },
      { value: "0", label: "planned downtime" },
    ],
    quote: {
      text: "We ripped out our home-grown auth in two sprints. Passkeys, SAML, and MFA were all working in the first week.",
      name: "Priya Anand",
      role: "Staff Engineer",
    },
    highlights: ["Passkeys", "SAML SSO", "Migration"],
    sections: [
      {
        heading: "The challenge",
        body: [
          "The platform team had built its own session store, SSO bridge, and MFA enrollment over several years. It worked, but every compliance cycle meant weeks of evidence-gathering, and auth incidents were the on-call rotation's least favourite page.",
          "Maintaining the bespoke stack also blocked the roadmap: every new factor or federation request became a quarter of plumbing nobody wanted to own.",
        ],
      },
      {
        heading: "The solution",
        body: [
          "They scoped a migration to Qeet ID in a single planning week. Passkeys, SAML, and TOTP were configured from the dashboard with no new deploys, and a dual-write cutover moved existing users without a maintenance window.",
          "Because Qeet ID self-hosts as a single Go binary, the team kept user data inside their own boundary while inheriting the platform's controls.",
        ],
      },
      {
        heading: "The results",
        body: [
          "Two sprints later the legacy auth service was switched off and deleted. The team reclaimed a meaningful slice of its roadmap, and the next audit inherited Qeet ID's controls wholesale.",
        ],
      },
    ],
  },
  {
    company: "Meridian Pay",
    logo: "M",
    industry: "Fintech · payments",
    segment: "Fintech",
    scale: "Regulated, high-assurance",
    headline: "A fintech made step-up auth and audit a non-event for compliance",
    summary:
      "A payments company needed phishing-resistant login, fine-grained step-up, and a tamper-evident trail it could hand an auditor without a fire drill.",
    metrics: [
      { value: "Phishing-resistant", label: "primary factor" },
      { value: "Hash-chained", label: "audit trail" },
      { value: "Self-hosted", label: "in their VPC" },
    ],
    quote: {
      text: "The audit log being hash-chained changed the conversation with our auditors entirely — we could prove integrity, not just assert it.",
      name: "Daniel Okafor",
      role: "Head of Platform Security",
    },
    highlights: ["Audit log", "Step-up MFA", "Self-hosting"],
    sections: [
      {
        heading: "The challenge",
        body: [
          "Moving money means proving who did what, when — and proving the record itself hasn't been altered. The team's previous setup could show events but couldn't demonstrate the log was tamper-evident, which made every audit a manual exercise in trust.",
          "They also wanted phishing-resistant authentication and step-up verification on sensitive actions, without bolting three vendors together.",
        ],
      },
      {
        heading: "The solution",
        body: [
          "Qeet ID's append-only, SHA-256 hash-chained audit log let them verify integrity with a single endpoint. Passkeys became the primary factor, and an ABAC policy gated high-risk actions behind step-up verification.",
          "Running the platform self-hosted inside their own VPC meant regulated data never crossed a third-party boundary.",
        ],
      },
      {
        heading: "The results",
        body: [
          "Audit prep went from a recurring scramble to producing a verifiable chain on demand. Security reviews started from a stronger baseline because the controls were the same ones the team could inspect in source.",
        ],
      },
    ],
  },
  {
    company: "Atlas Commerce",
    logo: "A",
    industry: "B2B SaaS · enterprise",
    segment: "B2B SaaS",
    scale: "Mid-market to enterprise",
    headline: "A B2B SaaS unlocked enterprise deals without a custom auth build",
    summary:
      "Multi-tenant isolation, SCIM provisioning, and per-org branding let a SaaS team say yes to enterprise requirements that used to be a quarter of custom work.",
    metrics: [
      { value: "SCIM 2.0", label: "users & groups" },
      { value: "Per-tenant", label: "isolation & branding" },
      { value: "Days, not quarters", label: "to onboard" },
    ],
    quote: {
      text: "Tenant isolation, SCIM, and our customer's logo on the login screen were configuration, not a roadmap item.",
      name: "Sofía Reyes",
      role: "CTO",
    },
    highlights: ["SCIM provisioning", "Multi-tenancy", "Branding"],
    sections: [
      {
        heading: "The challenge",
        body: [
          "A large prospect wanted hard data isolation, their own SSO, SCIM provisioning, and their brand on the sign-in screen — table stakes for enterprise, but a quarter of custom work the team didn't want to own or maintain.",
        ],
      },
      {
        heading: "The solution",
        body: [
          "Qeet ID provided tenant isolation at the data layer, per-org custom domains, and SCIM 2.0 (users and groups) out of the box. Branding was a dashboard setting rather than a deploy, and just-in-time provisioning mapped directory attributes straight onto roles.",
        ],
      },
      {
        heading: "The results",
        body: [
          "Enterprise requirements that once stalled deals became a short configuration checklist. The same setup now repeats for every new enterprise logo without re-engineering.",
        ],
      },
    ],
  },
  {
    company: "Cedar Health",
    logo: "C",
    industry: "Healthcare · patient portal",
    segment: "Healthcare",
    scale: "Privacy-sensitive workloads",
    headline: "A healthcare team kept sensitive data inside its own boundary",
    summary:
      "Self-hosting plus right-to-erasure and data-residency controls let a healthcare product adopt modern identity without handing PHI to a third party.",
    metrics: [
      { value: "Self-hosted", label: "in their region" },
      { value: "Right-to-erasure", label: "with audit preserved" },
      { value: "WebAuthn", label: "for clinicians" },
    ],
    quote: {
      text: "We needed modern passwordless auth without our patient data ever leaving our infrastructure. Self-hosting made that a non-negotiable we could actually meet.",
      name: "Maya Lindqvist",
      role: "VP Engineering",
    },
    highlights: ["Self-hosting", "Data residency", "Passkeys"],
    sections: [
      {
        heading: "The challenge",
        body: [
          "Patient data carries strict residency and privacy obligations. The team wanted passwordless sign-in for clinicians and a clean way to honour erasure requests, but couldn't route sensitive identities through an external CIAM cloud.",
        ],
      },
      {
        heading: "The solution",
        body: [
          "They ran Qeet ID self-hosted in their own region, so identity data never left their boundary. WebAuthn gave clinicians phishing-resistant login, and right-to-erasure performed an async PII purge while preserving the integrity of the audit trail.",
        ],
      },
      {
        heading: "The results",
        body: [
          "The team modernised authentication on terms their privacy obligations could accommodate, and erasure requests became a built-in workflow rather than a bespoke data project.",
        ],
      },
    ],
  },
  {
    company: "Tidewater",
    logo: "T",
    industry: "Marketplace · two-sided",
    segment: "Marketplace",
    scale: "High-traffic, spiky load",
    headline: "A marketplace kept permission checks fast under spiky load",
    summary:
      "A two-sided marketplace gated every action through Qeet ID's RBAC hot-path and kept evaluation snappy even during traffic spikes.",
    metrics: [
      { value: "Single-call", label: "permission checks" },
      { value: "Edge-cached", label: "decisions" },
      { value: "Explainable", label: "grant-path traces" },
    ],
    quote: {
      text: "The RBAC layer is the cleanest we've used, and when something is denied we get the exact grant-path back instead of guessing.",
      name: "Marcus Hale",
      role: "Principal Engineer",
    },
    highlights: ["RBAC", "Performance", "Explainability"],
    sections: [
      {
        heading: "The challenge",
        body: [
          "Every action across both sides of the marketplace is gated by a permission check, against a model that had grown organically into a tangle of special cases. Debugging a denial meant reverse-engineering which rule fired.",
        ],
      },
      {
        heading: "The solution",
        body: [
          "Qeet ID's RBAC engine let the team express hierarchical roles with inheritance and evaluate them on the hot path with a single /check call. Edge-cached decisions kept evaluation responsive during spikes, and explainable authorization returned the exact grant-path for every decision.",
        ],
      },
      {
        heading: "The results",
        body: [
          "The team stopped firefighting authorization edge cases and shifted focus back to product surface area. When a denial is questioned, the trace answers it directly.",
        ],
      },
    ],
  },
];

/** Look up a story by its URL slug. */
export function getStory(slug: string): CustomerStory | undefined {
  return stories.find((s) => caseStudySlug(s.company) === slug);
}

/** Alias matching the task's `getCustomer(slug)` naming. */
export const getCustomer = getStory;

/**
 * Stories related to a given one — same segment first, then any that share a
 * capability highlight. Excludes the story itself; capped at `limit`.
 */
export function relatedStories(slug: string, limit = 2): CustomerStory[] {
  const current = getStory(slug);
  if (!current) return [];
  const others = stories.filter((s) => caseStudySlug(s.company) !== slug);
  const scored = others
    .map((s) => {
      const sameSegment = s.segment === current.segment ? 2 : 0;
      const sharedTags = s.highlights.filter((h) => current.highlights.includes(h)).length;
      return { story: s, score: sameSegment + sharedTags };
    })
    .sort((a, b) => b.score - a.score);
  return scored.slice(0, limit).map((x) => x.story);
}
