// Release notes live in code (not a CMS) so the marketing site builds
// offline. Mirror of `lib/blog.ts` — migrate to MDX when cadence grows.

export type ChangelogTag = "new" | "improved" | "fixed" | "security";

export interface ChangelogEntry {
  version: string;
  /** ISO date the release shipped, e.g. "2026-05-20". */
  date: string;
  title: string;
  tags: ChangelogTag[];
  /** Bullet points describing what changed. */
  points: string[];
}

export const entries: ChangelogEntry[] = [
  {
    version: "1.8.0",
    date: "2026-05-22",
    title: "Passkey-first sign-in is generally available",
    tags: ["new", "security"],
    points: [
      "Passkeys are now the default primary factor for new tenants — phishing-resistant out of the box.",
      "Cross-device passkey flows via hybrid transport (QR + Bluetooth proximity).",
      "Conditional UI autofill on supported browsers for one-tap sign-in.",
    ],
  },
  {
    version: "1.7.0",
    date: "2026-05-06",
    title: "Streaming audit export to S3 and Kafka",
    tags: ["new", "improved"],
    points: [
      "Tamper-evident audit log can now stream directly to S3, Splunk, Datadog, and Kafka sinks.",
      "Per-sink redaction policies for PII-sensitive fields.",
      "Backfill API to replay historical events into a newly connected sink.",
    ],
  },
  {
    version: "1.6.2",
    date: "2026-04-18",
    title: "Faster permission evaluation",
    tags: ["improved", "fixed"],
    points: [
      "RBAC hot-path p99 dropped from 41ms to 28ms via a redesigned edge cache.",
      "Fixed a rare cache-invalidation race when a role and a group changed in the same transaction.",
      "Reduced cold-start latency for tenants in newly provisioned regions.",
    ],
  },
  {
    version: "1.6.0",
    date: "2026-03-30",
    title: "SCIM 2.0 provisioning and de-provisioning",
    tags: ["new"],
    points: [
      "Full SCIM 2.0 support for Okta, Azure AD, and JumpCloud directories.",
      "Just-in-time provisioning with attribute-to-role mapping.",
      "Automatic session revocation when a user is de-provisioned upstream.",
    ],
  },
  {
    version: "1.5.1",
    date: "2026-03-11",
    title: "Mandatory kid headers on every signed token",
    tags: ["security", "fixed"],
    points: [
      "Every JWT now carries a kid header; verifiers reject missing or unknown kids.",
      "Retired-key grace window makes JWKS rotation transparent to active sessions.",
      "Hardened token replay detection on the introspection endpoint.",
    ],
  },
  {
    version: "1.5.0",
    date: "2026-02-24",
    title: "Per-tenant branding and custom domains",
    tags: ["new", "improved"],
    points: [
      "Upload a logo, set brand colors, and serve sign-in on your own domain.",
      "Per-tenant email templates for magic links and verification.",
      "Data residency selector (US, EU, APAC) at the tenant level.",
    ],
  },
];

/** Entries sorted newest-first, suitable for the timeline. */
export function listEntries(): ChangelogEntry[] {
  return [...entries].sort((a, b) => b.date.localeCompare(a.date));
}
