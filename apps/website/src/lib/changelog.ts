// Release notes live in code (not a CMS) so the marketing site builds
// offline. Mirror of `lib/blog.ts` — migrate to MDX when cadence grows.
//
// Entries reflect capabilities that exist in the platform today (ES256 / JWKS
// token signing, passkeys / WebAuthn, SAML IdP, SCIM 2.0 users & groups, the
// OAuth device grant, OpenTelemetry tracing, the hash-chained audit log, and
// the SDKs). Versions/dates are illustrative of a pre-1.0 cadence.

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
    version: "0.12.0",
    date: "2026-05-22",
    title: "Passkey-first sign-in",
    tags: ["new", "security"],
    points: [
      "Passkeys (FIDO2 / WebAuthn) can now be the default primary factor for new tenants — phishing-resistant out of the box.",
      "Cross-device passkey flows via hybrid transport for signing in on a second device.",
      "Conditional-UI autofill on supported browsers for one-tap sign-in.",
    ],
  },
  {
    version: "0.11.0",
    date: "2026-05-06",
    title: "OAuth 2.0 device authorization grant",
    tags: ["new"],
    points: [
      "Added the device grant (RFC 8628) for CLIs, TVs, and other input-constrained clients.",
      "User-friendly verification codes with a hosted device-approval screen.",
      "Polling and slow-down handling per spec, scoped to the requesting tenant.",
    ],
  },
  {
    version: "0.10.0",
    date: "2026-04-18",
    title: "ES256 token signing with a JWKS endpoint",
    tags: ["security", "improved"],
    points: [
      "ID tokens are signed with ES256 (ECDSA P-256) and published at a standard JWKS endpoint.",
      "RFC 7638 key IDs (kid) on every token; verifiers reject missing or unknown kids.",
      "A retired-key grace window makes rotation transparent to active sessions, with an algorithm-confusion guard.",
    ],
  },
  {
    version: "0.9.0",
    date: "2026-03-30",
    title: "SAML IdP and SCIM 2.0 groups",
    tags: ["new"],
    points: [
      "Qeet ID can now act as a SAML identity provider with RSA-SHA256-signed assertions.",
      "SCIM 2.0 provisioning extended from users to groups, including PatchOp membership sync.",
      "Just-in-time provisioning maps directory attributes onto roles on first sign-in.",
    ],
  },
  {
    version: "0.8.1",
    date: "2026-03-11",
    title: "Faster, explainable permission checks",
    tags: ["improved", "fixed"],
    points: [
      "The RBAC /check hot-path is edge-cached, keeping evaluation responsive under spiky load.",
      "Authorization decisions now return an explainable grant-path trace — which role or group allowed it, or why it was denied.",
      "Fixed a rare cache-invalidation race when a role and a group changed in the same transaction.",
    ],
  },
  {
    version: "0.8.0",
    date: "2026-02-24",
    title: "OpenTelemetry tracing and official SDKs",
    tags: ["new", "improved"],
    points: [
      "End-to-end OpenTelemetry traces across auth, OIDC, RBAC, and webhook dispatch, exportable to any OTLP backend.",
      "Official server SDKs published for TypeScript and Go, generated from the OpenAPI contract.",
      "Webhook deliveries are HMAC-SHA256 signed and flow through a transactional outbox with retries and a dead-letter queue.",
    ],
  },
  {
    version: "0.7.0",
    date: "2026-01-28",
    title: "Per-tenant branding and data residency",
    tags: ["new", "improved"],
    points: [
      "Upload a logo, set brand colors, and serve sign-in on your own custom domain per tenant.",
      "Per-tenant email templates for magic links and verification.",
      "Data-residency selector (US / EU) at the tenant level, or self-host the single Go binary anywhere.",
    ],
  },
];

/** Entries sorted newest-first, suitable for the timeline. */
export function listEntries(): ChangelogEntry[] {
  return [...entries].sort((a, b) => b.date.localeCompare(a.date));
}

export interface ChangelogGroup {
  /** e.g. "May 2026" — the month/year heading for this batch. */
  label: string;
  entries: ChangelogEntry[];
}

/**
 * Newest-first entries grouped by month+year, for the timeline's rail headings.
 * Group order follows the (descending) date of each group's first entry.
 */
export function listGrouped(): ChangelogGroup[] {
  const sorted = listEntries();
  const groups = new Map<string, ChangelogEntry[]>();
  for (const entry of sorted) {
    const label = new Date(`${entry.date}T00:00:00Z`).toLocaleDateString("en-US", {
      month: "long",
      year: "numeric",
      timeZone: "UTC",
    });
    const bucket = groups.get(label);
    if (bucket) bucket.push(entry);
    else groups.set(label, [entry]);
  }
  return [...groups.entries()].map(([label, groupEntries]) => ({
    label,
    entries: groupEntries,
  }));
}
