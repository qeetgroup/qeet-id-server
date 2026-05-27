// In-app changelog feed shown by the "What's new" header dropdown.
// Hand-authored — the docs site has the long-form changelog at
// /docs/changelog.mdx; this file is the short, scannable variant
// the admin surfaces. Add new entries at the top.
//
// `date` must be ISO format so the unread-state comparison and the
// rendered TimeSince component both work without parsing magic.

export interface ChangelogEntry {
  /** Stable id used as the React key. */
  id: string;
  /** ISO date, e.g. "2026-05-25". */
  date: string;
  /** Short headline. */
  title: string;
  /** One-paragraph summary. */
  description: string;
  /** Optional in-app deep-link the user can follow. */
  href?: string;
  /** Visual treatment hint. */
  kind?: "feature" | "improvement" | "fix" | "security";
}

export const CHANGELOG: ChangelogEntry[] = [
  {
    id: "passkey-prompt",
    date: "2026-05-26",
    title: "Add a passkey from the dashboard",
    description:
      "Signed-in admins now see a dismissible card recommending passkey enrollment. Faster sign-in, phishing-resistant.",
    href: "/auth/login-methods/passkeys",
    kind: "feature",
  },
  {
    id: "bulk-import",
    date: "2026-05-26",
    title: "Bulk user import (CSV + NDJSON)",
    description:
      "Drop a CSV or NDJSON file on the new Import page and we'll preview every row before the import runs.",
    href: "/users/import",
    kind: "feature",
  },
  {
    id: "audit-export",
    date: "2026-05-26",
    title: "Export audit logs to CSV or JSON",
    description:
      "Filter the audit log and click Export — up to 10,000 rows fan in respecting your current filter set.",
    href: "/security/audit-logs",
    kind: "feature",
  },
  {
    id: "cmd-k",
    date: "2026-05-26",
    title: "Jump anywhere with Cmd-K",
    description:
      "Press ⌘K (or Ctrl-K) for a navigation palette that searches across every route in the admin.",
    kind: "improvement",
  },
  {
    id: "impersonation-banner",
    date: "2026-05-26",
    title: "Impersonation safety banner",
    description:
      "When the access token carries an `act` claim, a sticky rose banner surfaces who you're acting as.",
    kind: "security",
  },
  {
    id: "tx-audit",
    date: "2026-05-26",
    title: "Tamper-evident audit log",
    description:
      "Every mutation now writes an audit row inside the same DB transaction, chained by SHA-256. Verifier endpoint at /tenants/{id}/audit/verify.",
    kind: "security",
  },
];

/** localStorage key for the most-recent date the user has acknowledged. */
export const CHANGELOG_LAST_SEEN_KEY = "qeetid-admin-changelog-last-seen";

/** Return the entries newer than the user's last-seen date. */
export function unseenEntries(lastSeenISO: string | null): ChangelogEntry[] {
  if (!lastSeenISO) return CHANGELOG;
  return CHANGELOG.filter((e) => e.date > lastSeenISO);
}
