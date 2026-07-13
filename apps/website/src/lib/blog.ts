// Engineering blog posts. Lives in code (not a CMS) so the marketing
// site builds offline. When the team starts shipping weekly posts,
// migrate to MDX under `content/blog/*.mdx` + a build-time loader.

export interface BlogPost {
  slug: string;
  title: string;
  description: string;
  /** ISO date the post was published, e.g. "2026-05-12". */
  publishedAt: string;
  /** Author name; rendered next to the avatar fallback. */
  author: string;
  /** Optional author avatar URL. */
  authorAvatar?: string;
  /** Tags shown as muted pills on the index + post header. */
  tags: string[];
  /** Estimated reading time, e.g. "6 min read". */
  readingTime: string;
  /**
   * Body content as paragraphs. Keep it simple: headings emitted as
   * `## Heading` lines, code as triple-backtick fences. Renderer
   * handles those two formats. MDX comes later.
   */
  body: string;
}

export const posts: BlogPost[] = [
  {
    slug: "audit-log-hash-chain",
    title: "How we made our audit log tamper-evident",
    description:
      "A per-tenant SHA-256 chain + advisory locks. Why we picked this design over append-only Postgres logical replication.",
    publishedAt: "2026-05-20",
    author: "Sai Mareedu",
    tags: ["security", "audit", "postgres"],
    readingTime: "8 min read",
    body: `Audit logs are append-only by convention, but a privileged DB user can still DELETE rows or rewrite history. SOC 2 auditors want cryptographic integrity — and the typical answer is "ship logs to immutable storage." That's the right answer for the long term, but it introduces a network dependency on every mutation that has to be in the same transaction as the audit row.

## The design

Every row carries:

- \`prev_hash\` — the row_hash of the previous row in this tenant's chain
- \`row_hash\` — sha256(prev_hash || canonical_json(row))

To verify the chain you walk it from the genesis row and recompute. Tampering shows up as either a missing link or a hash mismatch.

## Concurrency

Two concurrent mutations on the same tenant would race to claim the same prev_hash. We serialise on a per-tenant pg_advisory_xact_lock:

\`\`\`go
lockKey := "audit:" + tenantID
tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", lockKey)
\`\`\`

This gives us a tenant-scoped critical section without a global table lock — busy tenants only serialise against themselves.

## What we didn't do

We considered logical-replication-to-Kafka and signing batches with a TPM. Both add operational surface area we didn't want at this stage. The chain runs entirely in Postgres; a future migration to a Merkle tree or external attestor is one column and a backfill away.`,
  },
  {
    slug: "log-redaction-without-regret",
    title: "Log redaction without regret",
    description:
      "How a 200-line slog.Handler wrapper made our structured logs SOC-2 friendly without changing a single call site.",
    publishedAt: "2026-05-08",
    author: "Sai Mareedu",
    tags: ["observability", "compliance", "go"],
    readingTime: "5 min read",
    body: `If your logger ever writes the bytes "password=hunter2" to stdout, you have a compliance problem. Most engineers know this; few teams have a guard that catches it everywhere.

## The wrapper

We built a slog.Handler middleware that walks every log record's attribute tree and masks 22 known-sensitive keys:

- \`password\`, \`*_token\`, \`*_secret\`, \`code\`, \`otp\`, \`authorization\`
- \`email\` → \`j***@domain.com\`
- \`phone\` → \`***1234\`

Nested groups (\`slog.Group("user", slog.String("email", ...))\`) recurse correctly.

## Why a handler, not a transformer

Transformer-style redaction runs at write time — too late if your logger has already serialised the record. A handler intercepts before serialisation, so the redacted view is what hits any sink. We test against the JSON output, not the in-memory record, to guarantee no leak path.`,
  },
  {
    slug: "kid-enforcement",
    title: "Why every JWT we sign carries a kid",
    description:
      "JWKS rotation is invisible until it breaks. Mandatory kid headers + a retired-key window made our rotation safe.",
    publishedAt: "2026-04-22",
    author: "Sai Mareedu",
    tags: ["security", "jwt", "oauth"],
    readingTime: "6 min read",
    body: `Our previous JWT issuer signed with a single key and didn't write a \`kid\` header. That works until the day you rotate.

## The trap

You rotate the key. The new signer is happy. Tokens in flight signed by the previous key still need to verify — but verifiers don't know which key signed them, because the header is missing. So you either accept any key (defeats the point of rotation) or you reject everything signed before the rotation moment (mass session-invalidation event).

## What we ship now

- Every \`Sign\` call writes a kid header sourced from the issuer's primary key id.
- Verifiers reject tokens with missing or unknown kid — \`invalid_token\`.
- Issuers carry a list of retired-but-still-trusted keys with a configurable grace window (default 24h).

The retired-key window is the trick: a token signed at T-1h with the old key still verifies at T+1h, so rotation is transparent to anyone currently signed in. After 24h the old key is purged.`,
  },
];

export function getPost(slug: string): BlogPost | undefined {
  return posts.find((p) => p.slug === slug);
}

/** Posts sorted newest-first, suitable for the index page. */
export function listPosts(): BlogPost[] {
  return [...posts].sort((a, b) => b.publishedAt.localeCompare(a.publishedAt));
}

/**
 * Posts related to a given one — ranked by shared tags, newest-first as the
 * tiebreaker. Excludes the post itself; capped at `limit`. Used for the
 * "Keep reading" strip on the post detail page.
 */
export function relatedPosts(slug: string, limit = 2): BlogPost[] {
  const current = getPost(slug);
  if (!current) return [];
  return posts
    .filter((p) => p.slug !== slug)
    .map((p) => ({
      post: p,
      score: p.tags.filter((t) => current.tags.includes(t)).length,
    }))
    .sort((a, b) => b.score - a.score || b.post.publishedAt.localeCompare(a.post.publishedAt))
    .slice(0, limit)
    .map((x) => x.post);
}

/**
 * Tiny renderer for the limited blog body format: paragraphs separated
 * by blank lines, with `## Heading` and triple-backtick fences. Avoids
 * pulling in a full MDX/markdown dep for what is currently three posts.
 */
export interface BlogBlock {
  kind: "p" | "h2" | "code";
  text: string;
  /** Language tag for code blocks. */
  lang?: string;
}

export function parseBody(body: string): BlogBlock[] {
  const out: BlogBlock[] = [];
  const lines = body.split("\n");
  let i = 0;
  while (i < lines.length) {
    const line = lines[i] ?? "";
    if (line.startsWith("```")) {
      const lang = line.slice(3).trim() || undefined;
      const buf: string[] = [];
      i++;
      while (i < lines.length && !(lines[i] ?? "").startsWith("```")) {
        buf.push(lines[i] ?? "");
        i++;
      }
      out.push({ kind: "code", text: buf.join("\n"), lang });
      i++;
      continue;
    }
    if (line.startsWith("## ")) {
      out.push({ kind: "h2", text: line.slice(3).trim() });
      i++;
      continue;
    }
    if (line.trim() === "") {
      i++;
      continue;
    }
    const buf: string[] = [];
    while (
      i < lines.length &&
      (lines[i] ?? "").trim() !== "" &&
      !(lines[i] ?? "").startsWith("## ") &&
      !(lines[i] ?? "").startsWith("```")
    ) {
      buf.push(lines[i] ?? "");
      i++;
    }
    out.push({ kind: "p", text: buf.join(" ") });
  }
  return out;
}
