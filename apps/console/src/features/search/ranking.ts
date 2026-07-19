// In-house fuzzy scorer and combined contextual ranker.
// Zero external dependencies — pure TypeScript, safe in both browser and Node.js
// (used by the browser runtime AND by Vitest unit tests).

// ─── Types ───────────────────────────────────────────────────────────────────

export interface RankCandidate {
  id: string;
  title: string;
  subtitle?: string;
  category?: string;
  keywords?: string[];
  url?: string;
}

export interface RankContext {
  /** IDs present in the recent store (for recency boost). */
  recentIds: ReadonlySet<string>;
  /** accessCount per id from the recent store (for frequency boost). */
  recentAccessCounts: ReadonlyMap<string, number>;
  /** IDs the operator has favorited (for favorites boost). */
  favoriteIds: ReadonlySet<string>;
  /** Current router pathname for route-segment affinity boost. */
  currentPathname: string;
}

export interface RankedItem<T extends RankCandidate> {
  item: T;
  /** Composite score ≥ 0. Higher is better. */
  score: number;
}

// ─── Text Scoring ─────────────────────────────────────────────────────────────

/**
 * Score `query` against a single `text` string.
 * Returns a value in [0, 100]; 0 means no meaningful match.
 *
 * Priority (highest → lowest):
 *   100 exact match
 *    90 prefix match
 *    80 first-word-boundary prefix
 *    70 later-word-boundary prefix
 *    60 substring containment
 *   1-40 subsequence (density-weighted)
 *   5-30 typo-tolerant (edit-distance ≤ 2, queries ≥ 3 chars)
 */
export function scoreText(query: string, text: string): number {
  if (!query || !text) return 0;
  const q = query.toLowerCase();
  const t = text.toLowerCase();

  if (t === q) return 100;
  if (t.startsWith(q)) return 90;

  const wb = _wordBoundaryScore(q, t);
  if (wb > 0) return wb;

  if (t.includes(q)) return 60;

  const ss = _subsequenceScore(q, t);
  if (ss > 0) return ss;

  if (q.length >= 3) return _typoTolerantScore(q, t);

  return 0;
}

function _wordBoundaryScore(q: string, t: string): number {
  const words = t.split(/[\s\-_./]+/);
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (w && w.startsWith(q)) return i === 0 ? 80 : 70;
  }
  return 0;
}

function _subsequenceScore(q: string, t: string): number {
  let qi = 0;
  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (q[qi] === t[ti]) qi++;
  }
  if (qi < q.length) return 0; // not all chars matched
  // Density: proportion of text chars that were matched query chars.
  const density = q.length / t.length;
  return Math.max(1, Math.round(40 * density));
}

/** Rolling-array Levenshtein edit distance — O(m·n) time, O(n) space. */
export function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  let curr = new Array<number>(n + 1);
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      curr[j] =
        a[i - 1] === b[j - 1]
          ? (prev[j - 1] as number)
          : 1 + Math.min(prev[j] as number, curr[j - 1] as number, prev[j - 1] as number);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n] as number;
}

function _typoTolerantScore(q: string, t: string): number {
  const maxDist = q.length <= 4 ? 1 : 2;
  // Slide a window of `q.length` chars over the text.
  for (let i = 0; i <= t.length - q.length; i++) {
    const window = t.slice(i, i + q.length);
    const dist = editDistance(q, window);
    if (dist <= maxDist) return Math.max(5, 30 - dist * 10);
  }
  return 0;
}

// ─── Candidate Scoring ────────────────────────────────────────────────────────

/**
 * Score a search candidate against a query across all its text fields.
 * The title is weighted highest; keywords at 90 %; subtitle at 70 %;
 * category at 50 % (so a category match doesn't surface unrelated items
 * above strong title matches).
 *
 * Returns 0 when there is no meaningful match.
 */
export function score(query: string, candidate: RankCandidate): number {
  if (!query) return 0;

  let best = scoreText(query, candidate.title); // weight 1.0

  for (const kw of candidate.keywords ?? []) {
    const s = scoreText(query, kw) * 0.9;
    if (s > best) best = s;
  }

  if (candidate.subtitle) {
    const s = scoreText(query, candidate.subtitle) * 0.7;
    if (s > best) best = s;
  }

  if (candidate.category) {
    const s = scoreText(query, candidate.category) * 0.5;
    if (s > best) best = s;
  }

  return best;
}

// ─── Combined Ranker ──────────────────────────────────────────────────────────

/**
 * Rank candidates against an optional query with contextual boosts.
 *
 * With `query`:  all candidates are scored; those with score > 0 are returned
 *                sorted descending with recency/frequency/favorites on top.
 * Without query: only recents and favorites are returned (no text scoring),
 *                ordered by favorite > recency, most-recent first.
 */
export function rankItems<T extends RankCandidate>(
  items: T[],
  query: string,
  ctx: RankContext,
): Array<RankedItem<T>> {
  const results: Array<RankedItem<T>> = [];

  for (const item of items) {
    let baseScore: number;

    if (query) {
      baseScore = score(query, item);
      if (baseScore === 0) continue;
    } else {
      // No query: only surface items the operator has interacted with.
      const isFav = ctx.favoriteIds.has(item.id);
      const isRecent = ctx.recentIds.has(item.id);
      if (!isFav && !isRecent) continue;
      baseScore = 50;
    }

    // Favorites boost (+30)
    if (ctx.favoriteIds.has(item.id)) baseScore += 30;

    // Recency + frequency boost: log-scaled, capped at +25.
    const accessCount = ctx.recentAccessCounts.get(item.id) ?? 0;
    if (accessCount > 0) {
      baseScore += Math.min(25, Math.floor(Math.log2(accessCount + 1) * 10));
    }

    // Route-segment affinity: items sharing path segments with the current
    // route float up slightly (+2 per shared segment, e.g. /users matches
    // /users/sessions because both share "users").
    if (item.url && ctx.currentPathname) {
      const pathSegs = new Set(ctx.currentPathname.split("/").filter(Boolean));
      const itemSegs = item.url.split("/").filter(Boolean);
      const shared = itemSegs.filter((s) => pathSegs.has(s)).length;
      if (shared > 0) baseScore += shared * 2;
    }

    results.push({ item, score: baseScore });
  }

  return results.sort((a, b) => b.score - a.score);
}
