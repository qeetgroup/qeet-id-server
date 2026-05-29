import { cn } from "@qeetid/ui";
import { CheckIcon, MinusIcon, XIcon } from "lucide-react";

import { ButtonLink } from "@/components/marketing/button-link";
import { BreadcrumbJsonLd } from "@/components/marketing/structured-data";

/**
 * Comparison cell value. We avoid claims we can't substantiate by
 * letting the data file pick the most honest shape for each row:
 *
 *   - `true` / `false` → a clear ✓ or ✕
 *   - `"partial"` → a half-tick (e.g. "available on enterprise only")
 *   - string → a short qualifier, e.g. "$99/mo + per-MAU"
 */
export type Cell = true | false | "partial" | string

export interface ComparisonRow {
  /** Category section header — rows with the same `section` cluster. */
  section: string
  /** Capability label, e.g. "Self-hostable / open-source". */
  feature: string
  /** What Qeet ID offers in this row. */
  qeetid: Cell
  /** What the competitor offers. */
  competitor: Cell
  /** Optional short footnote rendered below the row. */
  note?: string
}

export interface ComparisonData {
  /** Competitor display name, e.g. "Auth0". */
  competitor: string
  /** Short marketing-friendly description of the competitor (1 sentence). */
  competitorBlurb: string
  /** Pitch above the table: "Why teams pick Qeet ID over <competitor>". */
  pitch: {
    headline: string
    subhead: string
    bullets: string[]
  }
  /** Quick fact summary on the right side of the hero. */
  factsQeetid: { label: string; value: string }[]
  factsCompetitor: { label: string; value: string }[]
  rows: ComparisonRow[]
  /** Closing CTA strip text + buttons. */
  cta?: {
    headline: string
    subhead?: string
  }
}

function CellIcon({ value }: { value: Cell }) {
  if (value === true)
    return (
      <span className="inline-flex size-6 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-400">
        <CheckIcon className="size-3.5" />
      </span>
    )
  if (value === false)
    return (
      <span className="inline-flex size-6 items-center justify-center rounded-full bg-muted text-muted-foreground">
        <XIcon className="size-3.5" />
      </span>
    )
  if (value === "partial")
    return (
      <span className="inline-flex size-6 items-center justify-center rounded-full bg-amber-500/15 text-amber-700 dark:text-amber-400">
        <MinusIcon className="size-3.5" />
      </span>
    )
  return <span className="text-sm">{value}</span>
}

/**
 * ComparisonPage renders the canonical Qeet ID-vs-X marketing layout:
 *
 *   Hero with side-by-side "fact sheets"
 *      ↓
 *   Pitch (headline / sub-head / 3 bullets)
 *      ↓
 *   Feature-by-feature table grouped into sections
 *      ↓
 *   Honest "where the competitor still wins" disclaimer
 *      ↓
 *   CTA strip
 *
 * Each comparison page is a thin data file; this component does the
 * rendering so they all look identical and stay easy to audit /
 * update.
 */
export function ComparisonPage({ data }: { data: ComparisonData }) {
  // Group rows by section while preserving order.
  const sections: { name: string; rows: ComparisonRow[] }[] = []
  const seen = new Map<string, ComparisonRow[]>()
  for (const r of data.rows) {
    if (!seen.has(r.section)) {
      seen.set(r.section, [])
      sections.push({ name: r.section, rows: seen.get(r.section)! })
    }
    seen.get(r.section)!.push(r)
  }

  const slug = data.competitor.toLowerCase().replace(/[^a-z0-9]+/g, "-");

  return (
    <div className="mx-auto w-full max-w-6xl px-4 py-16 sm:px-6 sm:py-24">
      <BreadcrumbJsonLd
        items={[
          { name: "Home", url: "/" },
          { name: "Compare", url: "/compare" },
          { name: data.competitor, url: `/compare/${slug}` },
        ]}
      />
      {/* Hero */}
      <div className="mb-12 grid gap-8 lg:grid-cols-2 lg:items-start">
        <div>
          <p className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Compare
          </p>
          <h1 className="mt-2 text-3xl font-bold tracking-tight sm:text-5xl">
            Qeet ID <span className="text-muted-foreground">vs.</span> {data.competitor}
          </h1>
          <p className="mt-4 max-w-xl text-balance text-lg text-muted-foreground">
            {data.competitorBlurb}
          </p>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <FactCard title="Qeet ID" rows={data.factsQeetid} highlighted />
          <FactCard title={data.competitor} rows={data.factsCompetitor} />
        </div>
      </div>

      {/* Pitch */}
      <div className="mb-16 rounded-2xl border bg-card p-6 sm:p-10">
        <h2 className="text-2xl font-semibold tracking-tight">{data.pitch.headline}</h2>
        <p className="mt-2 max-w-2xl text-muted-foreground">{data.pitch.subhead}</p>
        <ul className="mt-6 grid gap-3 sm:grid-cols-3">
          {data.pitch.bullets.map((b) => (
            <li key={b} className="flex items-start gap-2 text-sm">
              <CheckIcon className="mt-0.5 size-4 shrink-0 text-emerald-500" />
              {b}
            </li>
          ))}
        </ul>
      </div>

      {/* Table */}
      <div className="overflow-hidden rounded-2xl border">
        <table className="w-full table-fixed text-sm">
          <thead className="bg-muted/40">
            <tr>
              <th className="px-4 py-3 text-left font-medium">Capability</th>
              <th className="w-40 px-4 py-3 text-center font-medium">Qeet ID</th>
              <th className="w-40 px-4 py-3 text-center font-medium">{data.competitor}</th>
            </tr>
          </thead>
          <tbody>
            {sections.map((section) => (
              <SectionRows key={section.name} name={section.name} rows={section.rows} />
            ))}
          </tbody>
        </table>
      </div>

      {/* Honesty disclaimer */}
      <p className="mt-4 text-xs text-muted-foreground">
        Comparison is based on publicly-available product information at the time of writing.
        We do our best to be accurate — if anything below is wrong, please{" "}
        <a href="/contact" className="underline">
          let us know
        </a>{" "}
        and we&apos;ll correct it.
      </p>

      {/* CTA */}
      {data.cta && (
        <div className="mt-16 flex flex-col items-center gap-4 rounded-2xl border bg-primary/5 p-8 text-center sm:p-12">
          <h3 className="text-2xl font-semibold tracking-tight">{data.cta.headline}</h3>
          {data.cta.subhead && (
            <p className="max-w-xl text-muted-foreground">{data.cta.subhead}</p>
          )}
          <div className="flex flex-wrap justify-center gap-2">
            <ButtonLink href="/sign-up">Start free</ButtonLink>
            <ButtonLink href="/contact" variant="outline">
              Talk to sales
            </ButtonLink>
          </div>
        </div>
      )}
    </div>
  )
}

function FactCard({
  title,
  rows,
  highlighted,
}: {
  title: string
  rows: { label: string; value: string }[]
  highlighted?: boolean
}) {
  return (
    <div
      className={cn(
        "rounded-xl border p-4",
        highlighted ? "border-primary bg-primary/5" : "bg-card",
      )}
    >
      <p className="text-sm font-semibold">{title}</p>
      <dl className="mt-3 space-y-2 text-xs">
        {rows.map((r) => (
          <div key={r.label} className="flex justify-between gap-3">
            <dt className="text-muted-foreground">{r.label}</dt>
            <dd className="text-right font-medium">{r.value}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

function SectionRows({ name, rows }: { name: string; rows: ComparisonRow[] }) {
  return (
    <>
      <tr className="bg-muted/20">
        <td colSpan={3} className="px-4 py-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          {name}
        </td>
      </tr>
      {rows.map((r) => (
        <tr key={r.feature} className="border-t">
          <td className="px-4 py-3 align-top">
            <div className="font-medium">{r.feature}</div>
            {r.note && <div className="mt-1 text-xs text-muted-foreground">{r.note}</div>}
          </td>
          <td className="px-4 py-3 text-center align-top">
            <CellIcon value={r.qeetid} />
          </td>
          <td className="px-4 py-3 text-center align-top">
            <CellIcon value={r.competitor} />
          </td>
        </tr>
      ))}
    </>
  )
}
