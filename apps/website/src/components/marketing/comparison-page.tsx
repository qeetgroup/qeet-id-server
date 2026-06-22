import { cn } from "@qeetrix/ui";
import { ArrowRightIcon, CheckIcon, MinusIcon, XIcon } from "lucide-react";

import { ButtonLink } from "@/components/marketing/button-link";
import { Reveal, Stagger, StaggerItem } from "@/components/marketing/motion";
import { PageHero } from "@/components/marketing/page-hero";
import { Section } from "@/components/marketing/section";
import { BreadcrumbJsonLd } from "@/components/marketing/structured-data";
import { SIGN_UP_URL } from "@/lib/links";

/**
 * Comparison cell value. We avoid claims we can't substantiate by
 * letting the data file pick the most honest shape for each row:
 *
 *   - `true` / `false` → a clear ✓ or ✕
 *   - `"partial"` → a half-tick (e.g. "available on enterprise only")
 *   - string → a short qualifier, e.g. "$99/mo + per-MAU"
 */
export type Cell = true | false | "partial" | string;

export interface ComparisonRow {
  /** Category section header — rows with the same `section` cluster. */
  section: string;
  /** Capability label, e.g. "Self-hostable / open-source". */
  feature: string;
  /** What Qeet ID offers in this row. */
  qeetid: Cell;
  /** What the competitor offers. */
  competitor: Cell;
  /** Optional short footnote rendered below the row. */
  note?: string;
}

export interface ComparisonData {
  /** Competitor display name, e.g. "Auth0". */
  competitor: string;
  /** Short marketing-friendly description of the competitor (1 sentence). */
  competitorBlurb: string;
  /** Pitch above the table: "Why teams pick Qeet ID over <competitor>". */
  pitch: {
    headline: string;
    subhead: string;
    bullets: string[];
  };
  /** Quick fact summary on the right side of the hero. */
  factsQeetid: { label: string; value: string }[];
  factsCompetitor: { label: string; value: string }[];
  rows: ComparisonRow[];
  /** Closing CTA strip text + buttons. */
  cta?: {
    headline: string;
    subhead?: string;
  };
}

/** Legend metadata shared by the cell icons + the legend strip. */
const LEGEND = [
  { kind: "yes" as const, label: "Available" },
  { kind: "partial" as const, label: "Partial / gated" },
  { kind: "no" as const, label: "Not offered" },
];

function CellIcon({ value }: { value: Cell }) {
  if (value === true)
    return (
      <span
        title="Available"
        className="inline-flex size-6 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-400"
      >
        <CheckIcon className="size-3.5" aria-hidden />
        <span className="sr-only">Yes</span>
      </span>
    );
  if (value === false)
    return (
      <span
        title="Not offered"
        className="inline-flex size-6 items-center justify-center rounded-full bg-muted text-muted-foreground"
      >
        <XIcon className="size-3.5" aria-hidden />
        <span className="sr-only">No</span>
      </span>
    );
  if (value === "partial")
    return (
      <span
        title="Partial / gated"
        className="inline-flex size-6 items-center justify-center rounded-full bg-amber-500/15 text-amber-700 dark:text-amber-400"
      >
        <MinusIcon className="size-3.5" aria-hidden />
        <span className="sr-only">Partial</span>
      </span>
    );
  return <span className="text-sm">{value}</span>;
}

function LegendDot({ kind }: { kind: "yes" | "partial" | "no" }) {
  if (kind === "yes")
    return (
      <span className="inline-flex size-4 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-400">
        <CheckIcon className="size-2.5" aria-hidden />
      </span>
    );
  if (kind === "partial")
    return (
      <span className="inline-flex size-4 items-center justify-center rounded-full bg-amber-500/15 text-amber-700 dark:text-amber-400">
        <MinusIcon className="size-2.5" aria-hidden />
      </span>
    );
  return (
    <span className="inline-flex size-4 items-center justify-center rounded-full bg-muted text-muted-foreground">
      <XIcon className="size-2.5" aria-hidden />
    </span>
  );
}

/**
 * ComparisonPage renders the canonical Qeet ID-vs-X marketing layout:
 *
 *   PageHero (brand eyebrow + word-reveal title) with side-by-side fact sheets
 *      ↓
 *   Pitch (headline / sub-head / 3 bullets) — "why teams switch"
 *      ↓
 *   Feature-by-feature matrix grouped into sections (brand check/cross marks)
 *      ↓
 *   Honest "publicly-available info" disclaimer
 *      ↓
 *   Migration / CTA block
 *
 * Each comparison page is a thin data file; this component does the rendering so
 * they all look identical and stay easy to audit / update. Motion is supplied by
 * the reduced-motion-safe Reveal/Stagger primitives.
 */
export function ComparisonPage({ data }: { data: ComparisonData }) {
  // Group rows by section while preserving order.
  const sections: { name: string; rows: ComparisonRow[] }[] = [];
  const seen = new Map<string, ComparisonRow[]>();
  for (const r of data.rows) {
    if (!seen.has(r.section)) {
      seen.set(r.section, []);
      sections.push({ name: r.section, rows: seen.get(r.section)! });
    }
    seen.get(r.section)!.push(r);
  }

  const slug = data.competitor.toLowerCase().replace(/[^a-z0-9]+/g, "-");

  return (
    <>
      <BreadcrumbJsonLd
        items={[
          { name: "Home", url: "/" },
          { name: "Compare", url: "/compare" },
          { name: data.competitor, url: `/compare/${slug}` },
        ]}
      />

      <PageHero
        align="left"
        eyebrow="Compare"
        title="Qeet ID"
        titleAccent={`vs. ${data.competitor}`}
        subtitle={data.competitorBlurb}
      >
        <div className="mt-2 grid w-full max-w-md grid-cols-2 gap-3">
          <FactCard title="Qeet ID" rows={data.factsQeetid} highlighted />
          <FactCard title={data.competitor} rows={data.factsCompetitor} />
        </div>
      </PageHero>

      {/* Pitch — why teams switch */}
      <Section innerClassName="mx-auto max-w-6xl px-4 py-20 sm:px-6 lg:px-8 lg:py-24">
        <Reveal>
          <div className="relative overflow-hidden rounded-3xl border border-border/60 bg-card p-6 sm:p-10">
            <span
              aria-hidden
              className="pointer-events-none absolute inset-x-0 top-0 h-px bg-[image:var(--brand-gradient)]"
            />
            <h2 className="font-display text-2xl font-semibold tracking-tight text-balance sm:text-3xl">
              {data.pitch.headline}
            </h2>
            <p className="mt-3 max-w-2xl text-muted-foreground">{data.pitch.subhead}</p>
            <Stagger staggerDelay={0.08} className="mt-8 grid gap-3 sm:grid-cols-3">
              {data.pitch.bullets.map((b) => (
                <StaggerItem key={b}>
                  <div className="flex h-full items-start gap-2.5 rounded-xl border border-border/60 bg-background p-4 text-sm">
                    <span className="mt-0.5 inline-flex size-5 shrink-0 items-center justify-center rounded-full bg-brand/15 text-brand">
                      <CheckIcon className="size-3" aria-hidden />
                    </span>
                    <span>{b}</span>
                  </div>
                </StaggerItem>
              ))}
            </Stagger>
          </div>
        </Reveal>
      </Section>

      {/* Feature matrix */}
      <Section muted innerClassName="mx-auto max-w-6xl px-4 py-20 sm:px-6 lg:px-8 lg:py-24">
        <Reveal className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
              Feature-by-feature
            </h2>
            <p className="mt-2 max-w-xl text-muted-foreground">
              Verified against Qeet ID&apos;s implemented status and {data.competitor}&apos;s public
              docs. Where we&apos;re still building, we say so.
            </p>
          </div>
          <ul className="flex flex-wrap gap-x-5 gap-y-2 text-xs text-muted-foreground">
            {LEGEND.map((l) => (
              <li key={l.kind} className="flex items-center gap-1.5">
                <LegendDot kind={l.kind} />
                {l.label}
              </li>
            ))}
          </ul>
        </Reveal>

        <Reveal className="overflow-hidden rounded-2xl border border-border/60 bg-background">
          <table className="w-full table-fixed text-sm">
            <caption className="sr-only">
              Feature comparison between Qeet ID and {data.competitor}
            </caption>
            <thead>
              <tr className="border-b border-border/60 bg-muted/40">
                <th scope="col" className="px-4 py-3 text-left font-medium">
                  Capability
                </th>
                <th scope="col" className="w-32 px-4 py-3 text-center font-medium sm:w-44">
                  <span className="text-gradient-brand font-semibold">Qeet ID</span>
                </th>
                <th scope="col" className="w-32 px-4 py-3 text-center font-medium sm:w-44">
                  {data.competitor}
                </th>
              </tr>
            </thead>
            <tbody>
              {sections.map((section) => (
                <SectionRows key={section.name} name={section.name} rows={section.rows} />
              ))}
            </tbody>
          </table>
        </Reveal>

        {/* Honesty disclaimer */}
        <p className="mt-4 text-xs text-muted-foreground">
          Comparison is based on publicly-available product information at the time of writing.
          We do our best to be accurate — if anything above is wrong, please{" "}
          <a href="/contact" className="underline">
            let us know
          </a>{" "}
          and we&apos;ll correct it.
        </p>
      </Section>

      {/* Migration / CTA */}
      {data.cta && (
        <Section innerClassName="mx-auto max-w-5xl px-4 py-20 sm:px-6 lg:px-8 lg:py-24">
          <Reveal>
            <div className="relative overflow-hidden rounded-3xl bg-[image:var(--brand-gradient)] p-px shadow-2xl shadow-brand/20">
              <div className="relative flex flex-col items-center gap-5 rounded-[calc(1.5rem-1px)] bg-background/95 px-6 py-16 text-center backdrop-blur sm:px-12">
                <p className="text-xs font-medium uppercase tracking-widest text-brand-text">
                  Migrate from {data.competitor}
                </p>
                <h3 className="font-display text-2xl font-semibold tracking-tight text-balance sm:text-4xl">
                  {data.cta.headline}
                </h3>
                {data.cta.subhead && (
                  <p className="max-w-xl text-muted-foreground text-balance">{data.cta.subhead}</p>
                )}
                <div className="flex flex-col gap-3 sm:flex-row">
                  <ButtonLink size="lg" href={SIGN_UP_URL} className="h-11 px-5">
                    Start free <ArrowRightIcon className="size-4" />
                  </ButtonLink>
                  <ButtonLink size="lg" variant="outline" href="/contact" className="h-11 px-5">
                    Talk to sales
                  </ButtonLink>
                </div>
              </div>
            </div>
          </Reveal>
        </Section>
      )}
    </>
  );
}

function FactCard({
  title,
  rows,
  highlighted,
}: {
  title: string;
  rows: { label: string; value: string }[];
  highlighted?: boolean;
}) {
  return (
    <div
      className={cn(
        "rounded-xl border p-4 backdrop-blur",
        highlighted ? "border-brand/40 bg-brand/5" : "border-border/60 bg-card/70",
      )}
    >
      <p className={cn("text-sm font-semibold", highlighted && "text-gradient-brand")}>{title}</p>
      <dl className="mt-3 space-y-2 text-xs">
        {rows.map((r) => (
          <div key={r.label} className="flex justify-between gap-3">
            <dt className="text-muted-foreground">{r.label}</dt>
            <dd className="text-right font-medium">{r.value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function SectionRows({ name, rows }: { name: string; rows: ComparisonRow[] }) {
  return (
    <>
      <tr className="bg-muted/20">
        <th
          scope="colgroup"
          colSpan={3}
          className="px-4 py-2 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground"
        >
          {name}
        </th>
      </tr>
      {rows.map((r) => (
        <tr key={r.feature} className="border-t border-border/60">
          <th scope="row" className="px-4 py-3 text-left align-top font-medium">
            <div className="font-medium">{r.feature}</div>
            {r.note && <div className="mt-1 text-xs font-normal text-muted-foreground">{r.note}</div>}
          </th>
          <td className="px-4 py-3 text-center align-top">
            <CellIcon value={r.qeetid} />
          </td>
          <td className="px-4 py-3 text-center align-top">
            <CellIcon value={r.competitor} />
          </td>
        </tr>
      ))}
    </>
  );
}
