import type { ReactNode } from "react";

/**
 * Shared shell for the /legal/* tree: eyebrow + title + "last updated"
 * line, with a constrained prose column. Pass section content as
 * children; use the exported building blocks for consistent rhythm.
 */
export interface LegalPageProps {
  title: string;
  /** ISO date, e.g. "2026-05-01". */
  updated: string;
  intro?: ReactNode;
  children: ReactNode;
}

function formatDate(iso: string) {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    timeZone: "UTC",
  });
}

export function LegalPage({ title, updated, intro, children }: LegalPageProps) {
  return (
    <section className="border-b border-border/60">
      <div className="mx-auto max-w-3xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <p className="text-sm font-medium uppercase tracking-widest text-primary">Legal</p>
        <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
          {title}
        </h1>
        <p className="mt-3 text-sm text-muted-foreground">Last updated {formatDate(updated)}</p>
        <p className="mt-6 rounded-xl border border-border/60 bg-muted/40 p-4 text-sm text-muted-foreground">
          This page is standard boilerplate provided for illustration. It is not legal advice and
          should be replaced with counsel-reviewed terms before launch.
        </p>
        {intro && <div className="mt-8 text-lg text-muted-foreground text-balance">{intro}</div>}
        <div className="mt-10 flex flex-col gap-8">{children}</div>
      </div>
    </section>
  );
}

export function LegalSection({ heading, children }: { heading: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-3">
      <h2 className="font-display text-xl font-semibold tracking-tight">{heading}</h2>
      <div className="flex flex-col gap-3 text-foreground/90 leading-relaxed">{children}</div>
    </div>
  );
}
