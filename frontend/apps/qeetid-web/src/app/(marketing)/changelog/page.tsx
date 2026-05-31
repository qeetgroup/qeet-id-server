import { listEntries, type ChangelogTag } from "@/lib/changelog";
import { Badge } from "@qeetrix/ui";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Changelog",
  description: "Every release, fix, and security improvement shipped to Qeet ID.",
};

const tagVariant: Record<ChangelogTag, "default" | "secondary" | "success" | "warning"> = {
  new: "default",
  improved: "secondary",
  fixed: "success",
  security: "warning",
};

function formatDate(iso: string) {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    timeZone: "UTC",
  });
}

export default function ChangelogPage() {
  const releases = listEntries();
  return (
    <section className="border-b border-border/60">
      <div className="mx-auto max-w-3xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <div className="max-w-2xl">
          <p className="text-sm font-medium uppercase tracking-widest text-primary">Changelog</p>
          <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
            What&apos;s new in Qeet ID
          </h1>
          <p className="mt-5 text-muted-foreground text-balance sm:text-lg">
            Product updates, performance work, and security improvements — shipped continuously.
          </p>
        </div>

        <ol className="mt-16 flex flex-col">
          {releases.map((r) => (
            <li
              key={r.version}
              className="relative border-l border-border/60 pb-12 pl-8 last:border-l-transparent last:pb-0"
            >
              <span
                aria-hidden
                className="absolute -left-[5px] top-1.5 size-2.5 rounded-full border-2 border-background bg-primary"
              />
              <div className="flex flex-col gap-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm font-medium text-foreground">v{r.version}</span>
                  <span aria-hidden className="text-muted-foreground/50">
                    ·
                  </span>
                  <time dateTime={r.date} className="text-xs text-muted-foreground">
                    {formatDate(r.date)}
                  </time>
                  <span className="ml-1 flex flex-wrap gap-1.5">
                    {r.tags.map((t) => (
                      <Badge key={t} variant={tagVariant[t]} className="capitalize">
                        {t}
                      </Badge>
                    ))}
                  </span>
                </div>
                <h2 className="font-display text-xl font-semibold tracking-tight text-balance">
                  {r.title}
                </h2>
                <ul className="flex flex-col gap-2 text-sm text-muted-foreground">
                  {r.points.map((p) => (
                    <li key={p} className="flex gap-2">
                      <span aria-hidden className="mt-1.5 size-1 shrink-0 rounded-full bg-primary" />
                      {p}
                    </li>
                  ))}
                </ul>
              </div>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
