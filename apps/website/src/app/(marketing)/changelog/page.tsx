import { Badge } from "@qeetrix/ui";
import type { Metadata } from "next";

import { Reveal, Stagger, StaggerItem } from "@/components/marketing/motion";
import { PageHero } from "@/components/marketing/page-hero";
import { CTA } from "@/components/marketing/sections/cta";
import { listGrouped, type ChangelogTag } from "@/lib/changelog";

export const metadata: Metadata = {
  title: "Changelog",
  description:
    "Every release shipped to Qeet ID — passkeys, ES256 / JWKS signing, SAML IdP, SCIM groups, the device grant, OpenTelemetry, and more.",
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
  const groups = listGrouped();

  return (
    <>
      <PageHero
        eyebrow="Changelog"
        title="Everything we've"
        titleAccent="shipped lately"
        subtitle="Product updates, performance work, and security improvements — released continuously and noted here in full."
      />

      <section className="border-b border-border/60">
        <div className="mx-auto max-w-3xl px-4 py-16 sm:px-6 lg:px-8 lg:py-24">
          {groups.map((group) => (
            <div key={group.label} className="mb-14 last:mb-0">
              <Reveal>
                <h2 className="mb-8 font-display text-sm font-medium uppercase tracking-widest text-brand-text">
                  {group.label}
                </h2>
              </Reveal>

              <Stagger staggerDelay={0.08} className="flex flex-col">
                {group.entries.map((r, i) => {
                  const last = i === group.entries.length - 1;
                  return (
                    <StaggerItem key={r.version}>
                      <article
                        aria-labelledby={`cl-${r.version}`}
                        className={`relative border-l pl-8 ${
                          last
                            ? "border-l-transparent pb-2"
                            : "border-l-border/60 pb-12"
                        }`}
                      >
                        {/* Brand accent rail node */}
                        <span
                          aria-hidden
                          className="absolute -left-1.5 top-1.5 size-3 rounded-full border-2 border-background bg-[image:var(--brand-gradient)]"
                        />

                        <div className="flex flex-col gap-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-mono text-sm font-medium text-foreground">
                              v{r.version}
                            </span>
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

                          <h3
                            id={`cl-${r.version}`}
                            className="font-display text-xl font-semibold tracking-tight text-balance"
                          >
                            {r.title}
                          </h3>

                          <ul className="flex flex-col gap-2 text-sm text-muted-foreground">
                            {r.points.map((p) => (
                              <li key={p} className="flex gap-2.5">
                                <span
                                  aria-hidden
                                  className="mt-1.5 size-1.5 shrink-0 rounded-full bg-brand"
                                />
                                <span>{p}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      </article>
                    </StaggerItem>
                  );
                })}
              </Stagger>
            </div>
          ))}
        </div>
      </section>

      <CTA />
    </>
  );
}
