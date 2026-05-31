import { ArrowRightIcon, CheckCircle2Icon } from "lucide-react";
import { ButtonLink } from "../button-link";

const trust = ["No credit card", "5,000 MAU free", "SOC 2 · GDPR ready"];

export function CTA() {
  return (
    <section className="relative overflow-hidden border-b border-border/60">
      <div
        className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(circle_at_50%_120%,theme(colors.primary/0.25),transparent_60%)]"
        aria-hidden
      />
      <div className="mx-auto flex max-w-4xl flex-col items-center px-4 py-24 text-center sm:px-6 lg:px-8 lg:py-32">
        <h2 className="font-display text-4xl font-semibold tracking-tight text-balance sm:text-6xl">
          Start building today.
          <br />
          <span className="bg-[linear-gradient(110deg,var(--color-primary),#7c5cff_50%,#22d3ee)] bg-clip-text text-transparent">
            Free for developers.
          </span>
        </h2>
        <p className="mt-6 max-w-xl text-base text-muted-foreground text-balance sm:text-lg">
          5,000 monthly active users on the house. Production-grade auth, no credit card, no time
          limit.
        </p>
        <div className="mt-8 flex flex-col items-center gap-3 sm:flex-row">
          <ButtonLink size="lg" href="/sign-up" className="h-11 px-5">
            Create your account <ArrowRightIcon className="size-4" />
          </ButtonLink>
          <ButtonLink size="lg" variant="outline" href="/contact" className="h-11 px-5">
            Talk to sales
          </ButtonLink>
        </div>
        <ul className="mt-8 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-sm text-muted-foreground">
          {trust.map((t) => (
            <li key={t} className="flex items-center gap-1.5">
              <CheckCircle2Icon aria-hidden className="size-4 text-primary" />
              {t}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
