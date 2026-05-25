import { ArrowRightIcon } from "lucide-react";
import { ButtonLink } from "../button-link";

export function CTA() {
  return (
    <section className="relative overflow-hidden border-b border-border/60">
      <div
        className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(circle_at_50%_120%,theme(colors.primary/0.25),transparent_60%)]"
        aria-hidden
      />
      <div className="mx-auto flex max-w-4xl flex-col items-center px-4 py-20 text-center sm:px-6 lg:px-8 lg:py-28">
        <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
          Start building today.
          <br />
          <span className="text-primary">Free for developers.</span>
        </h2>
        <p className="mt-5 max-w-xl text-muted-foreground text-balance">
          5,000 monthly active users on the house. Production-grade auth, no credit card, no time
          limit.
        </p>
        <div className="mt-8 flex flex-col items-center gap-3 sm:flex-row">
          <ButtonLink size="lg" href="/sign-up">
            Create your account <ArrowRightIcon className="size-4" />
          </ButtonLink>
          <ButtonLink size="lg" variant="outline" href="/contact">
            Talk to sales
          </ButtonLink>
        </div>
      </div>
    </section>
  );
}
