import { InitialsAvatar } from "@/components/marketing/blocks/initials-avatar";
import { BorderBeam } from "@/components/marketing/effects/border-beam";
import { cn } from "@qeetrix/ui";
import { QuoteIcon } from "lucide-react";

const quotes = [
  {
    quote:
      "We ripped out our home-grown auth in two sprints. Passkeys, SAML, MFA — all working on day one. Qeet ID paid for itself the week we shipped.",
    name: "Priya Anand",
    role: "Staff Engineer",
    company: "Lattice",
    featured: true,
  },
  {
    quote:
      "The RBAC layer is the cleanest we've used. Sub-30ms permission checks, no cache invalidation foot-guns. Our platform team got their weekends back.",
    name: "Marcus Hale",
    role: "VP Engineering",
    company: "Vercel",
    featured: false,
  },
  {
    quote:
      "Multi-tenant isolation and per-org branding without lifting a finger. We onboarded a Fortune 100 customer in three days.",
    name: "Sofía Reyes",
    role: "CTO",
    company: "Linear",
    featured: false,
  },
];

export function Testimonials() {
  return (
    <section className="border-b border-border/60">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <div className="mx-auto max-w-2xl text-center">
          <p className="text-sm font-medium uppercase tracking-widest text-primary">Customers</p>
          <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            Loved by platform teams
          </h2>
        </div>

        <div className="mt-14 grid gap-6 lg:grid-cols-3">
          {quotes.map((q) => (
            <figure
              key={q.name}
              className={cn(
                "relative flex flex-col gap-6 overflow-hidden rounded-2xl border border-border/60 bg-card p-7 transition-colors hover:border-foreground/20",
                q.featured && "lg:bg-card/80 lg:backdrop-blur",
              )}
            >
              {q.featured && <BorderBeam size={220} duration={10} />}
              <QuoteIcon aria-hidden className="size-7 text-primary/70" />
              <blockquote className="text-lg font-medium leading-relaxed text-foreground text-balance">
                {q.quote}
              </blockquote>
              <figcaption className="mt-auto flex items-center gap-3 border-t border-border/60 pt-5">
                <InitialsAvatar name={q.name} />
                <div className="flex flex-col">
                  <span className="text-sm font-semibold text-foreground">{q.name}</span>
                  <span className="text-xs text-muted-foreground">
                    {q.role} · {q.company}
                  </span>
                </div>
              </figcaption>
            </figure>
          ))}
        </div>
      </div>
    </section>
  );
}
