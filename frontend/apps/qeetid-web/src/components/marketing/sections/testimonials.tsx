import { InitialsAvatar } from "@/components/marketing/blocks/initials-avatar";
import { LogoLockup } from "@/components/marketing/blocks/logo-wall";
import { BorderBeam } from "@/components/marketing/effects/border-beam";
import { Marquee } from "@/components/marketing/effects/marquee";
import { Reveal, Stagger, StaggerItem, Tilt, WordReveal } from "@/components/marketing/motion";
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

const logoRow = [
  "Lattice",
  "Vercel",
  "Linear",
  "Ramp",
  "Retool",
  "Notion",
  "Loom",
  "Brex",
  "Mercury",
  "Cron",
];

export function Testimonials() {
  return (
    <section className="border-b border-border/60">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <Reveal className="mx-auto max-w-2xl text-center">
          <p className="text-sm font-medium uppercase tracking-widest text-brand-text">Customers</p>
          <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            <WordReveal text="Loved by platform teams" />
          </h2>
        </Reveal>

        <Stagger staggerDelay={0.12} className="mt-14 grid gap-6 lg:grid-cols-3">
          {quotes.map((q) => (
            <StaggerItem key={q.name} className="h-full">
              <Tilt max={4} perspective={1200} className="h-full">
                <figure
                  className={cn(
                    "relative flex h-full flex-col gap-6 overflow-hidden rounded-2xl border border-border/60 bg-card p-7 transition-[transform,border-color,box-shadow] duration-300 hover:-translate-y-1 hover:border-foreground/20 hover:shadow-xl hover:shadow-black/5",
                    q.featured && "lg:bg-card/80 lg:backdrop-blur",
                  )}
                >
                  {q.featured && (
                    <>
                      <span
                        aria-hidden
                        className="pointer-events-none absolute -right-16 -top-16 size-48 rounded-full bg-linear-to-br from-brand/30 to-transparent opacity-60 blur-3xl"
                      />
                      <BorderBeam
                        size={220}
                        duration={10}
                        colorFrom="var(--brand-500)"
                        colorTo="var(--brand-300)"
                      />
                    </>
                  )}
                  <QuoteIcon aria-hidden className="relative size-7 text-brand/70" />
                  <blockquote className="relative text-lg font-medium leading-relaxed text-foreground text-balance">
                    {q.quote}
                  </blockquote>
                  <figcaption className="relative mt-auto flex items-center gap-3 border-t border-border/60 pt-5">
                    <InitialsAvatar name={q.name} />
                    <div className="flex flex-col">
                      <span className="text-sm font-semibold text-foreground">{q.name}</span>
                      <span className="text-xs text-muted-foreground">
                        {q.role} · {q.company}
                      </span>
                    </div>
                  </figcaption>
                </figure>
              </Tilt>
            </StaggerItem>
          ))}
        </Stagger>

        {/* Calm logo row — reinforces the wall of names without stealing focus. */}
        <Reveal
          delay={0.1}
          className="relative mt-14 [mask-image:linear-gradient(to_right,transparent,black_12%,black_88%,transparent)]"
        >
          <Marquee duration={55} gap="3rem" pauseOnHover>
            {logoRow.map((name) => (
              <LogoLockup key={name} name={name} className="text-sm" />
            ))}
          </Marquee>
        </Reveal>
      </div>
    </section>
  );
}
