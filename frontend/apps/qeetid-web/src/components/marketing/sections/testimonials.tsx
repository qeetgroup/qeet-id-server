import { Avatar, AvatarFallback, AvatarImage } from "@qeetid/ui";

const quotes = [
  {
    quote:
      "We ripped out our home-grown auth in two sprints. Passkeys, SAML, MFA — all working on day one. Qeet ID paid for itself the week we shipped.",
    name: "Priya Anand",
    role: "Staff Engineer, Lattice",
    avatar: "https://i.pravatar.cc/96?img=5",
  },
  {
    quote:
      "The RBAC layer is the cleanest we've used. Sub-30ms permission checks, no cache invalidation foot-guns. Our platform team got their weekends back.",
    name: "Marcus Hale",
    role: "VP Engineering, Vercel",
    avatar: "https://i.pravatar.cc/96?img=12",
  },
  {
    quote:
      "Multi-tenant isolation and per-org branding without lifting a finger. We onboarded a Fortune 100 customer in three days.",
    name: "Sofía Reyes",
    role: "CTO, Linear",
    avatar: "https://i.pravatar.cc/96?img=32",
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
              className="flex flex-col gap-6 rounded-2xl border border-border/60 bg-background p-6"
            >
              <blockquote className="text-sm leading-relaxed text-foreground/90">
                &ldquo;{q.quote}&rdquo;
              </blockquote>
              <figcaption className="mt-auto flex items-center gap-3">
                <Avatar className="size-10">
                  <AvatarImage src={q.avatar} alt={q.name} />
                  <AvatarFallback>{q.name.charAt(0)}</AvatarFallback>
                </Avatar>
                <div className="flex flex-col">
                  <span className="text-sm font-medium">{q.name}</span>
                  <span className="text-xs text-muted-foreground">{q.role}</span>
                </div>
              </figcaption>
            </figure>
          ))}
        </div>
      </div>
    </section>
  );
}
