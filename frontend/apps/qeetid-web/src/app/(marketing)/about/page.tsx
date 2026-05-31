import { InitialsAvatar } from "@/components/marketing/blocks/initials-avatar";
import { CTA } from "@/components/marketing/sections/cta";
import { CompassIcon, HeartHandshakeIcon, ShieldCheckIcon, ZapIcon } from "lucide-react";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "About",
  description:
    "Qeet ID is on a mission to make secure identity the default for every product team. Meet the people building it.",
};

const values = [
  {
    icon: ShieldCheckIcon,
    title: "Security is the product",
    body: "Not a feature, not a checkbox. Every decision starts from the threat model and works outward.",
  },
  {
    icon: ZapIcon,
    title: "Developer-first",
    body: "If it isn't a joy to integrate, we haven't shipped it. SDKs, docs, and local dev are first-class.",
  },
  {
    icon: HeartHandshakeIcon,
    title: "Earn trust daily",
    body: "We publish our status, our subprocessors, and our incidents. Trust is renewed, never assumed.",
  },
  {
    icon: CompassIcon,
    title: "Opinionated, not rigid",
    body: "A small set of strong defaults you can override — never a maze of knobs you must configure.",
  },
];

const team = [
  { name: "Sai Mareedu", role: "Founder & CEO" },
  { name: "Priya Anand", role: "Head of Engineering" },
  { name: "Marcus Hale", role: "Security Lead" },
  { name: "Sofía Reyes", role: "Head of Product" },
  { name: "Dev Patel", role: "Developer Experience" },
  { name: "Jun Park", role: "Infrastructure" },
];

const stats = [
  { value: "2024", label: "Founded" },
  { value: "100%", label: "Remote" },
  { value: "9", label: "Time zones" },
  { value: "4,000+", label: "Teams onboarded" },
];

export default function AboutPage() {
  return (
    <>
      <section className="border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <div className="mx-auto max-w-3xl text-center">
            <p className="text-sm font-medium uppercase tracking-widest text-primary">About</p>
            <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
              Identity should be the easy part
            </h1>
            <p className="mt-5 text-muted-foreground text-balance sm:text-lg">
              We started Qeet ID because every team rebuilds the same auth stack, ships the same
              bugs, and inherits the same audit pain. We think that work should be done once, done
              well, and shared.
            </p>
          </div>
        </div>
      </section>

      <section className="border-b border-border/60 bg-muted/30">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <div className="grid gap-12 lg:grid-cols-[1fr_1.2fr]">
            <div className="flex flex-col gap-4">
              <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
                Our story
              </h2>
            </div>
            <div className="flex flex-col gap-5 text-muted-foreground leading-relaxed">
              <p>
                After years of maintaining bespoke session stores, SSO bridges, and MFA flows at
                companies large and small, the founding team kept hitting the same wall: auth is
                deceptively hard, security-critical, and never the thing customers pay you for.
              </p>
              <p>
                Qeet ID is the platform we wished we&apos;d had — passkeys-first, multi-tenant from
                day one, and audit-ready by default. We build in the open, publish our compliance
                posture, and treat every credential like it&apos;s our own.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            What we value
          </h2>
          <div className="mt-12 grid gap-6 sm:grid-cols-2">
            {values.map(({ icon: Icon, title, body }) => (
              <div
                key={title}
                className="flex flex-col gap-3 rounded-2xl border border-border/60 bg-card p-6"
              >
                <span className="grid size-10 place-items-center rounded-lg bg-primary/10 text-primary">
                  <Icon className="size-5" />
                </span>
                <h3 className="font-display text-lg font-semibold tracking-tight">{title}</h3>
                <p className="text-sm text-muted-foreground">{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="border-b border-border/60 bg-muted/30">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            The team
          </h2>
          <dl className="mt-10 grid grid-cols-2 gap-px overflow-hidden rounded-2xl bg-border/60 sm:grid-cols-4">
            {stats.map((s) => (
              <div key={s.label} className="flex flex-col gap-1 bg-background p-6">
                <dd className="font-display text-3xl font-semibold tracking-tight">{s.value}</dd>
                <dt className="text-xs text-muted-foreground">{s.label}</dt>
              </div>
            ))}
          </dl>
          <ul className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {team.map((m) => (
              <li
                key={m.name}
                className="flex items-center gap-3 rounded-2xl border border-border/60 bg-background p-5"
              >
                <InitialsAvatar name={m.name} size="lg" />
                <div className="flex flex-col">
                  <span className="font-medium">{m.name}</span>
                  <span className="text-sm text-muted-foreground">{m.role}</span>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <CTA />
    </>
  );
}
