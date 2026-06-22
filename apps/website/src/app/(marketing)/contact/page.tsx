import { BuildingIcon, ClockIcon, LifeBuoyIcon, MailIcon, NewspaperIcon } from "lucide-react";
import type { Metadata } from "next";

import { ContactForm } from "@/components/marketing/contact-form";
import { Reveal, Stagger, StaggerItem } from "@/components/marketing/motion";
import { PageHero } from "@/components/marketing/page-hero";

export const metadata: Metadata = {
  title: "Contact",
  description:
    "Talk to Qeet ID sales, support, or press — or send a message and we'll route it. We reply within one business day.",
};

const channels = [
  {
    icon: BuildingIcon,
    title: "Talk to sales",
    body: "Pricing, enterprise contracts, self-hosted deployments, and security reviews.",
    cta: "sales@qeet.id",
    href: "mailto:sales@qeet.id",
  },
  {
    icon: LifeBuoyIcon,
    title: "Support",
    body: "Already building on Qeet ID? We'll respond within your plan's SLA.",
    cta: "support@qeet.id",
    href: "mailto:support@qeet.id",
  },
  {
    icon: NewspaperIcon,
    title: "Press & media",
    body: "Story pitches, exec interviews, and brand assets.",
    cta: "press@qeet.id",
    href: "mailto:press@qeet.id",
  },
  {
    icon: MailIcon,
    title: "General",
    body: "Anything else — we read every message.",
    cta: "hello@qeet.id",
    href: "mailto:hello@qeet.id",
  },
];

export default function ContactPage() {
  return (
    <>
      <PageHero
        eyebrow="Contact"
        title="Let's talk about"
        titleAccent="your identity layer"
        subtitle="Whether you're evaluating Qeet ID, mid-migration, or just have a question — pick the channel that fits, or send the form and we'll route it for you."
      />

      <section className="border-b border-border/60 bg-muted/30">
        <div className="mx-auto grid max-w-7xl gap-12 px-4 py-16 sm:px-6 lg:grid-cols-[1fr_1.4fr] lg:px-8 lg:py-24">
          {/* Channels + context */}
          <div className="flex flex-col gap-6">
            <Reveal>
              <div className="flex items-start gap-3 rounded-2xl border border-border/60 bg-background p-5">
                <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-brand/10 text-brand">
                  <ClockIcon className="size-5" aria-hidden />
                </span>
                <div className="flex flex-col gap-1">
                  <h2 className="font-medium">Response time</h2>
                  <p className="text-sm text-muted-foreground">
                    We reply to every message within one business day. Sales enquiries usually hear
                    back same-day; support follows your plan&apos;s SLA.
                  </p>
                </div>
              </div>
            </Reveal>

            <Stagger staggerDelay={0.06} className="grid gap-4 sm:grid-cols-2 lg:grid-cols-1">
              {channels.map(({ icon: Icon, title, body, cta, href }) => (
                <StaggerItem key={title} className="h-full">
                  <a
                    href={href}
                    className="flex h-full flex-col gap-2 rounded-2xl border border-border/60 bg-background p-5 transition-colors hover:border-brand/50 focus-ring-brand"
                  >
                    <span className="grid size-9 place-items-center rounded-lg bg-brand/10 text-brand">
                      <Icon className="size-5" aria-hidden />
                    </span>
                    <h3 className="mt-1 font-medium">{title}</h3>
                    <p className="text-sm text-muted-foreground">{body}</p>
                    <span className="mt-auto pt-1 text-sm font-medium text-brand-text">{cta}</span>
                  </a>
                </StaggerItem>
              ))}
            </Stagger>
          </div>

          {/* Form */}
          <Reveal delay={0.05}>
            <ContactForm />
          </Reveal>
        </div>
      </section>
    </>
  );
}
