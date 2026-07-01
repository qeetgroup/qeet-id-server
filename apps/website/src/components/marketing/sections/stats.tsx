import { NumberTicker } from "@/components/marketing/effects/number-ticker";
import { Threads } from "@/components/marketing/effects/threads";
import { Reveal, Stagger, StaggerItem, WordReveal } from "@/components/marketing/motion";

const stats = [
  { label: "Uptime SLA", value: 99.99, decimals: 2, suffix: "%" },
  { label: "p99 auth latency", value: 48, suffix: "ms", prefix: "<" },
  { label: "Edge regions", value: 32, suffix: "+" },
  { label: "Auths per month", value: 2.4, decimals: 1, suffix: "B" },
];

export function Stats() {
  return (
    <section className="relative overflow-hidden border-b border-border/60 bg-foreground text-background">
      <Threads color="rgba(242,109,14,0.09)" />

      <div className="relative mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-24">
        <Reveal className="mx-auto max-w-2xl text-center">
          <p className="text-xs font-medium uppercase tracking-widest text-background/60">
            By the numbers
          </p>
          <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            Engineered for scale,{" "}
            <WordReveal
              text="proven in production"
              wordClassName="text-gradient-brand"
              initialDelay={0.3}
            />
          </h2>
        </Reveal>

        <Stagger
          staggerDelay={0.1}
          className="mt-14 grid grid-cols-2 gap-px overflow-hidden rounded-2xl bg-background/10 sm:grid-cols-4"
        >
          {stats.map((s) => (
            <StaggerItem key={s.label}>
              <div className="group relative flex h-full flex-col items-start gap-2 overflow-hidden bg-foreground p-6 transition-colors sm:p-8">
                <span
                  aria-hidden
                  className="pointer-events-none absolute inset-x-0 bottom-0 h-0.5 origin-left scale-x-0 bg-(image:--brand-gradient) transition-transform duration-500 group-hover:scale-x-100"
                />
                <dt className="text-xs font-medium uppercase tracking-widest text-background/60">
                  {s.label}
                </dt>
                <dd className="font-display text-4xl font-semibold tracking-tight sm:text-5xl">
                  <NumberTicker
                    value={s.value}
                    decimals={s.decimals ?? 0}
                    prefix={s.prefix}
                    suffix={s.suffix}
                  />
                </dd>
              </div>
            </StaggerItem>
          ))}
        </Stagger>
      </div>
    </section>
  );
}
