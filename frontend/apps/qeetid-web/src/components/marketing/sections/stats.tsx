import { NumberTicker } from "@/components/marketing/effects/number-ticker";

const stats = [
  { label: "Uptime SLA", value: 99.99, decimals: 2, suffix: "%" },
  { label: "p99 auth latency", value: 48, suffix: "ms", prefix: "<" },
  { label: "Edge regions", value: 32, suffix: "+" },
  { label: "Auths per month", value: 2.4, decimals: 1, suffix: "B" },
];

export function Stats() {
  return (
    <section className="relative overflow-hidden border-b border-border/60 bg-foreground text-background">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-30 [background-image:linear-gradient(var(--color-background)/0.1_1px,transparent_1px),linear-gradient(90deg,var(--color-background)/0.1_1px,transparent_1px)] [background-size:60px_60px] [mask-image:radial-gradient(ellipse_at_center,black,transparent_70%)]"
      />
      <div className="relative mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-24">
        <div className="mx-auto max-w-2xl text-center">
          <p className="text-xs font-medium uppercase tracking-widest text-background/60">
            By the numbers
          </p>
          <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            Engineered for scale,{" "}
            <span className="bg-[linear-gradient(110deg,#22d3ee,#7c5cff,#fb7185)] bg-clip-text text-transparent">
              proven in production
            </span>
          </h2>
        </div>

        <dl className="mt-14 grid grid-cols-2 gap-px overflow-hidden rounded-2xl bg-background/10 sm:grid-cols-4">
          {stats.map((s) => (
            <div key={s.label} className="flex flex-col items-start gap-2 bg-foreground p-6 sm:p-8">
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
          ))}
        </dl>
      </div>
    </section>
  );
}
