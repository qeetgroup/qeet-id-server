import { Marquee } from "@/components/marketing/effects/marquee";

const row1 = ["Acme", "Globex", "Initech", "Umbrella", "Hooli", "Pied Piper", "Stark", "Wayne"];
const row2 = [
  "Tyrell",
  "Massive Dynamic",
  "Aperture",
  "Bluebook",
  "Cyberdyne",
  "Soylent",
  "Vandelay",
  "InGen",
];

function LogoBadge({ name }: { name: string }) {
  return (
    <span className="font-display text-xl font-medium tracking-tight text-muted-foreground/60 transition-colors hover:text-foreground">
      {name}
    </span>
  );
}

export function LogoCloud() {
  return (
    <section className="border-b border-border/60 bg-muted/30">
      <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6 lg:px-8">
        <p className="text-center text-xs font-medium uppercase tracking-widest text-muted-foreground">
          Trusted by teams shipping to millions
        </p>

        <div className="relative mt-8 [mask-image:linear-gradient(to_right,transparent,black_15%,black_85%,transparent)]">
          <Marquee duration={50} gap="3rem">
            {row1.map((name) => (
              <LogoBadge key={name} name={name} />
            ))}
          </Marquee>
          <Marquee duration={60} reverse gap="3rem" className="mt-6">
            {row2.map((name) => (
              <LogoBadge key={name} name={name} />
            ))}
          </Marquee>
        </div>
      </div>
    </section>
  );
}
