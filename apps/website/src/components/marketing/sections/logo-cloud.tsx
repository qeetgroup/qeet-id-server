import { LogoLockup } from "@/components/marketing/blocks/logo-wall";
import { Marquee } from "@/components/marketing/effects/marquee";
import { Reveal } from "@/components/marketing/motion";

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

export function LogoCloud() {
  return (
    <section className="border-b border-border/60 bg-muted/30">
      <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6 lg:px-8">
        <Reveal>
          <p className="text-center text-xs font-medium uppercase tracking-widest text-muted-foreground">
            Trusted by teams shipping to millions
          </p>
        </Reveal>

        <Reveal
          delay={0.1}
          className="relative mt-8 [mask-image:linear-gradient(to_right,transparent,black_15%,black_85%,transparent)]"
        >
          <Marquee duration={50} gap="3rem" pauseOnHover>
            {row1.map((name) => (
              <LogoLockup key={name} name={name} />
            ))}
          </Marquee>
          <Marquee duration={60} reverse gap="3rem" className="mt-6" pauseOnHover>
            {row2.map((name) => (
              <LogoLockup key={name} name={name} />
            ))}
          </Marquee>
        </Reveal>
      </div>
    </section>
  );
}
