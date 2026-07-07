import {
  Cloudflare,
  Datadog,
  Figma,
  Google,
  Linear,
  Loom,
  Microsoft,
  Netlify,
  Spotify,
  Sentry,
  Shopify,
  Slack,
  Stripe,
  Supabase,
  Zapier,
  Discord,
} from "@thesvg/react";

import { LogoLockup } from "@/components/marketing/blocks/logo-wall";
import { Marquee } from "@/components/marketing/effects/marquee";
import { Reveal } from "@/components/marketing/motion";

const row1 = [
  { name: "Google", icon: Google },
  { name: "Stripe", icon: Stripe },
  { name: "Linear", icon: Linear },
  { name: "Microsoft", icon: Microsoft },
  { name: "Slack", icon: Slack },
  { name: "Loom", icon: Loom },
  { name: "Datadog", icon: Datadog },
  { name: "Zapier", icon: Zapier },
];
const row2 = [
  { name: "Shopify", icon: Shopify },
  { name: "Figma", icon: Figma },
  { name: "Netlify", icon: Netlify },
  { name: "Supabase", icon: Supabase },
  { name: "Cloudflare", icon: Cloudflare },
  { name: "Sentry", icon: Sentry },
  { name: "Discord", icon: Discord },
  { name: "Spotify", icon: Spotify },
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
          className="relative mt-8 mask-[linear-gradient(to_right,transparent,black_15%,black_85%,transparent)]"
        >
          <Marquee duration={50} gap="3rem" pauseOnHover>
            {row1.map((brand) => (
              <LogoLockup key={brand.name} name={brand.name} icon={brand.icon} />
            ))}
          </Marquee>
          <Marquee duration={60} reverse gap="3rem" className="mt-6" pauseOnHover>
            {row2.map((brand) => (
              <LogoLockup key={brand.name} name={brand.name} icon={brand.icon} />
            ))}
          </Marquee>
        </Reveal>
      </div>
    </section>
  );
}
