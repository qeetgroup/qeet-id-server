import { CTA } from "@/components/marketing/sections/cta";
import { Features } from "@/components/marketing/sections/features";
import { Hero } from "@/components/marketing/sections/hero";
import { HowItWorks } from "@/components/marketing/sections/how-it-works";
import { Integrations } from "@/components/marketing/sections/integrations";
import { LogoCloud } from "@/components/marketing/sections/logo-cloud";
import { Stats } from "@/components/marketing/sections/stats";
import { Testimonials } from "@/components/marketing/sections/testimonials";
import { ProductJsonLd, WebSiteJsonLd } from "@/components/marketing/structured-data";

export default function HomePage() {
  return (
    <>
      <WebSiteJsonLd />
      <ProductJsonLd />
      <Hero />
      <LogoCloud />
      <Features />
      <HowItWorks />
      <Stats />
      <Integrations />
      <Testimonials />
      <CTA />
    </>
  );
}
