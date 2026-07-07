import { GrainOverlay } from "@/components/marketing/effects/grain-overlay";
import { ScrollProgress } from "@/components/marketing/motion";
import { SiteFooter } from "@/components/marketing/site-footer";
import { SiteHeader } from "@/components/marketing/site-header";
import { SoftwareApplicationJsonLd } from "@/components/marketing/structured-data";

export default function MarketingLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      {/* Global film-grain texture — fixed, non-interactive, over the whole page. */}
      <GrainOverlay />
      <ScrollProgress />
      <div className="flex min-h-screen flex-col">
        {/* Organization + WebSite are emitted once in the root layout.
            SoftwareApplication is marketing-specific, so it stays here. */}
        <SoftwareApplicationJsonLd />
        <SiteHeader />
        <main className="flex-1">{children}</main>
        <SiteFooter />
      </div>
    </>
  );
}
