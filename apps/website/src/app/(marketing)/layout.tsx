import { ScrollProgress } from "@/components/marketing/motion";
import { SiteFooter } from "@/components/marketing/site-footer";
import { SiteHeader } from "@/components/marketing/site-header";
import { SmoothScroll } from "@/components/marketing/smooth-scroll";
import { SoftwareApplicationJsonLd } from "@/components/marketing/structured-data";

export default function MarketingLayout({ children }: { children: React.ReactNode }) {
  return (
    <SmoothScroll>
      <ScrollProgress />
      <div className="flex min-h-screen flex-col">
        {/* Organization + WebSite are emitted once in the root layout.
            SoftwareApplication is marketing-specific, so it stays here. */}
        <SoftwareApplicationJsonLd />
        <SiteHeader />
        <main className="flex-1">{children}</main>
        <SiteFooter />
      </div>
    </SmoothScroll>
  );
}
