/**
 * Schema.org JSON-LD blocks for Google rich-results + general search
 * engine surface area. Rendered as inline `<script type="application/
 * ld+json">` tags. We deliberately split each into its own component so
 * call sites can pick exactly which schemas apply to a given page.
 *
 * Spec: https://schema.org / https://developers.google.com/search/docs/appearance/structured-data
 */

const BASE = "https://qeetid.com";

interface JsonLdProps {
  data: Record<string, unknown>;
}

function JsonLd({ data }: JsonLdProps) {
  // Per Next.js JSON-LD guidance, escape `<` so an attacker can't break out
  // of the script tag via injected content. Cheaper than pulling in
  // serialize-javascript and sufficient because our payloads are static.
  const json = JSON.stringify(data).replace(/</g, "\\u003c");
  return (
    <script
      type="application/ld+json"
      // eslint-disable-next-line react/no-danger
      dangerouslySetInnerHTML={{ __html: json }}
    />
  );
}

/**
 * The Organization (publisher) block. Render once site-wide.
 */
export function OrganizationJsonLd() {
  return (
    <JsonLd
      data={{
        "@context": "https://schema.org",
        "@type": "Organization",
        "@id": `${BASE}/#organization`,
        name: "Qeet ID",
        url: BASE,
        logo: `${BASE}/icon.png`,
        sameAs: [
          "https://github.com/qeetid",
          "https://x.com/qeetid",
        ],
      }}
    />
  );
}

/**
 * The WebSite block with sitelinks-search-box action. Render once
 * site-wide (typically on the home page).
 */
export function WebSiteJsonLd() {
  return (
    <JsonLd
      data={{
        "@context": "https://schema.org",
        "@type": "WebSite",
        "@id": `${BASE}/#website`,
        url: BASE,
        name: "Qeet ID",
        publisher: { "@id": `${BASE}/#organization` },
        inLanguage: "en-US",
      }}
    />
  );
}

/**
 * Product block for the identity-platform offering. Helps Google show
 * the offer in product-search surfaces.
 */
export function ProductJsonLd() {
  return (
    <JsonLd
      data={{
        "@context": "https://schema.org",
        "@type": "Product",
        name: "Qeet ID",
        description:
          "Identity platform for modern teams. SSO, MFA, passkeys, RBAC, and session management — open source and self-hostable.",
        brand: { "@type": "Brand", name: "Qeet ID" },
        offers: [
          {
            "@type": "Offer",
            name: "Free",
            price: "0",
            priceCurrency: "USD",
            availability: "https://schema.org/InStock",
            url: `${BASE}/pricing`,
          },
          {
            "@type": "Offer",
            name: "Pro",
            price: "99",
            priceCurrency: "USD",
            priceSpecification: {
              "@type": "PriceSpecification",
              price: "99",
              priceCurrency: "USD",
              valueAddedTaxIncluded: false,
              description: "$99/month + $0.02/MAU",
            },
            availability: "https://schema.org/InStock",
            url: `${BASE}/pricing`,
          },
        ],
      }}
    />
  );
}

/**
 * SoftwareApplication block — useful for search results to label the
 * service as enterprise software vs. a generic page.
 */
export function SoftwareApplicationJsonLd() {
  return (
    <JsonLd
      data={{
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        name: "Qeet ID",
        applicationCategory: "DeveloperApplication",
        applicationSubCategory: "Identity & Access Management",
        operatingSystem: "Web, Linux, macOS, Windows",
        offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
        publisher: { "@id": `${BASE}/#organization` },
      }}
    />
  );
}

/**
 * BlogPosting/Article block for a single post. Ties the post back to the
 * site-wide Organization as publisher/author fallback so Google can attribute
 * it. Render on the post detail page.
 */
export function ArticleJsonLd({
  title,
  description,
  url,
  datePublished,
  author,
  image,
}: {
  title: string;
  description: string;
  /** Absolute or root-relative URL of the post. */
  url: string;
  /** ISO date string, e.g. "2026-05-20". */
  datePublished: string;
  author: string;
  /** Absolute or root-relative OG image URL. */
  image?: string;
}) {
  const abs = (u: string) => (u.startsWith("http") ? u : `${BASE}${u}`);
  return (
    <JsonLd
      data={{
        "@context": "https://schema.org",
        "@type": "BlogPosting",
        headline: title,
        description,
        url: abs(url),
        mainEntityOfPage: { "@type": "WebPage", "@id": abs(url) },
        datePublished,
        author: { "@type": "Person", name: author },
        publisher: { "@id": `${BASE}/#organization` },
        ...(image ? { image: abs(image) } : {}),
      }}
    />
  );
}

/**
 * FAQPage block — drives Google's FAQ rich result. Pass the same Q/A list the
 * visible FAQ accordion renders so the structured data always matches what's
 * on the page (Google requires the answer text to be present in the markup).
 */
export function FaqJsonLd({ items }: { items: { q: string; a: string }[] }) {
  return (
    <JsonLd
      data={{
        "@context": "https://schema.org",
        "@type": "FAQPage",
        mainEntity: items.map((item) => ({
          "@type": "Question",
          name: item.q,
          acceptedAnswer: {
            "@type": "Answer",
            text: item.a,
          },
        })),
      }}
    />
  );
}

/**
 * Breadcrumb helper for a route. Pass an ordered list of segments —
 * Schema.org expects 1-indexed positions.
 */
export function BreadcrumbJsonLd({ items }: { items: { name: string; url: string }[] }) {
  return (
    <JsonLd
      data={{
        "@context": "https://schema.org",
        "@type": "BreadcrumbList",
        itemListElement: items.map((item, i) => ({
          "@type": "ListItem",
          position: i + 1,
          name: item.name,
          item: item.url.startsWith("http") ? item.url : `${BASE}${item.url}`,
        })),
      }}
    />
  );
}
