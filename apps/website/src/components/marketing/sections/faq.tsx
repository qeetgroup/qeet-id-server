import { FaqAccordion, type FaqItem } from "@/components/marketing/faq-accordion";
import { Section, SectionHeader } from "@/components/marketing/section";
import { FaqJsonLd } from "@/components/marketing/structured-data";

const faq: FaqItem[] = [
  {
    q: "What is Qeet ID?",
    a: "A complete authentication and identity platform — SSO, MFA, passkeys, RBAC, and stateful sessions backed by a single, audit-ready identity graph. It's an open-source-core alternative to Auth0, Clerk, and WorkOS that you can self-host or run fully managed.",
  },
  {
    q: "How long does it take to integrate?",
    a: "Most teams ship a working sign-in flow in a day. We provide first-party SDKs for JavaScript, React, and Next.js (plus Go and Python), drop-in hosted pages, and a 100%-route-covered OpenAPI spec.",
  },
  {
    q: "Can I migrate from Auth0, Clerk, or another provider?",
    a: "Yes. We support bulk user import (including bcrypt/argon2/scrypt password hashes so users never need to reset), and lazy migration that verifies and re-hashes credentials on first login. Our team helps plan zero-downtime cutovers on Pro and Enterprise.",
  },
  {
    q: "Is passkey and enterprise SSO support built in?",
    a: "Both. Passkeys (FIDO2 / WebAuthn) are first-class, and Qeet ID acts as both an OIDC and a SAML IdP with SCIM user + group provisioning — with no per-connection “SSO tax.”",
  },
  {
    q: "Can I self-host, and where does my data live?",
    a: "The core is open-source and self-hostable down to air-gapped deployments on Enterprise. Managed hosting is available in the US, EU, and APAC, with custom data residency on Enterprise contracts.",
  },
  {
    q: "How are you priced?",
    a: "A real free tier up to 5,000 monthly active users, then linear per-MAU pricing with no surprise tier jumps. Enterprise is a custom annual contract. See the pricing page for the full breakdown and a calculator.",
  },
];

export function Faq() {
  return (
    <Section innerClassName="mx-auto max-w-3xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28" id="faq">
      {/* FAQPage rich-result data — mirrors the visible accordion below. */}
      <FaqJsonLd items={faq} />
      <SectionHeader align="left" eyebrow="FAQ" title="Questions," titleAccent="answered" />
      <FaqAccordion items={faq} />
    </Section>
  );
}
