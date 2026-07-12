import { SIGN_UP_URL } from "@/lib/links";

/**
 * Shared pricing tiers — the single source of truth for both the full
 * `/pricing` page and the condensed homepage Pricing section.
 */
export type PricingTier = {
  name: string;
  description: string;
  price: string;
  period: string;
  cta: { label: string; href: string };
  featured?: boolean;
  features: string[];
};

export const tiers: PricingTier[] = [
  {
    name: "Free",
    description: "For developers and side projects.",
    price: "$0",
    period: "forever",
    cta: { label: "Start free", href: SIGN_UP_URL },
    features: [
      "Up to 5,000 monthly active users",
      "Unlimited social providers",
      "Passkeys + TOTP MFA",
      "RBAC with up to 5 roles",
      "Community support",
      "Hosted EU or US",
    ],
  },
  {
    name: "Pro",
    description: "For teams shipping to real customers.",
    price: "$99",
    period: "/ month + $0.02 / MAU",
    cta: { label: "Start 14-day trial", href: `${SIGN_UP_URL}?plan=pro` },
    featured: true,
    features: [
      "Up to 50,000 MAU included",
      "All providers + magic link",
      "Unlimited RBAC + ABAC policies",
      "Audit log export (7-day retention)",
      "Email + chat support, 24h SLA",
      "99.95% uptime SLA",
    ],
  },
  {
    name: "Enterprise",
    description: "For regulated industries and scale.",
    price: "Custom",
    period: "annual contract",
    cta: { label: "Talk to sales", href: "/contact" },
    features: [
      "Unlimited MAU and tenants",
      "SAML, OIDC, SCIM, LDAP",
      "Dedicated single-tenant deploy option",
      "Audit log retention to your S3 / SIEM",
      "Named CSM + 24/7 phone support",
      "99.99% uptime SLA, custom DPAs",
      "SOC 2 Type II, ISO 27001, HIPAA BAA",
    ],
  },
];
