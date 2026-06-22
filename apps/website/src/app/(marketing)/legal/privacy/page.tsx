import { LegalPage, LegalSection } from "@/components/marketing/legal-page";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description: "How Qeet ID collects, uses, and protects personal data.",
};

export default function PrivacyPage() {
  return (
    <LegalPage
      title="Privacy Policy"
      updated="2026-05-01"
      intro="This policy explains what personal data we process, why, and the rights you have over it."
    >
      <LegalSection heading="1. Data we process">
        <p>
          We process account data (name, email, organization), authentication metadata (sign-in
          events, device and IP information), and usage data needed to operate and secure the
          Services. We do not sell personal data.
        </p>
      </LegalSection>
      <LegalSection heading="2. How we use data">
        <p>
          We use personal data to provide and secure the Services, prevent abuse, comply with legal
          obligations, and communicate with you about your account.
        </p>
      </LegalSection>
      <LegalSection heading="3. Legal bases">
        <p>
          Where the GDPR applies, we rely on the performance of a contract, our legitimate interests
          in operating a secure service, your consent where required, and compliance with legal
          obligations.
        </p>
      </LegalSection>
      <LegalSection heading="4. Retention">
        <p>
          We retain personal data for as long as your account is active and as needed to provide the
          Services, then delete or anonymize it in line with our retention schedule, subject to legal
          requirements.
        </p>
      </LegalSection>
      <LegalSection heading="5. Your rights">
        <p>
          Depending on your jurisdiction, you may have rights to access, correct, delete, or port
          your personal data, and to object to or restrict certain processing. Submit requests to{" "}
          <a className="text-primary underline" href="mailto:privacy@qeetid.com">
            privacy@qeetid.com
          </a>
          .
        </p>
      </LegalSection>
      <LegalSection heading="6. International transfers">
        <p>
          Where data is transferred across borders, we rely on appropriate safeguards such as
          Standard Contractual Clauses. You can choose your data residency region at the tenant
          level.
        </p>
      </LegalSection>
      <LegalSection heading="7. Contact">
        <p>
          Our Data Protection Officer can be reached at{" "}
          <a className="text-primary underline" href="mailto:dpo@qeetid.com">
            dpo@qeetid.com
          </a>
          .
        </p>
      </LegalSection>
    </LegalPage>
  );
}
