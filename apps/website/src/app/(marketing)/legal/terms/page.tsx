import type { Metadata } from "next";
import { LegalPage, LegalSection } from "@/components/marketing/legal-page";

export const metadata: Metadata = {
  title: "Terms of Service",
  description: "The terms governing your use of Qeet ID.",
};

export default function TermsPage() {
  return (
    <LegalPage
      title="Terms of Service"
      updated="2026-05-01"
      intro="These terms govern your access to and use of Qeet ID's services. By using the services, you agree to be bound by them."
    >
      <LegalSection heading="1. Agreement to terms">
        <p>
          By accessing or using Qeet ID (the &ldquo;Services&rdquo;), you agree to be bound by these
          Terms of Service and all policies referenced herein. If you are using the Services on
          behalf of an organization, you represent that you have authority to bind that
          organization.
        </p>
      </LegalSection>
      <LegalSection heading="2. Accounts and access">
        <p>
          You are responsible for safeguarding the credentials used to access your account and for
          all activity that occurs under it. You must promptly notify us of any unauthorized use.
        </p>
      </LegalSection>
      <LegalSection heading="3. Acceptable use">
        <p>
          You agree not to misuse the Services, including by interfering with their normal
          operation, attempting to access them using a method other than the interfaces and
          instructions we provide, or using them to violate any applicable law.
        </p>
      </LegalSection>
      <LegalSection heading="4. Fees and payment">
        <p>
          Paid plans are billed in advance on a recurring basis. Fees are non-refundable except as
          required by law or expressly stated in your order form.
        </p>
      </LegalSection>
      <LegalSection heading="5. Termination">
        <p>
          You may stop using the Services at any time. We may suspend or terminate access for breach
          of these terms, with notice where practicable.
        </p>
      </LegalSection>
      <LegalSection heading="6. Disclaimers and limitation of liability">
        <p>
          The Services are provided &ldquo;as is.&rdquo; To the maximum extent permitted by law, our
          aggregate liability arising out of or relating to these terms is limited to the amounts
          paid by you in the twelve months preceding the claim.
        </p>
      </LegalSection>
      <LegalSection heading="7. Contact">
        <p>
          Questions about these terms? Email{" "}
          <a className="text-primary underline" href="mailto:legal@qeet.in">
            legal@qeet.in
          </a>
          .
        </p>
      </LegalSection>
    </LegalPage>
  );
}
