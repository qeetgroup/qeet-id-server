import type { Metadata } from "next";
import { LegalPage, LegalSection } from "@/components/marketing/legal-page";

export const metadata: Metadata = {
  title: "Data Processing Agreement",
  description: "The terms under which Qeet ID processes personal data on your behalf.",
};

export default function DpaPage() {
  return (
    <LegalPage
      title="Data Processing Agreement"
      updated="2026-05-01"
      intro="This DPA forms part of the agreement between you (the controller) and Qeet ID (the processor) for the processing of personal data."
    >
      <LegalSection heading="1. Roles of the parties">
        <p>
          You act as the controller and Qeet ID acts as the processor of personal data processed on
          your behalf in connection with the Services. Where Qeet ID engages subprocessors, it does
          so as described in the Subprocessors page.
        </p>
      </LegalSection>
      <LegalSection heading="2. Scope and purpose of processing">
        <p>
          Qeet ID processes personal data only on documented instructions from you, including for
          authentication, authorization, session management, and audit logging as configured in your
          tenant.
        </p>
      </LegalSection>
      <LegalSection heading="3. Confidentiality">
        <p>
          Personnel authorized to process personal data are bound by appropriate confidentiality
          obligations.
        </p>
      </LegalSection>
      <LegalSection heading="4. Security measures">
        <p>
          Qeet ID maintains technical and organizational measures including encryption in transit
          and at rest, tenant isolation, least-privilege access, and continuous monitoring,
          consistent with its security documentation.
        </p>
      </LegalSection>
      <LegalSection heading="5. Subprocessors">
        <p>
          You authorize Qeet ID to engage the subprocessors listed on its Subprocessors page. Qeet
          ID will provide notice of additions and remains responsible for their performance.
        </p>
      </LegalSection>
      <LegalSection heading="6. Data subject requests and breach notification">
        <p>
          Qeet ID will assist you in responding to data subject requests and will notify you without
          undue delay after becoming aware of a personal data breach affecting your data.
        </p>
      </LegalSection>
      <LegalSection heading="7. Deletion and return">
        <p>
          On termination, Qeet ID will delete or return personal data in accordance with your
          instructions and applicable retention requirements.
        </p>
      </LegalSection>
    </LegalPage>
  );
}
