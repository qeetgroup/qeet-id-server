# Qeet ID — Usability Testing Plan & Findings Framework

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Usability Testing Plan & Findings Framework |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer + Product Manager |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines how Qeet ID validates its designs through usability testing — across Phase 3 (design), Phase 4 (development), Phase 8 (beta launch), and post-launch. It specifies the testing philosophy, the scope per phase, the participant recruitment strategy per persona, the testing method mix, the specific scenarios each persona will be tested on, the success metrics, the findings documentation template, the severity classification, the iteration cadence, the testing tools stack, the privacy & consent standards, and the findings distribution.

The audience is the UX Designer, Product Manager, UX Research / QA Lead, Developer Relations Lead (for participant recruitment), Customer Success Lead, and every stakeholder who consumes findings.

This document depends on every Phase 3 document so far (the artefacts to be tested) and on Phase 1 [Persona Documents](../phase-1/Qeet%20ID%20%E2%80%94%20Persona%20Documents%20%26%20Customer%20Journey%20Map.md) (the participant criteria) and [Business Goals & KPI Framework §5.5](../phase-1/Qeet%20ID%20%E2%80%94%20Business%20Goals%20%26%20KPI%20Framework.md) (the success metrics we test against).

---

### 3. Testing Philosophy

**TP-01 — Test Early.** The first usability test happens in Phase 3 Week 4–5 against design system + key flows — *before* Phase 4 development locks in implementation choices. Late testing finds issues that cannot be cheaply fixed.

**TP-02 — Test with Real Personas, Not Internal Proxies.** Internal "playtesting" by Qeet ID staff is the lowest-fidelity signal. Real Arjun-class developers test like Arjuns; Qeet ID engineers do not. Recruit external participants matching each persona.

**TP-03 — Test the Critical Journeys.** Not every screen, not every flow. The critical journeys — under-5-min TTFA for Arjun, SAML config for Sandra, audit log search for Daniel, Trust Center evaluation for Omar — are tested every cycle. Edge screens are tested sparingly.

**TP-04 — Iterate Fast.** Findings from a usability test should flow into Figma updates within one week and into Phase 4 backlog within two. Slow iteration kills the value of testing.

**TP-05 — Quantitative + Qualitative.** Task completion rate and time on task are necessary; without them, "the test went well" is the most defensive lie in UX. Qualitative themes are equally necessary; without them, the numbers describe failure without explaining it.

**TP-06 — Test Across Devices and Assistive Technologies.** Mobile (Persona end users), desktop (Sandra, Daniel, Arjun), and assistive tech (one participant per round; per [Doc 9 §16.3](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md)).

**TP-07 — Findings Are Not Recommendations.** A finding is "User X took 90 seconds and gave up before completing Task Y." The recommendation is what the UX designer + Product Manager do about it. Don't conflate them in findings docs.

---

### 4. Testing Scope per Phase

### 4.1 Phase 3 (Design) — Weeks 4–5

**Scope:** Prototype testing of:
- The Quickstart page (Arjun).
- The login flow with passkey conditional UI (end-user simulating Sandra's workforce).
- The SAML setup wizard (Sandra and Daniel).
- The audit log viewer (Sandra).
- The Security Trust Center (Omar).
- The pricing page + calculator (Maya).

**Method:** Figma prototype testing. Moderated remote sessions.

**Participants:** 5 per critical journey, recruited per §5.

**Output:** Findings document feeding back into Phase 3 design iteration (Figma + the relevant Doc).

### 4.2 Phase 4 (Development) — Mid-Phase

**Scope:** Beta SDK developer testing of:
- The SDK installation + first auth flow (Arjun).
- The dashboard for first-time tenant configuration (Maya).
- Migration flow from Firebase Auth (Daniel).

**Method:** Long-form moderated sessions (60–90 min) with developers using working SDKs against a staging Qeet ID environment.

**Participants:** 5 developers from various backgrounds.

**Output:** Findings document feeding back into Phase 4 backlog + Documentation revisions.

### 4.3 Phase 8 (Beta Launch) — Continuous

**Scope:** Real-world testing with the 5+ enterprise pilot customers + a developer beta cohort (Charter §14: enterprise pilots; KPI 5.2 developer signups).

**Method:**
- Weekly check-ins with each enterprise pilot.
- In-product feedback widgets (per [Doc 7 §21](Qeet ID%20%E2%80%94%20Developer%20Portal%20Design%20Specification.md)).
- NPS survey at +30 days and +90 days post-signup.
- Optional follow-up interviews (15 / week target).

**Output:** Beta findings register, fed into the v1.0 → v1.1 roadmap.

### 4.4 Post-Launch — Continuous

**Scope:** Production usability monitoring:
- Funnel analytics (per [Doc 1 §9](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) success metrics — DSM-01..DSM-10).
- In-product feedback widgets (per-page).
- NPS surveys quarterly.
- Quarterly persona-touchpoint usability tests (one per persona per quarter).

**Output:** Quarterly UX-health report to Engineering, Product, and CTO.

---

### 5. Participant Recruitment Strategy per Persona

The recruitment funnel for each persona, with channels, criteria, and incentive levels.

### 5.1 Arjun — Solo Developer

**Target: 5 participants per round.**

| Channel | Notes |
| --- | --- |
| Dev.to and Hacker News (paid promoted "developer feedback wanted" posts) | Reach genuine indie developers |
| Twitter / X DM outreach to developers tweeting about Auth0, Firebase Auth, or Cognito | Targeted recruitment |
| GitHub: contributors to OSS auth projects | Verified technical depth |
| Discord communities (Reactiflux, Next.js Discord) | Stack-relevant |

**Criteria:** Currently building or shipped a side project; uses React or Next.js or Node.js or Python; has integrated at least one auth provider (Firebase, Auth0, Clerk, Supabase) OR has built auth from scratch.

**Incentive:** $100 per 60-minute moderated session.

### 5.2 Maya — Startup CTO

**Target: 3 participants per round.**

| Channel | Notes |
| --- | --- |
| Y Combinator alumni Slack | Quality recruitment pool |
| Indie Hackers community | B2B SaaS founders |
| LinkedIn direct outreach to CTOs of 10–50-person B2B startups | Direct match |
| Existing Qeet ID investor / advisor network | Warm intro path |

**Criteria:** CTO or technical co-founder of a 5–100-employee B2B SaaS; has shipped multi-tenant features; has evaluated auth platforms in the last 12 months.

**Incentive:** $300 per 60-minute moderated session (her time is more expensive than Arjun's; the rate reflects this).

### 5.3 Daniel — Mid-Market Engineering Lead

**Target: 3 participants per round.**

| Channel | Notes |
| --- | --- |
| LinkedIn direct outreach to Engineering Managers/Directors at 100–500-employee SaaS companies | Direct match |
| Conference speakers / attendees (AWS re:Invent, Next.js Conf, KubeCon) | Self-selected technical depth |
| Customer advisory boards of complementary tools (Vercel, Supabase, Stripe) | Adjacent audience |

**Criteria:** Engineering Lead at a mid-market company; has overseen at least one auth migration OR is currently evaluating one; uses AWS or GCP; has at least one enterprise customer asking for SAML / SCIM.

**Incentive:** $300 per session + a Qeet ID swag pack.

### 5.4 Sandra — Enterprise IT Admin

**Target: 2 participants per round.**

| Channel | Notes |
| --- | --- |
| Qeet Group enterprise pilot network | Existing relationships |
| Microsoft Entra-administrator communities | Stack-relevant |
| Reddit r/sysadmin | Self-selecting |
| LinkedIn direct outreach to "IT Admin" / "Identity Engineer" at Fortune 1000 companies | Direct match |

**Criteria:** IT admin at a 500+ employee enterprise; administers SAML and SCIM today; uses Microsoft Entra ID or Okta or Ping; has ≥3 years experience.

**Incentive:** $400 per session + (when feasible) co-design recognition in the product.

### 5.5 Omar — Enterprise CISO

**Target: 1 participant per round (CISOs are hardest to recruit).**

| Channel | Notes |
| --- | --- |
| Qeet Group security advisory contacts | Warm intro path |
| ISACA / (ISC)² communities | Professional networks |
| CISO Forum / Evanta peer groups | Network |

**Criteria:** CISO or Head of Security at a 500+ employee enterprise; has approved or rejected at least one identity-platform vendor in the last 24 months.

**Incentive:** $500 per 45-minute session + a contribution to a security non-profit on their behalf (CISOs often decline direct fees).

### 5.6 Assistive Technology User

**Target: 1 participant per round.**

Per [Doc 9 §16.3](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md): at least one participant per testing round is an assistive-technology user.

| Channel | Notes |
| --- | --- |
| Fable (paid panel of assistive-tech users) | Recommended; specialised |
| AccessWorks | Alternative |

**Incentive:** Standard panel rate (set by the panel provider; typically $100–$200 per session).

---

### 6. Testing Method Mix

### 6.1 Methods

| Method | When used | Length | Sample size | Output |
| --- | --- | --- | --- | --- |
| Moderated remote testing | All phases for primary personas | 60 min (45 for CISO) | 5 per critical journey | Recordings + findings doc |
| Unmoderated remote testing (Maze or UserTesting) | High-volume validation of design choices (e.g., copy A/B) | 15 min | 50–100 | Aggregate metrics |
| In-product feedback widgets | Post-beta | n/a | Continuous | Anonymised feedback stream |
| NPS surveys | Quarterly post-launch | n/a | All paying customers | NPS score + verbatims |
| Eye-tracking (limited use) | Reserved for visual scan / hierarchy validation on key marketing surfaces | 30 min | 5 | Heatmaps |
| Diary studies | Reserved for migration journey (Daniel) | 4 weeks | 3 | Day-by-day journal entries |

### 6.2 Moderated Remote Testing Protocol

- Conducted via Google Meet or Zoom.
- Recorded with explicit consent.
- Screen + voice + (optionally) face.
- 60-minute structure:
  - 5 min: introduction, consent, warm-up.
  - 45 min: scenarios (typically 2–3 per session).
  - 10 min: SUS questionnaire + open-ended debrief.
- Moderator script provided; the moderator's job is to **facilitate, not lead**. ("Talk me through what you're trying to do" beats "Click this button.")

### 6.3 Unmoderated Testing

- Used for high-volume validation (we want to know "is this label clear" with 50 participants, not 5).
- Tasks scripted; participants record screen and voice asynchronously.
- Aggregate metrics: completion rate, time on task, error count, satisfaction (5-point Likert).
- Verbatims sampled and reviewed.

### 6.4 In-Product Feedback Widgets

- Per [Doc 7 §21](Qeet ID%20%E2%80%94%20Developer%20Portal%20Design%20Specification.md): thumbs up/down on every doc page.
- Per [Doc 6 §6.4](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md): a small feedback affordance on the dashboard overview ("Tell us what's working").
- Anonymised. Submitted feedback flows into a Linear board reviewed weekly by UX + Tech Writing + Product.

---

### 7. Test Scenarios per Persona

Verbatim task prompts for moderated sessions. The "talk me through what you're doing" instruction is consistent across all.

### 7.1 Arjun

**Scenario A: First Integration**
> "You're a developer building a side project in Next.js. You want to add Google login. Go to qeetify.com and complete the integration. Talk through what you're doing and how you feel."

Success metrics:
- Time to first auth completed ≤10 min (target 5 min)
- Self-reported satisfaction ≥4/5
- Did the participant find the right code snippet without help?
- Did they hit any blockers requiring moderator intervention?

**Scenario B: SDK Switching**
> "Now you're integrating the same auth into your Python backend. Find how to do it."

Success metrics:
- Time to find the Python SDK ≤30 s
- Time to integrate ≤5 min
- Did they find Python via the Code Tab Group, the SDK reference, or search?

### 7.2 Maya

**Scenario A: B2B Multi-Tenancy Evaluation**
> "You're a CTO evaluating Qeet ID for a B2B SaaS product. Your customers each have their own organisation. Walk through the docs and find out whether Qeet ID's multi-tenancy and RBAC support your use case."

Success metrics:
- Time to locate multi-tenancy concept doc ≤2 min
- Time to confirm RBAC support ≤3 min
- Did she find an architecture diagram? Did she find the pricing calculator?
- Confidence-to-commit score ≥4/5

**Scenario B: Dashboard Setup**
> "You've signed up for a trial. Set up your first tenant, invite a teammate, and create your first application."

Success metrics:
- Total time ≤10 min
- All three tasks completed without external help

### 7.3 Daniel

**Scenario A: Firebase Auth Migration Planning**
> "Your company is on Firebase Auth with 200,000 users. You need to migrate. Find the migration guide on qeetify.com and walk through how you would plan this migration. Identify the top 3 risks."

Success metrics:
- Time to locate Firebase migration guide ≤90 s
- Did he find the migration tool? Did he find the phased-rollout dashboard concept?
- Listed risks should include: user import correctness, phased rollout strategy, fallback plan, downtime tolerance.

**Scenario B: SAML Configuration**
> "Set up a SAML SSO connection between Microsoft Entra ID and Qeet ID, using the sample metadata I'll send you."

Success metrics:
- Time to completion ≤10 min (with provided metadata)
- Did the SAML wizard's live validation help or confuse?
- Did the test step give him confidence?

### 7.4 Sandra

**Scenario A: SAML SSO Setup**
> "You need to set up SAML SSO between Microsoft Entra ID and Qeet ID, as part of a workforce identity rollout. Use the metadata I'll provide. Once set up, configure SCIM provisioning so users sync automatically."

Success metrics:
- SAML setup ≤15 min
- SCIM setup ≤10 min
- Did she find the attribute mapping UI usable?
- Did the test step validate correctly?

**Scenario B: Audit Log Investigation**
> "Last night, a user reported they were unexpectedly signed out at 9:47 PM. Find what happened."

Success metrics:
- Time to locate the user's audit history ≤2 min
- Did she find the relevant event (e.g., refresh-token-reuse-detection or admin-revocation)?
- Did she figure out the cause without external help?

### 7.5 Omar

**Scenario: Vendor Security Review**
> "You're conducting a vendor security review of Qeet ID. Find everything you need to give Qeet ID a security sign-off — or to reject them."

Success metrics:
- Time to find SOC 2 report ≤90 s
- Time to find pen test summary ≤90 s
- Time to find data residency information ≤90 s
- Time to find breach notification policy ≤2 min
- Was the NDA gate (for SOC 2) friction-acceptable?
- Self-reported confidence in security posture ≥4/5

### 7.6 Assistive Technology User

**Scenario: Sign Up + Sign In with Screen Reader**
> "Using a screen reader, sign up for a Qeet ID account, register a passkey, sign out, and sign back in."

Success metrics:
- Task completion without seeing visual UI
- Time to first auth ≤15 min (we accept higher time given the unfamiliar UI)
- Any unannounced state changes
- Any keyboard traps

---

### 8. Success Metrics per Test

### 8.1 Quantitative

| Metric | Target |
| --- | --- |
| Task completion rate | ≥80% per persona, per critical scenario |
| Time on task | ≤target (5 min Arjun first auth; 10 min Sandra SAML; etc.) |
| Error count (moderator-observed) | ≤1 critical error per scenario |
| System Usability Scale (SUS) score | ≥68 (industry "good") at Phase 3 prototype testing; ≥75 at Phase 8 beta |
| Single Ease Question (SEQ) per task | ≥5/7 |
| Net Promoter Score (NPS, quarterly post-launch) | ≥30 |

### 8.2 Qualitative

- **Themes** that recur across ≥3 participants — high signal.
- **Surprises** — things participants did unexpectedly that informed an unanticipated design issue.
- **Quotes** — verbatim, attributed by pseudonym, used to humanise findings and quoted in roadmap discussions.

---

### 9. Findings Documentation Template

Every test session produces a findings document with the following structure:

```
   Findings: [Persona] — [Scenario name]
   Date · Moderator · Researcher · # participants

   1. Summary
      [3-sentence summary of what we learned]

   2. Setup
      Tasks tested
      Participants (pseudonymised)
      Tools used

   3. Key findings (ranked by severity)

      Finding 1 [P1]:
        Observation: [What happened, across how many participants]
        Quotes: [Verbatim from participants]
        Implication: [What this means for the design]
        Recommendation: [What the UX team proposes]
        Owner: [UX Designer / Frontend Lead / Tech Writing]
        Target resolution: [Date]

      Finding 2 [P2]:
        …

   4. Quantitative results
      Task completion rates
      Time on task (median, p95)
      SUS score
      SEQ scores

   5. Surprises
      [Unexpected behaviours worth noting]

   6. Positive findings
      [What worked well — don't lose track of these]

   7. Next steps
      Iterations to make
      Re-test date if any
```

A single living "Findings Register" tracks all findings across all tests with status (Open / In Progress / Resolved / Won't Fix). Reviewed weekly during Phase 3, fortnightly thereafter.

---

### 10. Findings Severity Classification

| Severity | Definition | SLA |
| --- | --- | --- |
| **P1 — Must fix before launch** | Blocks a critical persona task; the user fails or gives up; the design promise (passkey-first; 5-min TTFA) is not met | Phase 3 / Phase 4: ≤2 weeks; Phase 8: ≤4 weeks |
| **P2 — Should fix** | Degrades a task significantly; workaround exists; ≥50% of participants encountered it | Phase 3: ≤4 weeks; Phase 8: ≤8 weeks |
| **P3 — Track and consider** | Cosmetic or single-participant edge issue | Backlog; roadmap consideration |
| **P4 — Positive signal** | Confirms a design choice worked; do not lose track | n/a — log for future reference |

Findings with severity P1 are launch-blocking. The UX Designer and Product Manager jointly classify; the Solution Architect adjudicates disputes.

---

### 11. Iteration Cadence

### 11.1 Phase 3

- Weekly findings review (UX Designer + Product Manager + relevant stakeholders).
- Iterations applied to Figma and Phase 3 docs within one week of findings review.
- Re-test of high-priority changes within two weeks.

### 11.2 Phase 4

- Fortnightly findings review.
- Iterations enter Phase 4 backlog with severity-driven priority.
- Re-test at end of Phase 4 against critical scenarios.

### 11.3 Phase 8 (Beta)

- Weekly review of in-product feedback + pilot customer check-ins.
- Findings flow into v1.1 roadmap.
- Critical (P1) findings fixed in beta hotfixes.

### 11.4 Post-Launch

- Monthly review of feedback + NPS verbatims.
- Quarterly persona-touchpoint testing (one per persona).
- Findings inform v1.x roadmap.

---

### 12. Testing Tools Stack

| Tool | Use | Notes |
| --- | --- | --- |
| **Maze** OR **UserTesting** | Unmoderated remote testing (OD-UT-01) | Pick one |
| **Google Meet / Zoom** | Moderated session video conferencing | Recordings retained 90 days |
| **Lookback / Dovetail** | Session recording + analysis | OD-UT-02 |
| **Figma** | Prototype delivery for Phase 3 testing | |
| **Notion / Linear** | Findings register | |
| **Hotjar / FullStory** | Post-launch session recording (opt-in only; GDPR-compliant) | OD-UT-03 — only if customers opt in tenant-wide |
| **Delighted / Wootric / Sprig** | NPS surveys | OD-UT-04 |
| **Fable** | Assistive-tech user panel | |

---

### 13. Privacy & Consent Standards

### 13.1 Participant Consent

Every participant signs a consent form before testing covering:

- Recording (video + voice + screen) — explicit opt-in.
- Use of recordings (internal product improvement only, not marketing).
- Verbatim quotes (anonymised by pseudonym).
- Retention (90 days for raw recordings; aggregated findings retained indefinitely).
- Withdrawal (participant can request deletion any time).

Consent forms are stored alongside session recordings; researchers cannot view recordings without confirmed consent.

### 13.2 Pseudonymisation

Personally identifiable data is replaced with pseudonyms in findings docs: "Arjun-P1" / "Maya-P2" rather than real names. The mapping is held only by the UX Researcher; researchers reading findings docs see pseudonyms only.

### 13.3 GDPR & Beta Customer Data

For Phase 8 beta customers and post-launch testing:

- Production session recording (Hotjar / FullStory) requires **tenant opt-in** (per Phase 2 [Compliance Matrix](../phase-1/Qeet%20ID%20%E2%80%94%20Compliance%20Requirements%20Matrix.md)).
- No PII is captured in session recordings (passwords, MFA codes, email content all masked by default).
- Recordings retained 30 days; aggregate metrics indefinitely.

### 13.4 Researcher Conflict of Interest

The UX Researcher does not participate in design decisions arising from their own test findings — to maintain independence. Findings are presented to the UX Designer and Product Manager who make iteration decisions.

---

### 14. Findings Distribution

| Audience | Channel | Cadence |
| --- | --- | --- |
| UX Designer | Direct (researcher → designer) | Same day as session |
| Product Manager | Findings doc + 30-min weekly review | Weekly Phase 3; fortnightly thereafter |
| Frontend Engineering | Findings doc + linked backlog issues | When findings affect their work |
| Technical Writing | Findings doc + tickets for doc gaps | Weekly during Phase 3 / 4 |
| Customer Success / Sales | Quarterly digest of beta findings | Quarterly |
| CTO / Leadership | Quarterly UX-health report | Quarterly |
| Engineering team-wide | Selected verbatim quotes shared in weekly Friday roundup | Weekly post-launch |

### 14.1 Public Distribution

Selected findings (anonymised, with persona consent) inform:
- Public blog posts ("What we learned from 5 developers about auth integration").
- Conference talks (when appropriate).
- Open-source contributions to the broader auth-platform community.

---

### 15. Specific Phase 3 Testing Plan

The first round of usability testing, scheduled for Phase 3 Week 4–5:

| Week 4 | Week 5 |
| --- | --- |
| Recruitment + scheduling | Sessions + analysis |
| Prototype assembly in Figma | Iteration |

### 15.1 Phase 3 Test Suite

| Participants | Scenario | Prototype | Duration |
| --- | --- | --- | --- |
| 5 × Arjun | First Integration (§7.1 A) | Quickstart Figma prototype + clickable code | 60 min |
| 3 × Maya | B2B Multi-Tenancy Evaluation (§7.2 A) | Docs prototype + pricing calculator | 60 min |
| 3 × Daniel | Firebase Migration (§7.3 A) | Docs + dashboard migration prototype | 60 min |
| 2 × Sandra | SAML Setup (§7.4 A) | Dashboard prototype | 60 min |
| 1 × Omar | Trust Center Review (§7.5) | Trust Center prototype | 45 min |
| 1 × Assistive-tech user | Sign-up + Sign-in with SR | Hosted login pages prototype | 60 min |

**Total: ~15 sessions over 2 weeks.** Researcher-coordinated.

---

### 16. Open Design Decisions From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OD-UT-01 | Unmoderated testing tool — Maze vs UserTesting | UX Researcher | Phase 3 Week 2 |
| OD-UT-02 | Session analysis platform — Lookback vs Dovetail | UX Researcher | Phase 3 Week 2 |
| OD-UT-03 | Production session recording — opt-in tenant-wide vs per-user | UX + Compliance | Phase 4 |
| OD-UT-04 | NPS survey tool — Delighted vs Wootric vs Sprig | UX + Customer Success | Phase 8 |
| OD-UT-05 | Whether to do diary studies of Daniel-class migration journeys at MVP vs v1.1 | UX + Product | Phase 3 Week 3 |
| OD-UT-06 | Public sharing of usability findings — blog posts at MVP vs v1.1 | UX + Marketing + Legal | Phase 8 |

---

### 17. Cross-References

- Principles being tested: [UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) §6
- Success metrics referenced: [UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) §9
- Persona criteria: [Phase 1 Persona Documents & Customer Journey Maps](../phase-1/Qeet%20ID%20%E2%80%94%20Persona%20Documents%20%26%20Customer%20Journey%20Map.md)
- Compliance for production session recording: [Phase 1 Compliance Matrix §4](../phase-1/Qeet%20ID%20%E2%80%94%20Compliance%20Requirements%20Matrix.md)
- Accessibility-user inclusion: [Accessibility Compliance Plan (WCAG 2.1 AA)](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md) §16.3
- In-product feedback widgets: [Developer Portal Design Specification](Qeet ID%20%E2%80%94%20Developer%20Portal%20Design%20Specification.md) §21
- Dashboard feedback affordance: [Admin Dashboard Design Specification](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md) §6.4

---

### 18. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| UX Designer |  |  |  |
| UX Researcher |  |  |  |
| Product Manager |  |  |  |
| Customer Success Lead |  |  |  |
| Developer Relations Lead |  |  |  |
| Compliance Officer (privacy & consent) |  |  |  |
| QA Lead |  |  |  |

---

*This document is version controlled. Visual updates in Figma do not require re-sign-off; changes to the participant recruitment criteria (§5), the testing scenarios (§7), the success metrics (§8), the severity classification (§10), or the privacy / consent standards (§13) require UX Designer + UX Researcher + Product Manager + Compliance Officer review.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
