# Qeet ID — Persona Documents & Customer Journey Maps

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Persona Documents & Customer Journey Maps |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer + Product Manager |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the primary and secondary user personas for Qeet ID, grounded in Phase 1 stakeholder interviews, competitor research, and market analysis. Each persona is mapped to a detailed Customer Journey — from the moment they first encounter an authentication problem, through discovery, evaluation, integration, and long-term usage. These personas and journeys directly inform Phase 3 UI/UX Design decisions, Phase 4 SDK prioritization, and the Go-To-Market messaging strategy.

---

### 3. Persona Overview Summary

| # | Persona Name | Segment | Role | Primary Product Use |
| --- | --- | --- | --- | --- |
| 1 | Arjun — The Solo Developer | Developers & Startups | Individual Developer / Freelancer | Qeet ID Auth, Qeet ID Keys |
| 2 | Maya — The Startup CTO | Developers & Startups | Technical Co-Founder / CTO | Qeet ID Auth, Qeet ID ID, Qeet ID Access |
| 3 | Daniel — The Mid-Market Engineering Lead | Mid-Market | Engineering Manager / Tech Lead | Qeet ID Auth, Qeet ID Connect, Qeet ID Guard |
| 4 | Sandra — The Enterprise IT Admin | Enterprise | IAM Administrator / IT Director | Qeet ID Connect, Qeet ID ID, Qeet ID Access |
| 5 | Omar — The Enterprise Security Officer | Enterprise | CISO / Head of Security | Qeet ID Guard, Qeet ID Keys, Compliance Suite |

---

### 4. Persona 1 — Arjun, The Solo Developer

---

### 4.1 Persona Profile

|  |  |
| --- | --- |
| **Persona Name** | Arjun |
| **Persona Type** | Primary |
| **Segment** | Individual Developer / Freelancer |
| **Age** | 24–32 |
| **Location** | Urban tech hub — Bangalore, London, São Paulo, Toronto |
| **Education** | Computer Science degree or self-taught full-stack developer |
| **Experience** | 1–4 years in software development |
| **Primary Role** | Solo developer building SaaS apps, side projects, or freelance client work |
| **Primary Products Used** | Qeet ID Auth, Qeet ID Keys |
| **Pricing Tier** | Free (up to 10,000 MAUs) |

---

### 4.2 Background

Arjun is a self-driven developer building his own SaaS product on weekends or working as a freelancer taking on small startup contracts. He is technically capable but operates alone — no security team, no DevOps engineer, no compliance officer. He values his time fiercely. Every hour spent on authentication infrastructure is an hour not spent on his product's core features. He has tried building auth from scratch once, learned the hard way how complex token management and session security really are, and vowed never to do it again.

He has heard of Auth0 and Firebase. He has probably started integrating one of them, hit a confusing configuration wall, or discovered he'd be charged the moment his app gained traction. He is now actively looking for something better.

---

### 4.3 Goals

- Ship a working login system in hours, not days
- Not pay anything until his app actually has real users
- Have clean, copy-paste-ready documentation with real code examples
- Add social login (Google, GitHub) with minimal effort
- Know his users' data is secure without having to become a security expert

---

### 4.4 Pain Points

| Pain Point | Description |
| --- | --- |
| Time cost | Authentication takes days to build from scratch and weeks to secure properly |
| Pricing shock | Auth0 and Firebase charge for features Arjun needs before he has revenue |
| Documentation quality | Poor or outdated docs with no real-world code examples for his stack |
| Complexity | Configuring OIDC flows, callback URLs, and token validation is overwhelming for a solo dev |
| Vendor fear | Worried about building on a platform that gets acquired or deprecated (Firebase, Auth0/Okta history) |
| SDK gaps | His chosen stack (e.g. Next.js + Python backend) is often not covered by the same SDK ecosystem |

### 4.5 Motivations

- Wants to launch fast and look professional
- Wants to impress potential clients or early users with a polished, secure login experience
- Wants to grow his side project into a real business without re-platforming his auth stack later

---

### 4.6 Technology Profile

|  |  |
| --- | --- |
| **Primary Stack** | React / Next.js frontend, Node.js or Python backend |
| **Cloud** | Vercel, Railway, Render, or AWS (basic) |
| **Auth Knowledge** | Basic — understands JWTs and OAuth concepts, limited hands-on experience |
| **Devices** | MacBook, occasionally builds mobile apps with Flutter |
| **Communities** | GitHub, Dev.to, Hacker News, Reddit r/webdev, Discord servers |
| **Preferred Learning** | Code snippets, YouTube tutorials, GitHub README files |

---

### 4.7 Qeet ID Value Proposition for Arjun

*"Be live in under 10 minutes. Free until you're successful. We grow with you."*

- Free tier up to 10,000 MAUs — no credit card required
- React and Next.js SDKs with copy-paste quickstart examples
- Social login in under 5 minutes
- Passkeys as default — no more password headache
- Documentation written for developers, not enterprise architects

---

### 4.8 Quote (Representative)

> *"I just want auth to work. I don't want to read a 90-page guide before I can show my users a login screen."*
> 

---

### 5. Persona 2 — Maya, The Startup CTO

---

### 5.1 Persona Profile

|  |  |
| --- | --- |
| **Persona Name** | Maya |
| **Persona Type** | Primary |
| **Segment** | Startups (Seed to Series A) |
| **Age** | 28–38 |
| **Location** | San Francisco, Amsterdam, Singapore, Nairobi, Dubai |
| **Education** | Computer Science / Software Engineering degree |
| **Experience** | 5–10 years in engineering, now leading a team of 3–8 engineers |
| **Primary Role** | Technical Co-Founder or CTO at a fast-growing startup |
| **Primary Products Used** | Qeet ID Auth, Qeet ID ID, Qeet ID Access |
| **Pricing Tier** | Free → Growth (scales with MAU growth) |

---

### 5.2 Background

Maya is building a B2B SaaS product and is responsible for every technical decision. She moves fast but thinks long-term. She cannot afford to choose a technology today that will force a painful migration tomorrow. Auth is the most critical infrastructure decision she'll make early — get it wrong, and re-platforming her entire user base will cost months she doesn't have.

She's been burned before. She chose AWS Cognito for a previous product and spent weeks fighting its documentation. She considered Auth0 but couldn't justify the pricing once she modelled their MAU-based costs at scale. She is evaluating Qeet ID alongside Kinde, Auth0, and potentially Keycloak — and she will run a technical proof-of-concept before committing.

Maya needs multi-tenancy from day one. Her B2B product means each customer organization needs their own isolated space with their own user roles. She needs RBAC. She needs to look enterprise-ready to her own customers, even at Series A stage.

---

### 5.3 Goals

- Choose an auth platform that scales from 100 users to 1 million without migration
- Implement multi-tenancy and RBAC cleanly without building it herself
- Onboard her team with minimal ramp-up time
- Have a clear path to enterprise features (SAML, SCIM) when she needs them
- Keep infrastructure costs predictable as she scales

---

### 5.4 Pain Points

| Pain Point | Description |
| --- | --- |
| Scaling cost uncertainty | Most platforms have per-MAU pricing that becomes unpredictable at growth stage |
| Re-platforming risk | Choosing the wrong auth tool today means a painful migration later |
| Multi-tenancy complexity | Most auth platforms require custom code to handle B2B organization isolation |
| Team onboarding time | New engineers joining her team need to understand the auth architecture quickly |
| Enterprise readiness gap | Investor clients and enterprise prospects expect SAML/SSO, which cheaper plans don't include |
| SOC 2 pressure | Her biggest B2B prospects demand SOC 2 before they sign — she needs her auth platform to support that story |

---

### 5.5 Motivations

- Build something her team can maintain and extend without specialist knowledge
- Move fast without compromising security
- Make technically credible decisions that she can defend to her board and investors

### 5.6 Technology Profile

|  |  |
| --- | --- |
| **Primary Stack** | React / Next.js, Node.js or Go backend, PostgreSQL |
| **Cloud** | AWS or GCP, with Terraform for IaC |
| **Auth Knowledge** | Advanced — understands OAuth 2.0, OIDC, SAML, JWTs deeply |
| **Devices** | MacBook Pro, cloud CLI tools daily |
| **Communities** | YC Slack, Hacker News, LinkedIn, GitHub |
| **Preferred Learning** | Architecture docs, GitHub repos, official reference implementations |

---

### 5.7 Qeet ID Value Proposition for Maya

*"Start free. Scale to enterprise. Never migrate again."*

- Multi-tenancy built in — no custom code required
- RBAC included from the Growth tier
- Predictable MAU-based pricing with no hidden fees
- SAML and SCIM available when the first enterprise deal demands it
- SOC 2 Type I certified — supports Maya's own compliance story
- Go and Node.js SDKs ready for her team

---

### 5.8 Quote (Representative)

> *"I need auth that I can wire up today and still trust in three years when we're at 10 million users. I don't want to have this conversation again at Series B."*
> 

---

### 6. Persona 3 — Daniel, The Mid-Market Engineering Lead

---

### 6.1 Persona Profile

|  |  |
| --- | --- |
| **Persona Name** | Daniel |
| **Persona Type** | Primary |
| **Segment** | Mid-Market Companies (100–1,000 employees) |
| **Age** | 32–45 |
| **Location** | New York, Berlin, Sydney, Toronto |
| **Education** | Computer Science or Information Systems degree |
| **Experience** | 10–15 years in engineering; currently managing a team of 10–25 engineers |
| **Primary Role** | VP of Engineering / Engineering Manager |
| **Primary Products Used** | Qeet ID Auth, Qeet ID Connect, Qeet ID Guard |
| **Pricing Tier** | Growth → Enterprise |

---

### 6.2 Background

Daniel's company has outgrown its original auth setup. They started with Firebase Auth three years ago, and it worked fine at 5,000 users. Now they're at 200,000 MAUs, have enterprise customers demanding SAML-based SSO, and have a security team that's raising concerns about their bot exposure and lack of proper audit logging. Firebase Auth simply cannot meet these needs.

Daniel has been tasked with owning the auth migration. He has built a shortlist: Auth0 for enterprise features, Okta Customer Identity Cloud for scale, and Qeet ID as the new challenger. His priorities are clear — minimal migration disruption, enterprise protocol support, strong security posture, and a vendor that will be around in five years. His team is technically strong but stretched thin. He cannot afford months of integration work.

---

### 6.3 Goals

- Migrate from Firebase Auth to a platform that supports SAML, SCIM, and MFA without disrupting existing users
- Satisfy enterprise customer demands for SSO and provisioning
- Reduce auth-related security incidents and bot traffic
- Give his team a manageable, well-documented platform to operate
- Report clearly on auth events and user activity for compliance purposes

---

### 6.4 Pain Points

| Pain Point | Description |
| --- | --- |
| Migration complexity | Moving 200,000 existing users to a new platform without breaking login flows is technically high-risk |
| Enterprise feature gaps | Firebase Auth doesn't support SAML SSO — his biggest customers are asking for it at every renewal |
| Bot and fraud exposure | No bot detection or anomaly detection at Firebase's basic tier |
| Audit log deficiency | No granular audit trail — a problem during security reviews |
| Vendor reliability concern | Auth0 post-Okta acquisition has made him nervous about roadmap stability |
| Pricing at scale | Auth0's Business tier pricing is significant — finance is asking him to justify the ROI |

---

### 6.5 Motivations

- Deliver a platform migration his team can be proud of, without a war-room incident
- Give his security team the visibility tools they've been asking for
- Prove to leadership that he made the right technical choice long-term

---

### 6.6 Technology Profile

|  |  |
| --- | --- |
| **Primary Stack** | React frontend, Python and Node.js backend, microservices architecture |
| **Cloud** | AWS (primarily), some GCP services |
| **Auth Knowledge** | Expert — runs auth architecture decisions and reviews |
| **Devices** | MacBook Pro, Jira, GitHub, Slack daily |
| **Communities** | LinkedIn, engineering leadership conferences, CNCF events |
| **Preferred Learning** | Architecture whitepapers, migration guides, reference customers |

---

### 6.7 Qeet ID Value Proposition for Daniel

*"Migration-ready. Enterprise-certified. Built for teams like yours."*

- Dedicated migration guide from Firebase Auth to Qeet ID — low-disruption user import
- SAML 2.0 and SCIM provisioning included in Growth tier
- Qeet ID Guard provides bot detection, anomaly alerting, and rate limiting out of the box
- Audit logs with full event trail for security and compliance reporting
- SOC 2 Type I certified — satisfies Daniel's security team's approval process
- Independent roadmap — not subject to Okta's post-acquisition product decisions

### 6.8 Quote (Representative)

> *"I need a platform that can pass a security review on a Tuesday and close an enterprise deal on a Wednesday. And I need the migration to not be a war story I'm still telling in two years."*
> 

---

### 7. Persona 4 — Sandra, The Enterprise IT Admin

---

### 7.1 Persona Profile

|  |  |
| --- | --- |
| **Persona Name** | Sandra |
| **Persona Type** | Primary |
| **Segment** | Enterprise (1,000+ employees) |
| **Age** | 38–52 |
| **Location** | Chicago, Frankfurt, Singapore, Dubai |
| **Education** | Information Technology, Cybersecurity, or Systems Administration degree |
| **Experience** | 15+ years in IT and identity management |
| **Primary Role** | IAM Administrator / IT Director |
| **Primary Products Used** | Qeet ID Connect, Qeet ID ID, Qeet ID Access |
| **Pricing Tier** | Enterprise (Custom Contract) |

---

### 7.2 Background

Sandra is the person who makes enterprise identity work every day. She is not involved in the initial vendor selection decision — that happens above her — but she is the one who will live with it for the next five years. She manages thousands of user identities, onboards and offboards employees, manages SSO connections to dozens of SaaS applications, and responds when something goes wrong at 2am.

Sandra has worked with Microsoft Entra ID for years and knows its power — and its complexity. Her organization is expanding, acquiring a new subsidiary, and needs an external CIAM layer for their customer-facing application. Entra ID is the wrong tool for CIAM. She's been asked to evaluate options, and she needs something that integrates with Entra ID via SAML or OIDC federation, supports SCIM for automated provisioning, and won't require her team to rebuild their existing directory infrastructure.

Sandra's world is defined by risk. She doesn't adopt new tools eagerly. She validates security certifications, reads audit reports, checks integration compatibility lists, and calls references before making a recommendation. She needs to trust Qeet ID before she can advocate for it.

---

### 7.3 Goals

- Integrate Qeet ID with the existing Microsoft Entra ID workforce identity infrastructure via SAML federation
- Automate user provisioning and deprovisioning via SCIM to eliminate manual onboarding errors
- Give the application team a clean CIAM layer with proper user lifecycle management
- Maintain full audit trails for all identity events to support the company's ISO 27001 obligations
- Minimize support burden on her team post-deployment

---

### 7.4 Pain Points

| Pain Point | Description |
| --- | --- |
| Integration complexity with existing IdP | Connecting a new CIAM layer to an existing Entra ID infrastructure requires careful SAML/OIDC federation |
| Manual provisioning risk | Without SCIM, user access is managed manually — a source of access over-provisioning and offboarding failure |
| Audit and compliance gaps | Any identity platform that doesn't provide granular audit logs is immediately disqualified |
| Vendor evaluation burden | Evaluating a new identity platform is time-consuming — Sandra needs clear technical documentation and reference architecture |
| Support quality anxiety | When identity breaks, the entire organization stops. Sandra needs 24/7 enterprise support with committed SLAs |
| New vendor trust deficit | Sandra will not adopt a platform that hasn't proven it can survive long-term — the Auth0/Okta situation is a cautionary tale she references actively |

---

### 7.5 Motivations

- Protect the organization from identity-related security incidents
- Make her team's daily operations more efficient through automation
- Build an identity infrastructure that scales as the organization acquires more subsidiaries

---

### 7.6 Technology Profile

|  |  |
| --- | --- |
| **Primary Stack** | Microsoft Entra ID, Active Directory, PowerShell, REST APIs |
| **Cloud** | Microsoft Azure primarily; some AWS for non-Microsoft services |
| **Auth Knowledge** | Expert — deep understanding of SAML, SCIM, LDAP, OIDC, federation, directory services |
| **Devices** | Windows workstation, admin consoles, mobile for MFA |
| **Communities** | Microsoft Tech Community, ISACA, (ISC)², LinkedIn groups |
| **Preferred Learning** | Vendor documentation, architecture diagrams, peer references, certified training |

---

### 7.7 Qeet ID Value Proposition for Sandra

*"Enterprise-grade from Day 1. Proven. Certified. Reliable."*

- SAML 2.0 federation with Microsoft Entra ID — verified reference architecture provided
- SCIM 2.0 provisioning — fully automated user lifecycle management
- Audit logs with full event history and exportable reports for ISO 27001 evidence
- SOC 2 Type I certified — available in the sales process as formal documentation
- 24/7 enterprise support with dedicated SLA commitment
- Backed by Qeet Group — a diversified conglomerate with long-term organizational commitment

---

### 7.8 Quote (Representative)

> *"I've seen platforms come and go. What I need to know is: will this still be here and supported in five years? And can I show the auditor the logs they're asking for right now?"*
> 

### 8. Persona 5 — Omar, The Enterprise Security Officer

---

### 8.1 Persona Profile

|  |  |
| --- | --- |
| **Persona Name** | Omar |
| **Persona Type** | Primary |
| **Segment** | Enterprise (1,000+ employees) |
| **Age** | 40–55 |
| **Location** | London, Riyadh, New York, Singapore |
| **Education** | Computer Science, Cybersecurity, or Information Assurance degree; CISSP / CISM certified |
| **Experience** | 18+ years in cybersecurity; currently Chief Information Security Officer or Head of Security |
| **Primary Role** | CISO / Enterprise Security Officer |
| **Primary Products Used** | Qeet ID Guard, Qeet ID Keys, Qeet ID Access, Compliance Suite |
| **Pricing Tier** | Enterprise (Custom Contract) |

---

### 8.2 Background

Omar is the final security gate that any identity platform must pass before his organization can adopt it. He reports directly to the CEO and board. A breach at the identity layer is career-ending. He is not the day-to-day operator — that's Sandra — but he is the decision gatekeeper. He has rejected platforms before. He rejected a leading auth vendor two years ago specifically because it could not provide a SOC 2 Type II audit report and had a recent CVE disclosure it handled poorly.

Omar's evaluation is clinical. He will read Qeet ID's security architecture documentation, request the SOC 2 audit report, ask about penetration testing frequency, review the incident response and breach notification procedures, evaluate the data residency options, and check if Qeet ID has a published CVE disclosure policy. He will also ask about passkey and MFA enforcement — his organization is moving toward a passwordless policy. He is a late adopter but an influential one. A reference from Omar's company opens ten more enterprise doors.

---

### 8.3 Goals

- Ensure the authentication platform meets or exceeds the organization's security policy requirements
- Achieve zero credential-based breaches — enforce MFA and move toward passwordless
- Get full visibility into anomalous login activity, bot threats, and suspicious access patterns
- Ensure API keys and machine credentials are managed with proper secrets hygiene
- Satisfy external auditors with documented, certified security controls

---

### 8.4 Pain Points

| Pain Point | Description |
| --- | --- |
| Compliance documentation gaps | Vendors who cannot provide SOC 2 reports, penetration test summaries, or security architecture documentation are immediately disqualified |
| Inadequate threat visibility | No anomaly detection or bot protection in lower-tier auth platforms is unacceptable at enterprise scale |
| Credential sprawl risk | M2M API keys and secrets without proper lifecycle management are a persistent attack surface |
| MFA bypass risks | Platforms where MFA is optional or easy to bypass are a liability |
| Data residency uncertainty | For organizations in regulated markets (EU, Middle East, financial services), data residency and sovereignty are non-negotiable |
| Vendor incident transparency | Poor CVE disclosure history or slow breach notification is a red flag |

---

### 8.5 Motivations

- Protect the organization from identity-based attacks — the most common attack vector in enterprise environments
- Build a defensible security posture that satisfies board-level risk appetite
- Enable the business to move faster by providing secure-by-default identity infrastructure

---

### 8.6 Technology Profile

|  |  |
| --- | --- |
| **Primary Stack** | SIEM tools (Splunk, Microsoft Sentinel), IAM platforms, PAM tools |
| **Cloud** | Multi-cloud oversight, cloud security posture management |
| **Auth Knowledge** | Expert — deep knowledge of authentication protocols, zero trust architecture, threat modeling |
| **Devices** | Enterprise workstation, mobile, secure communication tools |
| **Communities** | ISACA, (ISC)², CISO forums, Gartner peer communities |
| **Preferred Learning** | Security whitepapers, audit reports, Gartner analyst coverage, peer CISOs |

---

### 8.7 Qeet ID Value Proposition for Omar

*"Security is not a feature at Qeet ID. It is the product."*

- SOC 2 Type I at launch; SOC 2 Type II within 12 months post-launch
- Qeet ID Guard — bot detection, anomaly detection, threat intelligence, and rate limiting built in
- Passkey-first authentication — passwordless by default, not by configuration
- MFA enforcement policies at the organizational level — not optional per user
- Qeet ID Keys — API key lifecycle management with rotation policies and expiry controls
- Structured incident response and breach notification procedures — available to enterprise customers in SLA documentation
- GDPR compliance at launch; data residency roadmap documented and committed

---

### 8.8 Quote (Representative)

> *"Every major breach in the last five years started at the identity layer. My job is to make sure ours doesn't. If your platform can't give me an audit report, a pen test, and a breach notification policy before we sign — we're done."*
> 

### 9. Customer Journey Maps

---

### 9.1 Journey Map — Arjun (Solo Developer)

**Journey Title:** From Authentication Frustration to First Auth in Under 10 Minutes

---

### Stage 1 — Awareness

|  |  |
| --- | --- |
| **Trigger** | Arjun has built 60% of his SaaS app and needs to add user login. He starts researching options. |
| **Actions** | Googles "best authentication library 2026", reads Reddit threads, browses Hacker News, watches a YouTube tutorial |
| **Touchpoints** | Google search results, Reddit r/webdev, Hacker News, Dev.to articles, YouTube |
| **Thoughts** | *"Which one is actually the easiest? I don't want to spend days on this."* |
| **Emotions** | Curious, slightly anxious about time cost |
| **Pain Points** | Overwhelmed by the number of options — Auth0, Firebase, Cognito, Kinde, Qeet ID all appearing |
| **Opportunity for Qeet ID** | Developer-focused SEO content and comparison articles — "Qeet ID vs Auth0 for solo devs", community presence on Reddit and Hacker News |

---

### Stage 2 — Discovery

|  |  |
| --- | --- |
| **Trigger** | Arjun sees Qeet ID mentioned alongside Auth0 and Kinde in a dev comparison article. Clicks through to qeetify.com. |
| **Actions** | Reads the homepage hero message, looks for pricing immediately, checks SDK list, looks for a "get started" button |
| **Touchpoints** | Qeet ID homepage, pricing page, documentation landing page |
| **Thoughts** | *"Is this actually free? Do they have Next.js? Let me check their docs before I commit to reading more."* |
| **Emotions** | Cautiously optimistic, scanning for red flags |
| **Pain Points** | Any friction on the homepage — vague pricing, missing SDK for his stack, no quick start code visible |
| **Opportunity for Qeet ID** | Prominent homepage: "10 minutes to first auth. Free up to 10,000 MAUs. No credit card." Visible Next.js and React in SDK list. Code snippet on the homepage. |

---

### Stage 3 — Evaluation

|  |  |
| --- | --- |
| **Trigger** | Arjun opens the documentation. He wants to see a real quickstart — not a concept guide, but actual code. |
| **Actions** | Reads the Next.js quickstart guide, checks if passkeys and social login setup are covered, copies a code snippet into his project |
| **Touchpoints** | Developer documentation portal, quickstart guides, code examples |
| **Thoughts** | *"Okay this actually looks clean. Let me try copying this into my project."* |
| **Emotions** | Focused, testing patience — one bad error and he leaves |
| **Pain Points** | Confusing setup steps, missing environment variable explanations, unclear callback URL configuration |
| **Opportunity for Qeet ID** | World-class quickstart: copy-paste working code, clear env variable setup, immediate test confirmation in under 10 minutes |

---

### Stage 4 — First Integration (Activation)

|  |  |
| --- | --- |
| **Trigger** | Arjun successfully runs his first auth flow — a user can log in with Google on his local app. |
| **Actions** | Celebrates the working login, checks the Qeet ID dashboard to confirm the user appeared, shares a screenshot in a dev Discord |
| **Touchpoints** | Qeet ID admin dashboard, developer portal, personal Discord server |
| **Thoughts** | *"That was actually fast. I'm going to tell people about this."* |
| **Emotions** | Relieved, excited, satisfied — this is the peak positive moment |
| **Pain Points** | Dashboard is confusing, user doesn't appear as expected, or the experience is anticlimactic |
| **Opportunity for Qeet ID** | Frictionless dashboard activation: first login confirmation screen, guided next steps ("Now add MFA", "Try passkeys"), shareable developer moment |

---

### Stage 5 — Adoption & Expansion

|  |  |
| --- | --- |
| **Trigger** | Arjun's app launches. First 50 users sign up. He checks his MAU dashboard — well within the free tier. |
| **Actions** | Adds MFA, explores passkeys feature, recommends Qeet ID to two freelancer friends |
| **Touchpoints** | Qeet ID dashboard, admin settings, developer community word-of-mouth |
| **Thoughts** | *"This is still free. I'll stick with this until I need to upgrade."* |
| **Emotions** | Confident, loyal early adopter |
| **Pain Points** | Unexpected billing, confusing free tier limits, missing features that force a competitor look |
| **Opportunity for Qeet ID** | Clear MAU counter in dashboard, proactive "You're at 8,000 MAUs — here's what happens when you reach 10K" communication. Developer referral program. |

---

### Stage 6 — Growth & Upgrade

|  |  |
| --- | --- |
| **Trigger** | Arjun's app crosses 10,000 MAUs. He receives a clear upgrade prompt from Qeet ID. |
| **Actions** | Reviews the Growth tier pricing, calculates cost vs revenue, upgrades to paid |
| **Touchpoints** | Billing page, pricing calculator, email notification |
| **Thoughts** | *"If I'm at 10K MAUs, I can afford this. And I don't want to rebuild auth."* |
| **Emotions** | Pragmatic, willing — conversion is emotionally low-friction because trust was already built |
| **Pain Points** | Sticker shock, no pricing calculator, unclear what the Growth tier actually adds |
| **Opportunity for Qeet ID** | Transparent pricing calculator, Growth tier value clearly articulated, smooth one-click upgrade |

---

### 9.2 Journey Map — Maya (Startup CTO)

**Journey Title:** From Platform Evaluation to Production Deploy for a B2B SaaS Product

---

### Stage 1 — Awareness

|  |  |
| --- | --- |
| **Trigger** | Maya's team is 3 weeks from launching their B2B SaaS MVP. Auth is the last major decision. She needs multi-tenancy and RBAC out of the box. |
| **Actions** | Posts in YC Slack asking for auth recommendations, reads three comparison articles, creates a shortlist: Auth0, Kinde, Qeet ID |
| **Touchpoints** | YC Slack, Hacker News, product comparison blogs |
| **Thoughts** | *"I need something that handles multi-tenant B2B and doesn't make me regret this decision at Series A."* |
| **Emotions** | Strategic, time-pressured, evaluating risk |
| **Pain Points** | Generic auth recommendations that don't address B2B multi-tenancy requirements |
| **Opportunity for Qeet ID** | B2B SaaS-specific positioning — "Multi-tenancy built in. RBAC included. Scale to enterprise without migrating." Visible in YC Slack and B2B founder communities. |

---

### Stage 2 — Technical Evaluation

|  |  |
| --- | --- |
| **Trigger** | Maya opens all three platforms. She goes straight to documentation architecture sections and pricing calculators. |
| **Actions** | Reviews multi-tenancy architecture docs, tests the Go SDK, runs a proof-of-concept with RBAC, models total cost at 50K MAUs |
| **Touchpoints** | Developer documentation, architecture guides, pricing page, SDK GitHub repository |
| **Thoughts** | *"Does the multi-tenancy model actually work the way I think it does? Let me run a quick POC before committing."* |
| **Emotions** | Analytical, methodical, testing assumptions |
| **Pain Points** | Vague architecture documentation, SDK bugs, opaque pricing at scale, no clear multi-tenancy reference implementation |
| **Opportunity for Qeet ID** | B2B multi-tenancy architecture guide with full reference implementation, pricing calculator with B2B volume simulation, clean Go SDK with real examples |

---

### Stage 3 — Team Alignment

|  |  |
| --- | --- |
| **Trigger** | Maya's POC works. She presents Qeet ID to her two senior engineers for a gut-check. |
| **Actions** | Shares the documentation link, runs a short team demo, asks engineers to push back on the architecture |
| **Touchpoints** | Qeet ID documentation portal, internal Slack, team demo session |
| **Thoughts** | *"If my engineers can get up to speed in a day, this is the right choice."* |
| **Emotions** | Collaborative, evaluating team buy-in |
| **Pain Points** | Documentation too complex for non-expert engineers, no team onboarding path, missing architecture explainer video |
| **Opportunity for Qeet ID** | Team onboarding guide, architecture explainer (diagram + text), "Share with your team" documentation links |

---

### Stage 4 — Procurement & Sign-up

|  |  |
| --- | --- |
| **Trigger** | Team aligns. Maya signs up for the Growth tier, enters billing, sets up the organization account. |
| **Actions** | Creates workspace, invites two engineers, sets up the first tenant, configures RBAC roles |
| **Touchpoints** | Qeet ID admin dashboard, onboarding flow, billing page, workspace setup |
| **Thoughts** | *"Let me get the workspace set up today so the team can start integration tomorrow."* |
| **Emotions** | Decisive, slightly impatient — wants to move fast |
| **Pain Points** | Slow onboarding, confusing workspace setup, unclear how to add team members with appropriate roles |
| **Opportunity for Qeet ID** | CTO onboarding flow — quick workspace setup, team invite with role templates, first tenant creation in under 5 minutes |

---

### Stage 5 — Integration & Launch

|  |  |
| --- | --- |
| **Trigger** | Maya's team integrates Qeet ID into the product over 3 days. B2B customers can now SSO with Google Workspace. |
| **Actions** | Tests full auth flow end-to-end, reviews audit logs, confirms RBAC policies work per tenant, deploys to production |
| **Touchpoints** | SDK documentation, admin dashboard, audit log viewer |
| **Thoughts** | *"This works exactly how I expected. This was the right call."* |
| **Emotions** | Confident, validated, relieved |
| **Pain Points** | Integration bugs in SDK, missing RBAC documentation for specific use case, audit log not surfacing expected events |
| **Opportunity for Qeet ID** | Integration success confirmation, production readiness checklist, pro-active check-in from customer success for Growth tier customers |

---

### Stage 6 — Enterprise Expansion

|  |  |
| --- | --- |
| **Trigger** | Maya's first enterprise prospect asks for SAML SSO. She checks Qeet ID — it's available on the next tier. |
| **Actions** | Upgrades to Enterprise tier, configures SAML with customer's Okta instance, closes the enterprise deal |
| **Touchpoints** | Qeet ID enterprise documentation, SAML configuration guide, support channel |
| **Thoughts** | *"I chose Qeet ID knowing this day would come. I'm glad I don't have to migrate."* |
| **Emotions** | Satisfied, strategically vindicated — this is the moment the "never migrate" promise pays off |
| **Pain Points** | Complex SAML configuration, no guided enterprise setup, slow support response for enterprise onboarding |
| **Opportunity for Qeet ID** | SAML quickstart guide for common IdPs (Okta, Entra ID, Google Workspace), dedicated enterprise onboarding support, "Upgrade to close enterprise deals" in-app prompt |

---

### 9.3 Journey Map — Daniel (Mid-Market Engineering Lead)

**Journey Title:** From Legacy Auth Migration Decision to Stable Production Deployment

---

### Stage 1 — Internal Problem Recognition

|  |  |
| --- | --- |
| **Trigger** | Daniel's biggest enterprise customer sends a written requirement: SSO via SAML or they won't renew. Firebase Auth cannot support this. |
| **Actions** | Escalates to VP of Product, opens a formal platform evaluation, creates an internal briefing document |
| **Touchpoints** | Internal Slack, Jira, engineering team planning session |
| **Thoughts** | *"We have 6 months before renewal. This migration has to go perfectly or we lose $400K ARR."* |
| **Emotions** | Pressured, responsible, risk-aware |
| **Pain Points** | Internal stakeholders underestimate migration complexity; timeline pressure from business side |
| **Opportunity for Qeet ID** | "Migrate from Firebase Auth" landing page and dedicated migration guide — the highest-intent search query Daniel will run |

---

### Stage 2 — Vendor Shortlisting

|  |  |
| --- | --- |
| **Trigger** | Daniel runs searches for "Firebase Auth migration SAML SSO" and finds Qeet ID alongside Auth0 on the shortlist. |
| **Actions** | Builds a feature comparison matrix, reviews pricing at 200K MAUs, sends evaluation RFPs to Auth0 and Qeet ID |
| **Touchpoints** | Qeet ID website, pricing page, feature documentation, RFP response from sales team |
| **Thoughts** | *"Auth0 is proven but expensive. Qeet ID is newer but cheaper — is it mature enough for us?"* |
| **Emotions** | Analytical, skeptical of new vendors, price-conscious |
| **Pain Points** | Qeet ID perceived as less battle-tested than Auth0; unclear enterprise references; sales response time critical |
| **Opportunity for Qeet ID** | Case studies from comparable mid-market customers, rapid enterprise sales response, SOC 2 report in the first email |

---

### Stage 3 — Technical Deep Dive

|  |  |
| --- | --- |
| **Trigger** | Daniel assigns a senior engineer to run a technical POC migration of 1,000 test users from Firebase to Qeet ID. |
| **Actions** | Tests user import API, validates SAML configuration with their enterprise customer's Okta instance, stress tests session management at scale |
| **Touchpoints** | Qeet ID migration documentation, REST API, SAML configuration guide, technical support channel |
| **Thoughts** | *"If the user import works cleanly and SAML works in under a day, this is the right choice."* |
| **Emotions** | Technical, detail-oriented, looking for blockers |
| **Pain Points** | Missing Firebase-specific migration guide, SAML configuration errors without clear error messages, slow technical support response |
| **Opportunity for Qeet ID** | Firebase Auth → Qeet ID migration tool + step-by-step guide, SAML config wizard with real-time validation, dedicated technical support channel for enterprise POCs |

---

### Stage 4 — Security & Compliance Review

|  |  |
| --- | --- |
| **Trigger** | Daniel's security team asks for evidence of Qeet ID's security posture before approving the migration. |
| **Actions** | Requests SOC 2 report, reviews Qeet ID Guard features, asks about data residency, reviews breach notification policy |
| **Touchpoints** | Qeet ID security documentation page, enterprise sales contact, SOC 2 report |
| **Thoughts** | *"I need to be able to hand this to our CISO and have her sign off. If the SOC 2 report is clean, I'm done with this evaluation."* |
| **Emotions** | Cautious, procedural — security approval is a binary gate |
| **Pain Points** | SOC 2 report not immediately available, security documentation scattered across the website, no single security overview document |
| **Opportunity for Qeet ID** | Security Trust Center — one page with SOC 2 report download, pen test summary, data residency details, and incident response policy |

---

### Stage 5 — Migration Execution

|  |  |
| --- | --- |
| **Trigger** | Security approved. Daniel kicks off the full migration with a phased approach — 5% of users, then 20%, then 100% over 4 weeks. |
| **Actions** | Uses Qeet ID's user import API, runs parallel auth systems during cutover, monitors error rates and session failures |
| **Touchpoints** | Qeet ID admin dashboard, migration monitoring tools, Qeet ID support team |
| **Thoughts** | *"Every error during migration is a user who can't log in. I need this to be perfect."* |
| **Emotions** | Tense, methodical, hyper-focused on error monitoring |
| **Pain Points** | No migration progress dashboard, unclear error codes during import, support response slow during high-stakes phase |
| **Opportunity for Qeet ID** | Migration dashboard with import progress, error code reference guide, dedicated migration support SLA for enterprise customers |

---

### Stage 6 — Post-Migration Operations

|  |  |
| --- | --- |
| **Trigger** | Migration complete. 200,000 users are on Qeet ID. Enterprise customer SSO is live. Renewal signed. |
| **Actions** | Configures Qeet ID Guard rules for bot protection, sets up audit log export to their SIEM, reviews monthly MAU reporting |
| **Touchpoints** | Qeet ID admin dashboard, Guard configuration, audit log SIEM integration |
| **Thoughts** | *"Now I need to make sure this is stable and my team can operate it without needing me."* |
| **Emotions** | Relieved, shifting to operational confidence |
| **Pain Points** | Guard configuration is complex without guidance, SIEM integration requires custom work, no runbook template for the team |
| **Opportunity for Qeet ID** | SIEM integration guide (Splunk, Sentinel, Datadog), Guard configuration templates for common threat profiles, team operations runbook template |

---

### 9.4 Journey Map — Sandra (Enterprise IT Admin)

**Journey Title:** From Integration Requirements to Fully Federated Enterprise Deployment

---

### Stage 1 — Requirements Receipt

|  |  |
| --- | --- |
| **Trigger** | Sandra receives a requirement from her Director: the new customer-facing application needs a CIAM layer. It must federate with Entra ID and support SCIM provisioning. |
| **Actions** | Documents requirements, checks existing vendor relationships, is handed a shortlist by the procurement team including Qeet ID |
| **Touchpoints** | Internal procurement brief, Qeet ID enterprise sales contact |
| **Thoughts** | *"This has to connect to our existing Entra ID directory. If it can't, we're done before we start."* |
| **Emotions** | Systematic, requirement-focused |
| **Pain Points** | Unclear whether Qeet ID has been formally evaluated — she's being asked to assess a vendor she hasn't heard of |
| **Opportunity for Qeet ID** | Enterprise sales materials with Microsoft Entra ID integration reference architecture, SCIM 2.0 compatibility documentation visible upfront |

---

### Stage 2 — Technical Compatibility Assessment

|  |  |
| --- | --- |
| **Trigger** | Sandra reviews Qeet ID's Connect documentation for SAML federation with Entra ID. |
| **Actions** | Checks SAML 2.0 attribute mapping documentation, verifies SCIM 2.0 support with their SCIM schema requirements, calls the Qeet ID enterprise team to ask specific integration questions |
| **Touchpoints** | Qeet ID Connect documentation, SCIM documentation, enterprise sales engineer call |
| **Thoughts** | *"If the SAML attribute mapping can handle our custom attributes and SCIM can match our AD schema, this will work."* |
| **Emotions** | Technical, precise — looking for specific protocol details, not marketing |
| **Pain Points** | Generic protocol documentation without Entra ID-specific configuration steps, sales team unable to answer deep technical protocol questions |
| **Opportunity for Qeet ID** | Dedicated "Qeet ID + Microsoft Entra ID" integration guide with attribute mapping examples; pre-sales solutions engineer who can answer technical protocol questions directly |

---

### Stage 3 — Security Approval Gate

|  |  |
| --- | --- |
| **Trigger** | Sandra escalates to Omar (CISO) for security sign-off. Omar requests the SOC 2 report, pen test summary, and data residency documentation. |
| **Actions** | Submits the Qeet ID security documentation package to the CISO, answers follow-up questions, facilitates a security review meeting |
| **Touchpoints** | Qeet ID Security Trust Center, CISO review meeting |
| **Thoughts** | *"My job is to get Omar everything he needs to say yes. If any document is missing, this stalls for months."* |
| **Emotions** | Collaborative internally, somewhat dependent on Qeet ID's responsiveness |
| **Pain Points** | Any missing compliance documentation causes indefinite delay — data residency ambiguity is a common blocker for EU organizations |
| **Opportunity for Qeet ID** | Security Trust Center with everything in one place — SOC 2, pen test executive summary, data residency commitment by region, DPA template, incident response overview |

---

### Stage 4 — Pilot Deployment

|  |  |
| --- | --- |
| **Trigger** | Security approved. Sandra configures Qeet ID in a test environment and runs a pilot with 100 users from one department. |
| **Actions** | Configures SAML federation with Entra ID, sets up SCIM provisioning, tests onboarding/offboarding user lifecycle, verifies audit logs appear correctly |
| **Touchpoints** | Qeet ID Connect admin configuration, Entra ID admin portal, Qeet ID audit log viewer |
| **Thoughts** | *"I need SCIM to automatically disable users when I deprovision them in Entra. That's my core test."* |
| **Emotions** | Methodical, detail-oriented, testing specific failure modes |
| **Pain Points** | SCIM provisioning delay or sync errors, attribute mapping errors surfaced only at runtime, audit logs not capturing expected events |
| **Opportunity for Qeet ID** | SCIM sync status dashboard, real-time provisioning event log, pilot deployment support from a dedicated Qeet ID integration engineer |

---

### Stage 5 — Full Deployment & Handoff

|  |  |
| --- | --- |
| **Trigger** | Pilot successful. Sandra deploys to all 5,000 CIAM users and hands daily operations to her level-2 IT team. |
| **Actions** | Writes internal operations runbook, trains L2 team on Qeet ID admin console, sets up monitoring alerts |
| **Touchpoints** | Qeet ID admin dashboard, operations documentation, monitoring and alerting configuration |
| **Thoughts** | *"My team needs to be able to handle common issues without escalating to me."* |
| **Emotions** | Shifting to operational assurance — wants self-sufficient team operations |
| **Pain Points** | No role-based admin console permissions (too much access for L2 staff), complex alert configuration, no internal operations guide template |
| **Opportunity for Qeet ID** | Granular admin role permissions (L1/L2/L3 tiers), operations runbook template, pre-configured monitoring alert templates |

---

### 9.5 Journey Map — Omar (Enterprise Security Officer)

**Journey Title:** From Security Evaluation Gate to Signed Security Addendum

---

### Stage 1 — Security Evaluation Trigger

|  |  |
| --- | --- |
| **Trigger** | Omar is notified by Sandra that Qeet ID is being evaluated as the CIAM layer. He schedules a formal vendor security review. |
| **Actions** | Sends Qeet ID's enterprise team a security questionnaire (VSQ), requests the SOC 2 report, schedules a security architecture call |
| **Touchpoints** | Vendor Security Questionnaire response, Qeet ID security team, SOC 2 report |
| **Thoughts** | *"I'll give them 48 hours to respond. The speed and completeness of that response tells me a lot about how they operate."* |
| **Emotions** | Evaluative, unimpressed by marketing — wants evidence |
| **Pain Points** | Slow VSQ response, incomplete answers, missing documentation |
| **Opportunity for Qeet ID** | Pre-populated VSQ response document ready to send within 24 hours, dedicated security team contact for enterprise evaluations, SOC 2 report available immediately upon NDA |

---

### Stage 2 — Architecture & Protocol Review

|  |  |
| --- | --- |
| **Trigger** | Omar's security architect reviews Qeet ID's security architecture documentation. |
| **Actions** | Reviews authentication flow diagrams, encryption standards, token lifecycle management, passkey implementation, API security model |
| **Touchpoints** | Qeet ID security architecture documentation, technical whitepaper |
| **Thoughts** | *"I want to see zero-trust assumptions baked in, not bolted on. And I want to see passkey enforcement, not just passkey support."* |
| **Emotions** | Expert-level scrutiny — looking for architectural integrity, not feature lists |
| **Pain Points** | Marketing-heavy security documentation without technical depth, missing architecture diagrams, passkeys treated as an optional feature |
| **Opportunity for Qeet ID** | Technical security whitepaper (written for CISOs), architecture diagrams with data flow and trust boundary annotations, passkey-first architecture documented as a design principle |

---

### Stage 3 — Compliance Documentation Review

|  |  |
| --- | --- |
| **Trigger** | Omar reviews the SOC 2 Type I report and requests the penetration testing executive summary. |
| **Actions** | Reviews SOC 2 controls against his organization's control requirements, identifies any exceptions or qualified opinions, forwards to his compliance team |
| **Touchpoints** | SOC 2 report, pen test executive summary, Qeet ID security team for clarifications |
| **Thoughts** | *"No exceptions in the audit report is the baseline. Any qualified opinion goes into a risk register and requires compensating controls."* |
| **Emotions** | Forensic — reading compliance documents line by line |
| **Pain Points** | Qualified opinions in the audit without compensating controls documented, pen test findings without clear remediation evidence |
| **Opportunity for Qeet ID** | Clean SOC 2 report with zero qualified opinions, pen test remediation summary showing all critical and high findings closed before report publication |

---

### Stage 4 — Contract & Legal Negotiation

|  |  |
| --- | --- |
| **Trigger** | Omar passes the security evaluation. He hands to legal for DPA and security addendum negotiation. |
| **Actions** | Reviews Qeet ID's standard DPA, negotiates breach notification timelines (72 hours is baseline), confirms data residency commitments, approves security addendum |
| **Touchpoints** | Qeet ID legal team, DPA template, security addendum |
| **Thoughts** | *"72-hour breach notification is GDPR minimum. I want 48. And I want data residency in the EU committed contractually, not just described in documentation."* |
| **Emotions** | Precise, contractually focused — this is risk transfer |
| **Pain Points** | Inflexible DPA terms, no EU data residency contractual commitment, vague breach notification language |
| **Opportunity for Qeet ID** | Flexible DPA terms for enterprise customers, EU data residency contractual commitment available, security addendum template pre-approved by legal to accelerate negotiation |

---

### Stage 5 — Ongoing Security Governance

|  |  |
| --- | --- |
| **Trigger** | Contract signed. Omar sets up an annual security review cadence with Qeet ID. |
| **Actions** | Schedules annual security review, subscribes to Qeet ID's security advisory notifications, sets up audit log export to Splunk |
| **Touchpoints** | Qeet ID security advisory mailing list, audit log SIEM integration, annual security review meeting |
| **Thoughts** | *"I need to know about CVEs and incidents before my team discovers them in the news."* |
| **Emotions** | Satisfied with initial approval, now in monitoring mode |
| **Pain Points** | No proactive security advisory program, SIEM integration requires professional services, annual review not offered proactively by Qeet ID |
| **Opportunity for Qeet ID** | Proactive security advisory program (CVE notifications, incident updates before public disclosure), Splunk and Sentinel integration guides, annual enterprise security review offered as a standard enterprise benefit |

---

### 10. Persona-to-Product Mapping

| Persona | Primary Pain | Key Qeet ID Solution | Most Critical Feature at Adoption |
| --- | --- | --- | --- |
| Arjun — Solo Developer | Time to working auth | Free tier + <10 min quickstart | Social login & Next.js SDK |
| Maya — Startup CTO | Platform longevity & B2B complexity | Multi-tenancy + RBAC + SAML when needed | Multi-tenancy architecture + RBAC |
| Daniel — Mid-Market Eng. Lead | Migration risk + enterprise protocol gaps | Migration tool + SAML + Qeet ID Guard | Firebase Auth migration guide + SAML |
| Sandra — Enterprise IT Admin | Entra ID federation + SCIM automation | Qeet ID Connect + SCIM 2.0 | SAML federation + SCIM provisioning |
| Omar — CISO | Security posture + compliance evidence | SOC 2 + Qeet ID Guard + Security Trust Center | SOC 2 report + pen test summary |

---

### 11. Design Implications for Phase 3 (UI/UX)

| Persona | Key Design Requirement |
| --- | --- |
| Arjun | Homepage must show a working code snippet within the first scroll. Pricing must be visible without clicking. |
| Maya | Documentation must include a B2B multi-tenancy architecture guide. SDK GitHub repos must be clean and well-starred. |
| Daniel | A dedicated "Migrations" section in documentation — Firebase, Cognito, Auth0 migration guides each as first-class content. |
| Sandra | SAML and SCIM configuration flows in the admin dashboard must have step-by-step wizards with real-time validation. |
| Omar | A standalone Security Trust Center page — SOC 2 report, pen test summary, data residency map, DPA template, all downloadable in one place. |

---

### 12. Go-To-Market Messaging Alignment

| Persona | Primary Message | Tone |
| --- | --- | --- |
| Arjun — Solo Developer | *"Auth in 10 minutes. Free until you're successful."* | Direct, fast, no-fluff |
| Maya — Startup CTO | *"Start free. Scale to enterprise. Never migrate again."* | Strategic, confidence-building |
| Daniel — Mid-Market Eng. Lead | *"Migration-ready. Enterprise-certified. Built for teams like yours."* | Credible, risk-reducing |
| Sandra — Enterprise IT Admin | *"Federate everything. Automate provisioning. Sleep at night."* | Operational, reliability-focused |
| Omar — Enterprise Security Officer | *"Security is not a feature at Qeet ID. It is the product."* | Authoritative, evidence-based |

---

### 13. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Product Manager |  |  |  |
| UX Designer |  |  |  |
| CTO |  |  |  |
| Marketing Lead |  |  |  |
| Sales Lead |  |  |  |
| CEO / Founder |  |  |  |

---

*This document is version controlled. Personas and journey maps are living documents — they must be reviewed and updated after each round of beta user research, customer interviews, and post-launch usability findings. Any significant market shift or new customer segment discovery requires a formal persona revision submitted to the Product Manager.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*

---