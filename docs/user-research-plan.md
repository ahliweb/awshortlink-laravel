# User Discovery / UX Validation Protocol (Steps 2 and 4)

**No interviews or usability tests have occurred as part of this repository work.** This plan defines evidence to collect prior to Gate 9.

## Sample and permission
Central site owner (1), unit admin (1-2), program editor (2), approver (1), analyst or communications officer (1), accessibility tester/representative citizen (1-2), hosting/security operator (1). Obtain institutional permission; recruit volunteers; avoid collecting health or personal details. Store consent and recordings securely outside source repository.

## Research questions
Who creates links? Who owns a slug when a program ends? What approval applies to .go.id vs external target? How often must a link be suspended? How does hosting staff change /buka route without SSH? What constitutes a meaningful analytics number for public education? What QR printing sizes? Existing brand guidelines and contact process?

## Usability sessions
Each participant completes tasks on interactive prototype:
T1 create safe public link; T2 respond to reserved/duplicate slug; T3 replace target with pending approval; T4 copy/download QR and confirm scanned value; T5 understand bot-vs-human counts; T6 suspend suspected malicious link; T7 locate expired/retired link; T8 identify external destination risk prompt.
Observe completion, time, errors, navigation confusion, accessibility difficulty, suggestions; record UXT-001..008. Compare against agreed pass thresholds before design acceptance.

## Outputs
Research notes, persona/JTBD, task flow and information architecture, prototype URL/version, usability test report with prioritized defects and re-test evidence, owner signoff. Link every validated UI screen to REQ, API and access policy IDs. No database/data contract freeze before step 4 validated.


## Extended IAM usability validation tasks
Include central admin granting a unit-scoped editor, unit admin being denied global admin permission, authenticated user viewing their effective roles and MFA, ABAC draft/simulation/review workflow, an auditor reviewing reason for denial without private data, and session/role revocation. Capture task results UXT-009..014, approval owner and affected role; validate UI-011..018 before Gate 9.
