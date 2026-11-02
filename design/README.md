# Design Artefacts — AW Shortlink

**Status:** draft design for review. **Not implemented, not user-validated.** Gate 9 ([#9](https://github.com/ahliweb/awshortlink-laravel/issues/9)) is NO-GO. Nothing in this folder is production code.

This folder holds the UI/UX and system-design outputs of workflow steps 1, 4, 5–8 (SPEC-04 [#4](https://github.com/ahliweb/awshortlink-laravel/issues/4) and related specs). Requirements, threats, ADRs and API contracts remain in [`../docs/`](../docs/README.md) and are the source of truth.

| Path | Deliverable | Workflow step | Issues |
| --- | --- | --- | --- |
| [system-design.md](system-design.md) | Detailed system design: C4 L1–L3, modules, request flows, state machines, PostgreSQL DDL/RLS sketch, ABAC rule DSL, API mapping and contract gaps, security controls, issue #1–#43 mapping, open decisions DES-001..015 | 1, 5–8 | #1–#43 |
| [ui-ux-design-system.md](ui-ux-design-system.md) | Design tokens with measured contrast, component inventory, screen ↔ API ↔ permission map for UI-001..018, interaction patterns, microcopy guide, WCAG 2.2 AA checklist, Filament 5 mapping | 4 | #4 |
| [mock-server/](mock-server/README.md) | Contract-driven OpenAPI 3.1 mock server (`server.mjs`) and Gate 9 contract verifier (`verify-contract.mjs`) | 8, 9 | #8, #9 |

## Note on the interactive prototype
The clickable HTML prototype and its screenshots used during the origin deployment contain agency-specific fictitious data and are intentionally not part of this upstream. Rebuild them from `ui-ux-design-system.md` and `docs/ui-ux.md` with your own fixtures if you need them.

## Related
- Specification index: [../docs/README.md](../docs/README.md)
- UX scope and validation protocol: [../docs/ui-ux.md](../docs/ui-ux.md), [../docs/user-research-plan.md](../docs/user-research-plan.md)
- Change history: [../CHANGELOG.md](../CHANGELOG.md)
