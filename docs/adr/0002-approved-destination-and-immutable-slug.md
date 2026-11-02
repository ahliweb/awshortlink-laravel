# ADR-0002: Approved destinations, permanent slug reservation and 302 redirects

**Status:** Accepted (Gate 9 Approved 2026-11-01) | **Date:** 2026-10-31

## Context
Official .go.id short URLs have high perceived trust; unchecked target changes can cause phishing. Printed QR codes may persist for years while target content changes. Browser-cached 301/308 would bypass future suspend or editing.

## Proposed decision
- Only authenticated authorized staff create links; publish right follows approved policy, external destinations require review and risk classification. MVP may allow authorized central admin to publish institutional allowlisted domains; full independent workflow is P1 (#27). High-risk external destinations **must not be published** before reviewer controls exist.
- URL canonicalization, allowed scheme, host and token/PII checks on every draft submit/change and publish; external content remains untrusted. No server-side target fetch during click.
- Once published, normalized slug is permanently reserved/tombstoned even if retired; namespaced unique DB constraint controls concurrency.
- Current approved destination version is pointer bound to link and owner, changed transactionally with audit. Unapproved proposed version never redirects.
- HTTP GET uses 302 Found by default, Cache-Control no-store. HEAD does not count as click. Suspend/expiry enforced on each authoritative lookup.
- No request query forwarding by default; later named allowlist requires DPIA/ADR.

## Alternatives rejected
Public anonymous shorten; arbitrary redirect; permanent redirect for editable link; published slug recycling; browser-only validation; cache without revocation proof.

## Consequences
Allows trusted dynamic QR at cost of approval friction and DB lookup. Performance tuning must preserve immediate revocation. Critical tests: collision, archive/reuse, concurrency, stale approval and wrong target. Final external domain policy owned by the organisation security officer at Gate 9.
