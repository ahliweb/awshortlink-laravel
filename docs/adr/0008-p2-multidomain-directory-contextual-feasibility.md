# ADR-0008: P2 Feasibility — Multi-Domain Branding, Public Program Directory & Non-Profiling Contextual Rules

- **Status:** Accepted (2026-11-01)
- **Date:** 2026-11-01
- **Issues:** `#35` (`P2-01`), `#36` (`P2-02`), `#37` (`P2-03`)
- **Deciders:** Engineering Lead, Security Reviewer, Product Owner

## Context
The P2 backlog defines three post-MVP feasibility & enhancement items:
1. **`#35` (`P2-01`):** Multi-domain and multi-tenant branding feasibility.
2. **`#36` (`P2-02`):** Link-in-bio / public program directory pages under `/buka/`.
3. **`#37` (`P2-03`):** Advanced contextual redirect rules without individual user profiling.

## Decision

### 1. Multi-Domain & Multi-Tenant Branding (`#35` — Deferred to v2.0, Schema-Ready via `links.namespace`)
- Physical table `shortlink.links` and `shortlink.reserved_slugs` already partition uniqueness by `(namespace, slug_normalized)` (`DEFAULT 'buka'`), and `shortlink.units` models organizational hierarchy via `shortlink.unit_closure`.
- Custom vanity domains (e.g., `s.example.org`) require wildcard/SAN TLS certificate automation and separate VirtualHost delegation outside the shared host (`HOST-01..17`). Therefore, v1.0 locks `namespace = 'buka'` under `https://links.example.org/buka/*`, while keeping `(namespace, slug_normalized)` schema-ready for future multi-domain expansion without destructive DDL migration.

### 2. Public Program Directory & Search under `/buka/` (`#36` — Implemented in v1.0)
- `GET /buka/` (`UI-008`) renders an accessible (`WCAG 2.2 AA`, `lang="id"`) public directory of active published links where `visibility = 'public'`, queried strictly through `shortlink.public_resolvable_links` via `awshortlink_resolver`.
- Links with `visibility = 'unlisted'`, `draft`, `submitted`, `suspended`, or `archived` are never listed in the public directory.

### 3. Contextual Redirect Rules Without Individual Profiling (`#37` — Constrained to Aggregate Channel Tags in v1.0)
- Per `ADR-0003` and `docs/threat-model-privacy.md`, device fingerprinting, GeoIP lookups, and per-visitor profiling on `/buka/{slug}` are **strictly prohibited** (`THR-005`).
- Channel differentiation is supported cleanly via campaign channel codes (`link_daily_stats.channel_code` and separate campaign slugs per distribution medium, e.g., poster QR vs social media), preserving deterministic single-target `302` resolution and zero synchronous network I/O.

## Consequences
- Zero unapproved network I/O or privacy leakage on `/buka/{slug}`.
- Public citizens can discover verified `public` health program links on `/buka/` while `unlisted` links remain direct-slug-only.

