# ADR-0003: Privacy-first aggregate-only click analytics by default

**Status:** Accepted (Gate 9 Approved 2026-11-01) | **Date:** 2026-10-31

## Context
QR scans may be performed by patients, minors and citizens. IP, full query, user-agent and detailed location create disproportionate privacy risk for public information redirects. Distinguishing bots from humans is difficult without identifying users; avoid false precision.

## Proposed decision
- Count only bounded anonymous aggregates (link, UTC day, optional declared channel, bot category); expose freshness and estimates explicitly.
- No full client IP, visitor fingerprint, cookie-based user tracking, medical identifier or raw referrer query stored in application metrics by default. No third-party tracking tags.
- If security investigation requires raw events, seek documented DPIA/processing basis, restricted schema, lifecycle/TTL and manual purge fallback when cron absent before enabling.
- Do not claim unique visitors == unique people; report total requests vs validated eligible clicks and suspected bot counts distinctly.
- Analytics writes must not block valid redirect; surface data-gap alerts when counters dropped, never fabricate backfill.

## Consequences
Reduced attribution granularity; stronger privacy and predictable workload. Report effectiveness measured by channel-level aggregates, not individuals. Requires stakeholder validation and legal retention approval at Gate 9.
