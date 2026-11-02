# Master Blueprint v1.0.0-draft — AW Shortlink

**Vision:** accountable, trustworthy, fast official short-link and dynamic QR distribution platform. Initial institutional deployment at @@ORG_SHORT@@ with public path https://links.example.org/buka/. Operable without SSH if host supports PHP/DB/files/routing. **Status:** discovery; deployment routing not yet validated.

## Success outcomes (not vanity metrics)
1. Public official links remain stable when document destinations change; no slug reuse after publication.
2. Staff can create, approve and suspend a link with fully attributable audit history.
3. Public redirect follows safe, predictable HTTP behavior without analytics blocking.
4. Program owners can distinguish human click estimates vs bot traffic; no personal/health data processed.
5. Hosting can deploy/rollback safely without privileged shell and without impacting main site.

## Personas / system context
- Citizen or patient: follow a trusted public link or QR, understand when link is invalid or external.
- Editors and unit administrators: author and maintain approved links scoped by unit.
- Approver, analyst, auditor, central admin: review, report, monitor and manage safe policies.
- Existing organisation website / hosting panel: delegating /buka/* without changing other web paths.
- External destinations: government websites and institutionally approved sites, treated as untrusted content.

## C4 context
~~~mermaid
flowchart LR
    People[Citizen or official] --> Web[Main organisation website / reverse proxy]
    Web --> Prefix[/buka/* -> Laravel public front controller]
    Editor[Authorized staff] --> Admin[Filament panel]
    Prefix --> Core[Laravel Link Resolver]
    Admin --> Core
    Core --> DB[(PostgreSQL + mandatory RLS)]
    Core --> Target[Approved public destination]
    Core -.-> Analytics[Nonblocking click accumulator]
    Operator[Hosting operator] --> Deploy[Panel/SFTP release mechanism]
~~~

## Runtime and trust boundaries
Same Laravel application provides public redirect, admin and documented API; separate modules by route, service and policy. Public requests must never receive admin session/state. Server-side destination checker (if enabled) is in separate constrained job with deny-local-address policy; NEVER fetch a target during redirect. Data store is authoritative for state/permissions and audit. Admin accessible only through HTTPS, institutional identity controls, MFA policy and authorized roles.

## Deployment topology choices
A: dedicated Laravel app outside webroot + directory /buka/ public assets, webserver path delegation (preferred if proved). B: host/reverse proxy path dispatch to dedicated subdomain app, preserving external /buka/ URLs. C: isolate on separate approved host if host cannot meet PHP/Rewrite/permissions. Do not assume Cloudflare availability, SSH, symlinks or .htaccess support. Hosting owner must approve plan.

## Candidate stack
Laravel 13.x (PHP >=8.3), Filament 5.x and Livewire; Composer locked; secure PHP QR generation; Laravel Eloquent and migrations; PostgreSQL exclusively with mandatory RLS, managed Filament admin/user RBAC and ABAC policy modules. Database queue + cron only when verified. No persistent process requirement in production.

## Initial SLO proposal (not committed SLA)
- redirect gateway response p95 <=300ms measured from Indonesian probes excluding destination download; test under realistic host load.
- monthly availability >=99.9% proposed; define exclusions, synthetic probe, incident owner.
- database backup RPO <=15 minutes and service RTO <=4 hours **aspirational**, validate actual hosting backup capability before publishing.
- link suspend/effective-destination changes visible immediately on authoritative reads; forbid proxy/browser permanent caching for dynamic links.
- all security-relevant writes produce complete audit record or fail closed.
- redirect path tolerates unavailable analytics sink: maintain redirect where policy lookup still succeeds, measure dropped click events.

## Exclusions and non-goals
No anonymous link creation; no arbitrary external open-redirect platform; no tracking of individual citizens, patient or RME data; no marketing fingerprinting, browser push, AI feature or payment system in MVP. Redirect analytics are not clinical outcome metrics.

## Release plan
Phase 1 specs/host audit -> Gate 9 -> atomic issues -> frontend mock-first/backend/integration -> local CI & staging -> UAT -> Gate 15 human Go/No-Go -> production route cutover -> monitoring and rollback rehearsal.

## Open blockers
HOST-01 PHP versions/ext, DB and minimum privileges; HOST-02 front-controller /buka route rewrite & parent-site coexistence; HOST-03 storage outside webroot; HOST-04 cron/PHP CLI; HOST-05 secure panel transport; HOST-06 institutional domain/control approvals. See deployment-no-ssh.md and decision-log.md.


## Binding change 2026-10-31
The sole database is PostgreSQL across development, testing, staging and production. PHP pdo_pgsql, PostgreSQL service access, approved SQL migration/roles and backup without SSH are hard hosting gates. No database fallback. Role and permission management is a core P0 product feature for admin and authenticated user accounts: delegated unit scopes, ABAC policy versions and permission inspector. Laravel Policy/Gate + ABAC + PostgreSQL RLS all required; SQL runtime user must not be owner/BYPASSRLS. See ADR-0005/0006.
