# Link Resolver Domain Algorithm Specification — v1.1.0-draft (Workflow 7 / SPEC-07)

**Locked decisions ([ADR-0007](adr/0007-resolved-design-decisions-des-001-015.md)):**
- **DES-003:** Suspended links return **HTTP `404 Not Found`** (identical safe generic page as unknown slug; zero signal to attacker). Intentionally archived or expired links with public tombstone (`retired_public_message = true`) return **HTTP `410 Gone`**.
- **DES-008:** Only `https://` destinations are allowed by default (`url_canonical ~ '^https://'`); cleartext `http://` is rejected unless a specific institutional host has a time-bounded DPO + Security Owner waiver in `destination_domain_rules`.
- **DES-011:** Direct atomic UPSERT into `shortlink.link_daily_stats` via `shortlink.record_click(uuid, smallint)` after HTTP response flush.
- **DES-013:** Slug charset is lowercase ASCII `[a-z0-9-]`, length `3..64`, no leading/trailing hyphen, no consecutive `--` (`^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])$`). Uppercase ASCII in incoming requests is canonicalized to lowercase; non-ASCII/Unicode slugs are rejected.

## Algorithm Catalog (`ALG-001..005`)
| ALG ID | Name | Responsibility | Mapped Tests |
| --- | --- | --- | --- |
| **ALG-001** | `SlugCanonicalizer` | ASCII lowercasing, length `3..64`, pattern `^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])$`, no `--`, reserved word rejection (`admin`, `api`, `login`, `logout`, `livewire`, `qr`, `preview`, `build`, `storage`, `assets`, `health`, `.env`, `artisan`, `laporan`) | `TST-001`, `TST-002` |
| **ALG-002** | `UrlCanonicalizer` + `DestinationRiskClassifier` | RFC 3986 / WHATWG parse, `https` only, IDNA UTS-46 host to lowercase punycode, reject userinfo/IP literals/non-default ports/dot-segments/sensitive query keys (`token`, `access_token`, `sig`, `signature`, `password`, `session`, `nik`, `no_rm`, `rm`, 16-digit NIK, email), classify `low` / `medium` / `high` / `forbidden` | `TST-003`, `TST-010` |
| **ALG-003** | `ResolveSlug` | Single bounded lookup on `shortlink.public_resolvable_links` via `awshortlink_resolver`, defensive URL invariant check, fail-closed `302` / `404` / `410` / `405` / `503` response with `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` | `TST-001`, `TST-009` |
| **ALG-004** | `AtomicPointerSwap` & `PermanentSlugReservation` | `If-Match` optimistic version check (`409 STALE_VERSION`), permanent `reserved_slugs` tombstone on first publication, deferred constraint `current_dest_same_link` atomic swap in same transaction as hash-chained `link_audit_events` | `TST-002`, `TST-007` |
| **ALG-005** | `BotClassifier` & `RecordClick` | In-memory request classification (`0 = human_eligible`, `1 = known_bot_ua`, `2 = prefetch_or_missing_headers`, `3 = synthetic_probe`), HEAD ignored, post-response `shortlink.record_click(link_id, bot_class)` UPSERT, $k=10$ small-cohort suppression (`DES-005`) | `TST-006`, `TST-014` |

## Canonical input and namespace (`ALG-001`)
Route: HTTPS GET/HEAD /buka/{slug}. Public admin/system routes take precedence; slug is **one path segment only**. Accept lowercase ASCII [a-z0-9] with internal hyphens, length 3..64, no leading/trailing hyphen; normalize uppercase ASCII input to lowercase before lookup and reject noncanonical/malformed input with 404. Reserved words: `admin`, `api`, `login`, `logout`, `livewire`, `qr`, `preview`, `build`, `storage`, `assets`, `health`, `.env`, `artisan`, `laporan`. Case policy: lowercase canonical, no accidental duplicate.

## Deterministic lookup algorithm (`ALG-003`)
1. Validate host against trusted host list; require HTTPS after trusted proxy checks. Validate method GET/HEAD; any other method returns `405 Method Not Allowed` (`Allow: GET, HEAD`); HEAD returns identical headers/status without incrementing click counters.
2. Parse and canonicalize slug via `ALG-001`; reject malformed or reserved segment safely with `404` (no DB lookup). Incoming query strings on `/buka/{slug}?...` are **never** forwarded to the destination and never logged.
3. Perform **single bounded** indexed lookup (`statement_timeout <= 1000ms`) on `shortlink.public_resolvable_links` by `(namespace, slug)` using role `awshortlink_resolver`. Fail closed (`503`) on DB unavailability; never use positive cache for suspended/mutated links.
4. Require view row `status = 'active'` (`links.status = 'active'`, `published_at <= now()`, `expires_at IS NULL OR expires_at > now()`, `current_destination_id` points to `status = 'current'` destination of same link). No fallback to unapproved or user-supplied URL.
5. Validate stored `target_url` defensively (`^https://`, no userinfo, no IP literal, no forbidden scheme). If corrupted/invalid, fail closed with `503` and emit integrity alert.
6. Respond `302 Found`, `Location: <target_url>`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`; HSTS at host level. Never emit `Set-Cookie` on public resolver responses.
7. For `GET` requests returning `302` (excluding `bot_class = 3` synthetic probe), invoke `shortlink.record_click(link_id, bot_class)` after flushing the HTTP response (`ALG-005`). Analytics write failure logs a degraded counter metric and never alters the HTTP 302 response.

## State and HTTP decision table (`ALG-003`, `DES-003` locked)
| Condition | View Status | HTTP Status | Response Behavior |
| --- | --- | --- | --- |
| Valid approved `active`, `published_at <= now()`, unexpired | `active` | **302 Found** | `Location: <canonical target>`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer` |
| Unknown slug / malformed / reserved word / `draft` / `submitted` | *(none)* | **404 Not Found** | Safe generic missing page (`UI-009`), no redirect |
| `scheduled` (`active` with `published_at > now()`) | `unavailable` | **404 Not Found** | No destination or schedule leakage |
| `suspended` (abuse / emergency stop, `DES-003`) | `unavailable` | **404 Not Found** | Identical safe 404 page; no `Location`, no suspension reason leaked |
| `archived` or `expired` (`expires_at <= now()`) with `retired_public_message = true` | `retired` | **410 Gone** | Branded expired/retired page (`UI-009`); no target URL exposed |
| `archived` or `expired` with `retired_public_message = false` | `unavailable` | **404 Not Found** | Safe generic 404 page |
| Database timeout / unavailable / defensive URL invariant failure | *(error)* | **503 Service Unavailable** | Safe temporary error page (`UI-009`), `Retry-After: 30`, ops alert |
| HTTP method not in `{GET, HEAD}` (e.g. `POST`, `PUT`, `DELETE`) | *(pre-check)* | **405 Method Not Allowed** | `Allow: GET, HEAD` |

## URL security rules
- Use standard PHP URL parsing plus strict canonicalization (scheme, IDNA/domain, normalized port/host, forbid embedded user/pass). Do NOT validate only by regex. Destination policy evaluated at draft submission AND approval AND each destination change.
- Validation should catch open redirect to malicious sites even if target is syntactically valid: institutional domain allowlist or reviewer approval with official link ownership proof and expiry.
- Any optional server-side link checker follows OWASP SSRF rules: resolve host to public IP, deny loopback/private/link-local/metadata, inspect every redirect hop and DNS rebinding, restrict egress, timeout; if safe egress cannot be guaranteed, **disable checker**. No HEAD/GET target fetch during public redirect.
- No raw click query/url/IP/cookies in analytics/logs; content of query may include sensitive values; redact host and path as necessary.
- No 301/308 for dynamic links because cached permanent redirect may bypass suspend/change.

## Concurrency/idempotency and revisions
- A link with published slug has irreversible reservation. Creating link uses DB uniqueness and transaction; conflicts produce 409.
- Destination edit creates version n+1; old approved version remains active until approval transaction swaps pointer. Never allow public access to unapproved revision.
- Concurrent update uses expected_version; mismatch 409. Submission and approval bind to immutable proposed version.
- Archive/suspend enforce immediate authoritative lookup; cache purge/negative cache rules tested.
- Link event capture uses aggregate atomic increments or deduplicated bounded queue; never claim precise unique users.

## Required edge-case tests & Deterministic Test Vectors (`TV-001..024`)
| Vector ID | Algorithm | Input / Scenario | Expected Output / Verdict | HTTP / Code |
| --- | --- | --- | --- | --- |
| **TV-001** | `ALG-001` | `GET /buka/EVENT-62` (active link `event-62`) | Canonical slug `event-62` → resolves active target | `302 Found` |
| **TV-002** | `ALG-001` | `GET /buka/ab` (length 2 < min 3) | Rejected before DB query | `404 Not Found` |
| **TV-003** | `ALG-001` | `GET /buka/-event62` or `/buka/event62-` or `/buka/event--62` | Rejected (leading/trailing/double hyphen) | `404 Not Found` |
| **TV-004** | `ALG-001` | `GET /buka/admin` or `/buka/livewire` or `/buka/.env` | Reserved slug / system route guard | `404` (or admin route) |
| **TV-005** | `ALG-001` | `GET /buka/kesehatan-ії` (Cyrillic/homograph non-ASCII) | Rejected (`DES-013` ASCII only) | `404 Not Found` |
| **TV-006** | `ALG-002` | `https://links.example.org/info/../jadwal?utm_source=ig#top` | Canonical `https://links.example.org/jadwal?utm_source=ig`, risk=`low` | `200 OK` (valid) |
| **TV-007** | `ALG-002` | `http://links.example.org/info` (cleartext `http`) | Blocked (`SCHEME_NOT_HTTPS`, `DES-008`) | `422 Unprocessable` |
| **TV-008** | `ALG-002` | `javascript:alert(1)` or `data:text/html,...` or `//evil.example/phish` | Blocked (`UNSAFE_SCHEME_OR_RELATIVE`) | `422 Unprocessable` |
| **TV-009** | `ALG-002` | `https://admin:secret@example.org/` | Blocked (`EMBEDDED_CREDENTIALS`) | `422 Unprocessable` |
| **TV-010** | `ALG-002` | `https://127.0.0.1/admin` or `https://169.254.169.254/latest/meta-data` or `https://[::1]/` | Blocked (`IP_LITERAL_FORBIDDEN`) | `422 Unprocessable` |
| **TV-011** | `ALG-002` | `https://links.example.org:8443/panel` | Blocked (`NON_STANDARD_PORT`) | `422 Unprocessable` |
| **TV-012** | `ALG-002` | `https://simrs.example.go.id/pasien?nik=6201011234560001` or `?no_rm=12345` | Blocked (`PROHIBITED_PII_OR_TOKEN_QUERY`, `THR-004`) | `422 Unprocessable` |
| **TV-013** | `ALG-002` | `https://portal.Example.GO.ID/Path%7E1` | Canonical `https://portal.example.go.id/Path~1`, risk=`medium` (requires SoD approval) | `200 OK` (`medium`) |
| **TV-014** | `ALG-002` | `https://bit.ly/3xyz` (known URL shortener) | Blocked (`CHAINED_SHORTENER_FORBIDDEN`) | `422 Unprocessable` |
| **TV-015** | `ALG-003` | `GET /buka/event62?token=secret&redirect=https://evil.test` (active link) | Query dropped; `Location` is exact stored canonical URL; no query logged | `302 Found` |
| **TV-016** | `ALG-003` | `HEAD /buka/event62` (active link) | Same `302` + `Location` headers, `record_click` **not** called | `302 Found` |
| **TV-017** | `ALG-003` | `POST /buka/event62` | Rejected by method guard (`Allow: GET, HEAD`) | `405 Method Not Allowed` |
| **TV-018** | `ALG-003` | `GET /buka/skm` when link status is `suspended` (`DES-003`) | Returns generic safe 404 page; no `Location` header | `404 Not Found` |
| **TV-019** | `ALG-003` | `GET /buka/event61` when link is `archived` or `expires_at <= now()` (`retired_public_message=true`) | Returns branded retired page (`UI-009`) | `410 Gone` |
| **TV-020** | `ALG-003` | `GET /buka/event62` when PostgreSQL connection times out | Fail-closed safe temporary error page (`Retry-After: 30`) | `503 Service Unavailable` |
| **TV-021** | `ALG-004` | Archive published link `/buka/event62`, then attempt `createLink` with slug `event62` | Blocked by permanent `reserved_slugs` row (`SLUG_PERMANENTLY_RESERVED`, `THR-007`) | `409 Conflict` |
| **TV-022** | `ALG-004` | Active link `v1` has pending destination `v2` (`pending_review`); citizen requests `GET /buka/event62` | Resolves `v1` until `approveLink` atomically swaps `current_destination_id` to `v2` | `302 Found` (`v1`) |
| **TV-023** | `ALG-004` | Two editors submit `PATCH /links/{id}` with `If-Match: "v2"` concurrently | First succeeds (`v3`), second rejected (`STALE_VERSION`) | `200` then `409 Conflict` |
| **TV-024** | `ALG-005` | `GET /buka/event62` with `User-Agent: WhatsApp/2.24.1` or `Purpose: prefetch` | `302 Found` immediately; post-response increments `suspected_bot` (`bot_class > 0`), not `valid_clicks` | `302 Found` |

## Reference
OWASP Unvalidated Redirects; OWASP SSRF Prevention; RFC 9110 HTTP Semantics: https://www.rfc-editor.org/rfc/rfc9110.


## PostgreSQL resolver and RLS enforcement
Public anonymous resolver only reads a narrowly exposed current published link view/function using restricted read-only SQL role and approved RLS policy; it must not impersonate staff context or access audit, roles, users, drafts, approvals or private destinations. Authenticated changes and analytics views use Laravel RBAC+ABAC AND DB RLS with validated transaction-local context. Any stale/changed destination must not bypass immediate revocation. See postgresql-rls-design.md.
