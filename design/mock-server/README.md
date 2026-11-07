# Contract-Driven OpenAPI Mock Server & Verifier (`SPEC-08` / Step 8)

**Status:** Specification & contract verification tooling (not production code).

Per owner's internal cross-portfolio standard (the development-flow standard v2.1.1 Step 8 & Gate 9), the mock server is **generated directly from `docs/api/openapi.yaml`** at runtime rather than hand-coded, and serves the exact response schemas, headers (`ETag`), error taxonomy (`application/problem+json`), and `x-permission` bindings defined in the contract.

## Files
- [`server.mjs`](server.mjs) — Zero-dependency Node.js HTTP mock server that loads [`../../docs/api/openapi.yaml`](../../docs/api/openapi.yaml) dynamically and serves `/buka/api/v1/*` (`API-001`..`API-058`, 58 operations).
- [`verify-contract.mjs`](verify-contract.mjs) — Gate 9 automated contract verifier: validates OpenAPI 3.1.0 + AsyncAPI 3.0.0 completeness (`x-permission`, `UI-001..018` screen coverage, `x-producer`/`x-consumers`, `schemaVersion`) and runs live HTTP tests against all 58 operations plus negative security/concurrency cases (`401`, `403`, `404` cross-unit concealment, `409` stale `If-Match`, `428` missing `If-Match`).

## Usage

### 1. Run Gate 9 Contract & Mock Verification
```bash
node design/mock-server/verify-contract.mjs
```

### 2. Start the Mock Server for Step 11.1 Frontend Development
```bash
node design/mock-server/server.mjs
# Listening on http://127.0.0.1:4010/buka/api/v1
```

### 3. Simulated Headers Supported by Mock Server
- `Authorization: Bearer <token>` — required on all endpoints (`401` if omitted).
- `X-Mock-Permissions: links.list_internal,links.create_draft` — optional comma-separated permission override to test `403 Forbidden` handling when `x-permission` is not granted.
- `X-Mock-Cross-Unit: true` — simulates querying a resource owned by another organizational unit (`404 Not Found` per `access-control.md`).
- `If-Match: "v1"` — required on state-mutating operations (`428` if omitted; `409 Conflict` if set to `"v0"` or `"stale"`).
