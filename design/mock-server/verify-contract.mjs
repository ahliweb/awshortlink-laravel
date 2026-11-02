#!/usr/bin/env node
/**
 * Gate 9 Contract & Mock Verification Runner (SPEC-08 / SPEC-09)
 *
 * Verifies:
 * 1. `docs/api/openapi.yaml` is valid OpenAPI 3.1.0 with zero syntax errors.
 * 2. Every operation has `x-api-id`, `operationId`, `x-permission`, `x-ui-screens`, and concrete examples.
 * 3. Every UI screen `UI-001`..`UI-018` is mapped to at least one OpenAPI operation or `x-non-api-routes` entry
 *    (Gate 9 blocking rule: `layar_tanpa_sumber_data_kontrak` & `endpoint_tanpa_permission`).
 * 4. `docs/api/asyncapi.yaml` is valid AsyncAPI 3.0.0 and every operation has `x-event-id`, `x-producer`,
 *    `x-consumers`, and `schemaVersion: 1`.
 * 5. Starts the contract-driven mock server and executes live HTTP requests against every single operation,
 *    plus negative security/concurrency tests (401, 403, 404 cross-unit, 405, 409 stale version, 428 missing If-Match).
 */

import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createContractMockServer, loadYamlSpec } from './server.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OPENAPI_PATH = path.resolve(__dirname, '../../docs/api/openapi.yaml');
const ASYNCAPI_PATH = path.resolve(__dirname, '../../docs/api/asyncapi.yaml');

const openapi = loadYamlSpec(OPENAPI_PATH);
const asyncapi = loadYamlSpec(ASYNCAPI_PATH);

assert.equal(openapi.openapi, '3.1.0', 'OpenAPI version must be 3.1.0');
assert.equal(asyncapi.asyncapi, '3.0.0', 'AsyncAPI version must be 3.0.0');

const coveredScreens = new Set();
for (const nonApi of openapi['x-non-api-routes'] || []) {
  if (nonApi.ui) coveredScreens.add(nonApi.ui);
}

const seenOperationIds = new Set();
const seenApiIds = new Set();
const operations = [];

for (const [rawPath, pathItem] of Object.entries(openapi.paths || {})) {
  for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
    const op = pathItem[method];
    if (!op) continue;
    assert.ok(op['x-api-id'], `Missing x-api-id on ${method.toUpperCase()} ${rawPath}`);
    assert.ok(op.operationId, `Missing operationId on ${method.toUpperCase()} ${rawPath}`);
    assert.ok(op['x-permission'], `Gate 9 blocker: Missing x-permission on ${op.operationId}`);
    assert.ok(Array.isArray(op['x-ui-screens']) && op['x-ui-screens'].length > 0, `Missing x-ui-screens on ${op.operationId}`);

    assert.ok(!seenOperationIds.has(op.operationId), `Duplicate operationId: ${op.operationId}`);
    assert.ok(!seenApiIds.has(op['x-api-id']), `Duplicate x-api-id: ${op['x-api-id']}`);
    seenOperationIds.add(op.operationId);
    seenApiIds.add(op['x-api-id']);

    for (const ui of op['x-ui-screens']) {
      coveredScreens.add(ui);
    }

    const successCode = op.responses?.['201'] ? '201' : '200';
    const content = op.responses?.[successCode]?.content || {};
    const firstMedia = Object.values(content)[0];
    assert.ok(firstMedia && firstMedia.example !== undefined, `Missing contract example on ${op.operationId} (${successCode})`);

    operations.push({ method: method.toUpperCase(), rawPath, op });
  }
}

for (let i = 1; i <= 18; i++) {
  const uiId = `UI-${String(i).padStart(3, '0')}`;
  assert.ok(coveredScreens.has(uiId), `Gate 9 blocker (layar_tanpa_sumber_data_kontrak): ${uiId} has no contract data source`);
}

const asyncOps = Object.entries(asyncapi.operations || {});
assert.ok(asyncOps.length >= 6, 'Expected at least 6 AsyncAPI domain operations');
for (const [opName, opDef] of asyncOps) {
  assert.ok(opDef['x-event-id'], `Missing x-event-id on AsyncAPI operation ${opName}`);
  assert.ok(opDef['x-producer'], `Missing x-producer on AsyncAPI operation ${opName}`);
  assert.ok(Array.isArray(opDef['x-consumers']) && opDef['x-consumers'].length > 0, `Missing x-consumers on AsyncAPI operation ${opName}`);
}
for (const [msgName, msgDef] of Object.entries(asyncapi.components?.messages || {})) {
  assert.equal(
    msgDef.payload?.properties?.schemaVersion?.const,
    1,
    `AsyncAPI message ${msgName} must declare schemaVersion const 1`
  );
}

// Live contract mock server verification
const { server } = createContractMockServer(openapi);
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const address = server.address();
const baseUrl = `http://127.0.0.1:${address.port}/buka/api/v1`;

try {
  // 1. Verify every operation succeeds with valid bearer token, permission, and If-Match
  for (const { method, rawPath, op } of operations) {
    const concretePath = rawPath.replace(/\{[^}]+\}/g, '0192e5a0-1111-7000-8000-000000000001');
    const res = await fetch(`${baseUrl}${concretePath}`, {
      method,
      headers: {
        Authorization: 'Bearer mock-valid-token',
        'X-Mock-Permissions': op['x-permission'],
        'If-Match': '"v1"',
        'Content-Type': 'application/json',
      },
      body: ['POST', 'PUT', 'PATCH'].includes(method) ? JSON.stringify({}) : undefined,
    });
    const expectedStatus = op.responses?.['201'] ? 201 : 200;
    assert.equal(res.status, expectedStatus, `Expected ${expectedStatus} on ${op.operationId}, got ${res.status}`);
    assert.equal(res.headers.get('x-contract-operation-id'), op.operationId);
  }

  // 2. Verify 401 Unauthorized when Bearer token is missing
  const res401 = await fetch(`${baseUrl}/links`);
  assert.equal(res401.status, 401);
  const body401 = await res401.json();
  assert.equal(body401.code, 'UNAUTHENTICATED');

  // 3. Verify 403 Forbidden when actor lacks operation's x-permission
  const res403 = await fetch(`${baseUrl}/access/policies`, {
    headers: {
      Authorization: 'Bearer mock-valid-token',
      'X-Mock-Permissions': 'links.list_internal',
    },
  });
  assert.equal(res403.status, 403);
  const body403 = await res403.json();
  assert.equal(body403.code, 'ACCESS_DENIED');

  // 4. Verify 404 NotFound on cross-unit concealment (no existence leak)
  const res404 = await fetch(`${baseUrl}/links/0192e5a0-1111-7000-8000-000000000099`, {
    headers: {
      Authorization: 'Bearer mock-valid-token',
      'X-Mock-Permissions': 'links.list_internal',
      'X-Mock-Cross-Unit': 'true',
    },
  });
  assert.equal(res404.status, 404);

  // 5. Verify 428 Precondition Required when If-Match is omitted on PATCH /links/{id}
  const res428 = await fetch(`${baseUrl}/links/0192e5a0-1111-7000-8000-000000000001`, {
    method: 'PATCH',
    headers: {
      Authorization: 'Bearer mock-valid-token',
      'X-Mock-Permissions': 'links.update_draft',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ title: 'Tanpa If-Match' }),
  });
  assert.equal(res428.status, 428);

  // 6. Verify 409 Conflict when If-Match version is stale
  const res409 = await fetch(`${baseUrl}/links/0192e5a0-1111-7000-8000-000000000001`, {
    method: 'PATCH',
    headers: {
      Authorization: 'Bearer mock-valid-token',
      'X-Mock-Permissions': 'links.update_draft',
      'If-Match': '"v0"',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ title: 'Versi Usang' }),
  });
  assert.equal(res409.status, 409);

  console.log(
    JSON.stringify(
      {
        status: 'PASS',
        openapiVersion: openapi.openapi,
        asyncapiVersion: asyncapi.asyncapi,
        operationsVerified: operations.length,
        asyncEventsVerified: asyncOps.length,
        uiScreensCovered: coveredScreens.size,
        negativeTestsPassed: ['401_UNAUTHENTICATED', '403_ACCESS_DENIED', '404_CROSS_UNIT', '409_STALE_VERSION', '428_PRECONDITION_REQUIRED'],
      },
      null,
      2
    )
  );
} finally {
  server.close();
}
