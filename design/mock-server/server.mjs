#!/usr/bin/env node
/**
 * Contract-driven OpenAPI 3.1 Mock Server for AW Shortlink (SPEC-08 / Workflow Step 8)
 *
 * Dynamically parses `docs/api/openapi.yaml` at startup (never hand-written routes)
 * and serves contract examples, enforcing:
 *   - Bearer authentication (`401 Unauthorized` when missing/invalid)
 *   - Permission check via `x-permission` (`403 Forbidden` when simulated role lacks permission)
 *   - Optimistic concurrency (`428 Precondition Required` when required `If-Match` is omitted;
 *     `409 Conflict` when `If-Match: "v0"` or `"stale"`)
 *   - RFC 9457 `application/problem+json` error payloads directly from `components.responses`
 */

import http from 'node:http';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_SPEC_PATH = path.resolve(__dirname, '../../docs/api/openapi.yaml');

export function loadYamlSpec(filePath = DEFAULT_SPEC_PATH) {
  const rawJson = execFileSync(
    'python3',
    ['-c', 'import sys, yaml, json; json.dump(yaml.safe_load(open(sys.argv[1], encoding="utf-8")), sys.stdout)', filePath],
    { encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 }
  );
  return JSON.parse(rawJson);
}

function compilePathRegex(openApiPath) {
  const paramNames = [];
  const pattern = openApiPath.replace(/\{([^}]+)\}/g, (_, name) => {
    paramNames.push(name);
    return '([^/]+)';
  });
  return { regex: new RegExp(`^${pattern}$`), paramNames };
}

function resolveRef(spec, refObj) {
  if (!refObj || typeof refObj !== 'object' || !refObj.$ref) return refObj;
  const parts = refObj.$ref.replace(/^#\//, '').split('/');
  let cur = spec;
  for (const part of parts) {
    cur = cur?.[part];
  }
  return cur;
}

export function createContractMockServer(spec = loadYamlSpec()) {
  const basePath = '/buka/api/v1';
  const routes = [];

  for (const [rawPath, pathItem] of Object.entries(spec.paths || {})) {
    const { regex, paramNames } = compilePathRegex(basePath + rawPath);
    const pathParams = (pathItem.parameters || []).map((p) => resolveRef(spec, p));

    for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
      const op = pathItem[method];
      if (!op) continue;
      const opParams = [...pathParams, ...(op.parameters || []).map((p) => resolveRef(spec, p))];
      routes.push({
        method: method.toUpperCase(),
        rawPath,
        regex,
        paramNames,
        op,
        opParams,
      });
    }
  }

  function sendProblem(res, statusKey, override = {}) {
    const respDef = spec.components?.responses?.[statusKey];
    const media = respDef?.content?.['application/problem+json'];
    const payload = { ...(media?.example || {}), ...override };
    const status = payload.status || 500;
    res.writeHead(status, {
      'Content-Type': 'application/problem+json; charset=utf-8',
      'Cache-Control': 'no-store',
    });
    res.end(JSON.stringify(payload));
  }

  const server = http.createServer((req, res) => {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    const pathname = url.pathname;

    if (pathname === '/__mock/meta' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(
        JSON.stringify({
          title: spec.info?.title,
          version: spec.info?.version,
          operationsCount: routes.length,
          operations: routes.map((r) => ({
            apiId: r.op['x-api-id'],
            operationId: r.op.operationId,
            method: r.method,
            path: basePath + r.rawPath,
            permission: r.op['x-permission'],
            screens: r.op['x-ui-screens'] || [],
          })),
        })
      );
      return;
    }

    const matchedByPath = routes.filter((r) => r.regex.test(pathname));
    if (matchedByPath.length === 0) {
      sendProblem(res, 'NotFound');
      return;
    }

    const route = matchedByPath.find((r) => r.method === req.method);
    if (!route) {
      res.writeHead(405, {
        Allow: matchedByPath.map((r) => r.method).join(', '),
        'Content-Type': 'application/problem+json; charset=utf-8',
      });
      res.end(
        JSON.stringify({
          type: 'https://links.example.org/buka/problems/method-not-allowed',
          title: 'Metode HTTP Tidak Diizinkan',
          status: 405,
          code: 'METHOD_NOT_ALLOWED',
          detail: `Metode ${req.method} tidak didukung pada endpoint ini.`,
          requestId: '0192e5a0-9999-7000-8000-000000000405',
        })
      );
      return;
    }

    // 1. Authentication check
    const authHeader = req.headers['authorization'] || '';
    if (!authHeader.startsWith('Bearer ') || authHeader.slice(7).trim() === '') {
      sendProblem(res, 'Unauthorized');
      return;
    }

    // 2. Permission check (`x-permission`)
    const requiredPerm = route.op['x-permission'];
    const mockPermsHeader = req.headers['x-mock-permissions'];
    if (mockPermsHeader !== undefined) {
      const granted = mockPermsHeader
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      if (!granted.includes(requiredPerm) && !granted.includes('*')) {
        sendProblem(res, 'Forbidden', {
          detail: `Izin '${requiredPerm}' diperlukan untuk operasi '${route.op.operationId}'.`,
        });
        return;
      }
    }

    // 3. Cross-unit simulation (`X-Mock-Cross-Unit: true` -> 404 NotFound per access-control.md)
    if (req.headers['x-mock-cross-unit'] === 'true') {
      sendProblem(res, 'NotFound');
      return;
    }

    // 4. Optimistic concurrency check (`If-Match`)
    const requiresIfMatch = route.opParams.some(
      (p) => p?.in === 'header' && p?.name?.toLowerCase() === 'if-match' && p?.required
    );
    if (requiresIfMatch) {
      const ifMatch = req.headers['if-match'];
      if (!ifMatch) {
        sendProblem(res, 'PreconditionRequired');
        return;
      }
      if (ifMatch === '"v0"' || ifMatch === 'stale') {
        sendProblem(res, 'Conflict');
        return;
      }
    }

    // 5. Select success response (`200` or `201`) from OpenAPI contract
    const statusCode = route.op.responses?.['201'] ? 201 : 200;
    const respObj = route.op.responses?.[String(statusCode)];
    const contentEntries = Object.entries(respObj?.content || {});
    const [contentType, mediaObj] = contentEntries[0] || ['application/json', { example: {} }];

    const headers = {
      'Content-Type': `${contentType}; charset=utf-8`,
      'Cache-Control': 'no-store',
      'X-Contract-Operation-Id': route.op.operationId,
      'X-Contract-Permission': requiredPerm,
    };
    if (respObj?.headers?.ETag) {
      headers['ETag'] = '"v2"';
    }

    res.writeHead(statusCode, headers);
    if (contentType === 'application/json') {
      res.end(JSON.stringify(mediaObj.example ?? {}));
    } else {
      res.end(String(mediaObj.example ?? ''));
    }
  });

  return { server, routes, spec };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 4010);
  const { server, routes } = createContractMockServer();
  server.listen(port, '127.0.0.1', () => {
    console.log(`AW Shortlink Contract Mock Server listening on http://127.0.0.1:${port}/buka/api/v1 (${routes.length} operations loaded from docs/api/openapi.yaml)`);
  });
}
