import { readFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { ReasonCode } from '@agenttrust/shared';
import { startServer, type TestServer } from './helpers';

/**
 * The public API reference (docs/developer/openapi.yaml) must not drift from
 * the running application: every documented operation must exist, every
 * $ref must resolve, and documented reason codes must be real.
 */
const spec = parse(readFileSync(path.resolve(__dirname, '../../../docs/developer/openapi.yaml'), 'utf8'));
const METHODS = ['get', 'post', 'put', 'patch', 'delete'] as const;

let server: TestServer;
beforeAll(async () => {
  server = await startServer();
});
afterAll(async () => {
  await server.close();
});

function registeredRoutes(): Set<string> {
  const router = (server.app.getHttpAdapter().getInstance() as { _router: { stack: { route?: { path: string; methods: Record<string, boolean> } }[] } })._router;
  const out = new Set<string>();
  for (const layer of router.stack) {
    if (!layer.route) continue;
    for (const [m, on] of Object.entries(layer.route.methods)) if (on) out.add(`${m.toUpperCase()} ${layer.route.path}`);
  }
  return out;
}

describe('OpenAPI reference', () => {
  it('is OpenAPI 3.1 with a version matching the SDKs', () => {
    expect(spec.openapi).toBe('3.1.0');
    expect(spec.info.version).toBe('0.4.0');
  });

  it('every documented operation is served by the application', () => {
    const routes = registeredRoutes();
    const missing: string[] = [];
    for (const [p, item] of Object.entries<Record<string, unknown>>(spec.paths)) {
      for (const m of METHODS) {
        if (!item[m]) continue;
        const key = `${m.toUpperCase()} ${p.replace(/\{(\w+)\}/g, ':$1')}`;
        if (!routes.has(key)) missing.push(key);
      }
    }
    expect(missing).toEqual([]);
  });

  it('every operation has a summary, tags, responses and an explicit security requirement', () => {
    for (const [p, item] of Object.entries<Record<string, any>>(spec.paths)) {
      for (const m of METHODS) {
        const op = item[m];
        if (!op) continue;
        const where = `${m.toUpperCase()} ${p}`;
        expect(op.summary, where).toBeTruthy();
        expect(op.tags?.length, where).toBeGreaterThan(0);
        expect(Object.keys(op.responses ?? {}).length, where).toBeGreaterThan(0);
        expect(Array.isArray(op.security), `${where} must declare security (use [] for public)`).toBe(true);
        for (const req of op.security) for (const name of Object.keys(req)) expect(spec.components.securitySchemes[name], `${where}: ${name}`).toBeDefined();
      }
    }
  });

  it('every $ref resolves', () => {
    const refs: string[] = [];
    const walk = (node: unknown) => {
      if (Array.isArray(node)) node.forEach(walk);
      else if (node && typeof node === 'object') {
        for (const [k, v] of Object.entries(node)) {
          if (k === '$ref' && typeof v === 'string') refs.push(v);
          else walk(v);
        }
      }
    };
    walk(spec);
    const unresolved = refs.filter((r) => {
      const parts = r.replace(/^#\//, '').split('/');
      let cur: any = spec;
      for (const part of parts) cur = cur?.[part];
      return cur === undefined;
    });
    expect(unresolved).toEqual([]);
  });

  it('documented reason codes exist', () => {
    const known = new Set(Object.values(ReasonCode));
    for (const code of spec.components.schemas.ReasonCode.examples as string[]) expect(known.has(code as never), code).toBe(true);
  });
});
