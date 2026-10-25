import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { INestApplication } from '@nestjs/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { loadConfig, signingKeyFromSeed } from '../src/config';

/** Hosted-sandbox deployment features: seed-derived signing key, developer portal, downloads. */
async function boot(overrides: Record<string, string | undefined>): Promise<{ app: INestApplication; baseUrl: string }> {
  const app = await createApp(loadConfig({ ...process.env, ...overrides }), { logger: false });
  await app.listen(0, '127.0.0.1');
  return { app, baseUrl: `http://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}` };
}

describe('signing key from seed (for hosts that can only generate random strings)', () => {
  const seed = 'x'.repeat(16) + 'a-high-entropy-generated-value-0123456789';

  it('derives the same valid Ed25519 key every time, and different seeds give different keys', () => {
    const pem = signingKeyFromSeed(seed);
    expect(signingKeyFromSeed(seed)).toBe(pem);
    expect(signingKeyFromSeed(`${seed}!`)).not.toBe(pem);
    const key = createPrivateKey(pem);
    expect(key.asymmetricKeyType).toBe('ed25519');
    const sig = sign(null, Buffer.from('m'), key);
    expect(verify(null, Buffer.from('m'), createPublicKey(key), sig)).toBe(true);
  });

  it('config requires exactly one key source', () => {
    expect(() => loadConfig({ ...process.env, AGENTTRUST_SIGNING_KEY_SEED: seed })).toThrow(/exactly one/);
    expect(() => loadConfig({ ...process.env, AGENTTRUST_SIGNING_KEY_PEM_B64: undefined })).toThrow(/exactly one/);
    const cfg = loadConfig({ ...process.env, AGENTTRUST_SIGNING_KEY_PEM_B64: undefined, AGENTTRUST_SIGNING_KEY_SEED: seed });
    expect(cfg.signingKeyPem).toBe(signingKeyFromSeed(seed));
  });

  it('the API boots and signs with a seed-derived key', async () => {
    const s = await boot({ AGENTTRUST_SIGNING_KEY_PEM_B64: undefined, AGENTTRUST_SIGNING_KEY_SEED: seed });
    try {
      expect((await fetch(`${s.baseUrl}/v1/health`)).status).toBe(200);
    } finally {
      await s.app.close();
    }
  });
});

describe('developer portal disabled by default', () => {
  it('/docs, /downloads and / are 404 unless AGENTTRUST_PUBLIC_DOCS=true', async () => {
    const s = await boot({ AGENTTRUST_PUBLIC_DOCS: 'false' });
    try {
      for (const p of ['/', '/docs', '/docs/quickstart', '/docs/openapi.yaml', '/downloads/agenttrust-sdk-0.4.0.tgz']) {
        expect((await fetch(`${s.baseUrl}${p}`, { redirect: 'manual' })).status, p).toBe(404);
      }
    } finally {
      await s.app.close();
    }
  });
});

describe('developer portal (hosted sandbox)', () => {
  let s: { app: INestApplication; baseUrl: string };
  const downloads = mkdtempSync(path.join(tmpdir(), 'agenttrust-dl-'));

  beforeAll(async () => {
    writeFileSync(path.join(downloads, 'agenttrust-sdk-0.4.0.tgz'), 'tarball');
    writeFileSync(path.join(downloads, 'agenttrust-0.4.0-py3-none-any.whl'), 'wheel');
    writeFileSync(path.join(downloads, '.env'), 'SECRET=1');
    writeFileSync(path.join(downloads, 'notes.txt'), 'private');
    s = await boot({ AGENTTRUST_PUBLIC_DOCS: 'true', AGENTTRUST_DOWNLOADS_DIR: downloads, AGENTTRUST_PUBLIC_URL: 'https://sandbox.example.test/' });
  });
  afterAll(async () => {
    await s.app.close();
  });

  const get = (p: string, headers: Record<string, string> = {}) => fetch(`${s.baseUrl}${p}`, { headers, redirect: 'manual' });

  it('root redirects to the portal; the portal lists pages and only published SDK artifacts', async () => {
    const root = await get('/');
    expect(root.status).toBe(302);
    expect(root.headers.get('location')).toBe('/docs');
    const html = await (await get('/docs')).text();
    expect(html).toContain('/docs/quickstart');
    expect(html).toContain('/docs/reference');
    expect(html).toContain('npm install https://sandbox.example.test/downloads/agenttrust-sdk-0.4.0.tgz');
    expect(html).toContain('pip install https://sandbox.example.test/downloads/agenttrust-0.4.0-py3-none-any.whl');
    expect(html).not.toContain('notes.txt');
    expect(html).not.toContain('.env');
    expect(html).toContain('no real money');
  });

  it('renders the Quickstart with the deployment URL substituted and links rewritten', async () => {
    const res = await get('/docs/quickstart');
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('<h1');
    expect(html).not.toContain('$BASE_URL');
    expect(html).toContain('https://sandbox.example.test/downloads/agenttrust-sdk-0.4.0.tgz');
    expect(html).toContain('href="/docs/integration-guide');
    expect((await get('/docs/integration-guide')).status).toBe(200);
    expect((await get('/docs/evaluation')).status).toBe(200);
  });

  it('serves the OpenAPI document pointed at this deployment', async () => {
    const yaml = await (await get('/docs/openapi.yaml')).text();
    expect(yaml).toContain('openapi: 3.1.0');
    expect(yaml).toContain('- url: https://sandbox.example.test');
    expect(yaml).not.toContain('http://localhost:4000');
    expect((await get('/docs/reference')).status).toBe(200);
  });

  it('downloads only allow-listed artifact names (no traversal, no other files)', async () => {
    expect((await get('/downloads/agenttrust-sdk-0.4.0.tgz')).status).toBe(200);
    for (const p of ['/downloads/.env', '/downloads/notes.txt', '/downloads/..%2F..%2Fpackage.json', '/downloads/agenttrust-sdk-9.9.9.tgz', '/docs/..%2F..%2F.env', '/docs/README']) {
      expect((await get(p)).status, p).toBe(404);
    }
  });
});

describe('developer portal URL fallback', () => {
  it('a forged Host header cannot inject markup (falls back to localhost)', async () => {
    const s = await boot({ AGENTTRUST_PUBLIC_DOCS: 'true', AGENTTRUST_PUBLIC_URL: undefined });
    try {
      const { request } = await import('node:http');
      const html = await new Promise<string>((resolve, reject) => {
        const req = request(`${s.baseUrl}/docs`, { headers: { host: '<script>alert(1)</script>' } }, (res) => {
          let body = '';
          res.on('data', (c) => (body += c));
          res.on('end', () => resolve(body));
        });
        req.on('error', reject);
        req.end();
      });
      expect(html).not.toContain('<script>alert(1)</script>');
      expect(html).toContain('http://localhost');
    } finally {
      await s.app.close();
    }
  });
});
