import { describe, expect, it } from 'vitest';
import {
  generateEd25519KeyPair,
  Headers,
  parseEd25519PublicKey,
  parseSignatureHeaders,
  signRequest,
  verifyRequestSignature,
} from '@agenttrust/identity';

const CRED = `akc_${'a'.repeat(32)}`;
const NOW = new Date('2026-10-22T12:00:00Z');

function signed(body = '{"amountCents":50000}', overrides: Partial<Parameters<typeof signRequest>[0]> = {}) {
  const keys = generateEd25519KeyPair();
  const headers = signRequest({
    credentialId: CRED,
    privateKeyPem: keys.privateKeyPem,
    method: 'POST',
    path: '/v1/authorizations',
    body,
    now: NOW,
    ...overrides,
  });
  const parsed = parseSignatureHeaders((n) => headers[n]);
  if (!parsed.ok) throw new Error(parsed.reason);
  return { keys, headers, parsed: parsed.value, publicKey: parseEd25519PublicKey(keys.publicKeyPem) };
}

describe('agent request signing', () => {
  it('verifies a correctly signed request', () => {
    const { parsed, publicKey } = signed();
    expect(verifyRequestSignature({ publicKey, method: 'POST', path: '/v1/authorizations', rawBody: '{"amountCents":50000}', headers: parsed, now: NOW }))
      .toEqual({ ok: true });
  });

  it('rejects a modified body (e.g. amount changed in transit)', () => {
    const { parsed, publicKey } = signed();
    const r = verifyRequestSignature({ publicKey, method: 'POST', path: '/v1/authorizations', rawBody: '{"amountCents":500000}', headers: parsed, now: NOW });
    expect(r.ok).toBe(false);
  });

  it('rejects a different method or path', () => {
    const { parsed, publicKey } = signed();
    const body = '{"amountCents":50000}';
    expect(verifyRequestSignature({ publicKey, method: 'POST', path: '/v1/transactions/execute', rawBody: body, headers: parsed, now: NOW }).ok).toBe(false);
    expect(verifyRequestSignature({ publicKey, method: 'PUT', path: '/v1/authorizations', rawBody: body, headers: parsed, now: NOW }).ok).toBe(false);
  });

  it('rejects signatures from a different key (forged identity)', () => {
    const { parsed } = signed();
    const other = parseEd25519PublicKey(generateEd25519KeyPair().publicKeyPem);
    expect(verifyRequestSignature({ publicKey: other, method: 'POST', path: '/v1/authorizations', rawBody: '{"amountCents":50000}', headers: parsed, now: NOW }).ok).toBe(false);
  });

  it('rejects stale or future timestamps', () => {
    const { parsed, publicKey } = signed();
    const later = new Date(NOW.getTime() + 301_000);
    const r = verifyRequestSignature({ publicKey, method: 'POST', path: '/v1/authorizations', rawBody: '{"amountCents":50000}', headers: parsed, now: later });
    expect(r).toEqual({ ok: false, reason: 'timestamp outside allowed window' });
  });

  it('rejects missing or malformed headers', () => {
    expect(parseSignatureHeaders(() => undefined).ok).toBe(false);
    const { headers } = signed();
    const bad: Record<string, string> = { ...headers, [Headers.credential]: 'agt_pretending' };
    expect(parseSignatureHeaders((n) => bad[n]).ok).toBe(false);
  });

  it('refuses non-Ed25519 public keys', () => {
    expect(() => parseEd25519PublicKey('not a key')).toThrow();
  });
});
