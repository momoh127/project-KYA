import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildStringToSign, parseEd25519PublicKey, parseSignatureHeaders, signRequest, verifyRequestSignature } from '@agenttrust/identity';
import { sha256Hex } from '@agenttrust/shared';

/**
 * Cross-language conformance: these committed vectors are reproduced byte for
 * byte by every SDK (see packages/sdk-python/tests/test_signing.py). If this
 * test fails, the wire format changed and every SDK must change with it.
 */
const file = JSON.parse(readFileSync(path.join(__dirname, 'vectors', 'request-signing.json'), 'utf8')) as {
  privateKeyPem: string;
  publicKeyPem: string;
  vectors: { name: string; method: string; path: string; body: string; timestamp: number; nonce: string; credentialId: string; bodySha256: string; stringToSign: string; headers: Record<string, string> }[];
};

describe('request-signing vectors (AGENTTRUST-ED25519-V1)', () => {
  for (const v of file.vectors) {
    it(`${v.name}: string-to-sign, headers and signature are reproduced exactly`, () => {
      expect(sha256Hex(v.body)).toBe(v.bodySha256);
      expect(buildStringToSign({ method: v.method, path: v.path, timestamp: String(v.timestamp), nonce: v.nonce, bodySha256: v.bodySha256 })).toBe(v.stringToSign);
      const headers = signRequest({ credentialId: v.credentialId, privateKeyPem: file.privateKeyPem, method: v.method, path: v.path, body: v.body, now: new Date(v.timestamp * 1000), nonce: v.nonce });
      expect(headers).toEqual(v.headers);
      const parsed = parseSignatureHeaders((n) => v.headers[n]);
      if (!parsed.ok) throw new Error(parsed.reason);
      const ok = verifyRequestSignature({ publicKey: parseEd25519PublicKey(file.publicKeyPem), method: v.method, path: v.path, rawBody: v.body, headers: parsed.value, now: new Date(v.timestamp * 1000) });
      expect(ok).toEqual({ ok: true });
    });
  }
});
