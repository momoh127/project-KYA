import { randomBytes, type KeyObject } from 'node:crypto';
import { base64UrlDecode, base64UrlEncode, sha256Hex } from '@agenttrust/shared';
import { ed25519Sign, ed25519Verify, parseEd25519PrivateKey } from './keys';

/**
 * Agent request signing.
 *
 * Every API call made by an agent is signed with the agent's Ed25519 private
 * key. The signature covers the method, path (including query), a timestamp,
 * a single-use nonce, and the SHA-256 of the exact request body. The server:
 *   1. looks up the credential by id and loads the registered public key,
 *   2. rejects timestamps outside the allowed clock skew,
 *   3. rejects nonces it has seen before (replay protection; caller's job),
 *   4. verifies the signature over the reconstructed string.
 *
 * Design note: this is intentionally close to HTTP Message Signatures
 * (RFC 9421) so we can migrate to a standard header format later.
 */
export const SIGNATURE_SCHEME = 'AGENTTRUST-ED25519-V1';

export const Headers = {
  credential: 'x-agenttrust-credential',
  timestamp: 'x-agenttrust-timestamp',
  nonce: 'x-agenttrust-nonce',
  signature: 'x-agenttrust-signature',
} as const;

export interface StringToSignParts {
  method: string;
  path: string;
  timestamp: string;
  nonce: string;
  bodySha256: string;
}

export function buildStringToSign(p: StringToSignParts): string {
  return [SIGNATURE_SCHEME, p.method.toUpperCase(), p.path, p.timestamp, p.nonce, p.bodySha256].join('\n');
}

export interface SignRequestInput {
  credentialId: string;
  privateKeyPem: string | KeyObject;
  method: string;
  path: string;
  body: string;
  now?: Date;
  nonce?: string;
}

export function signRequest(input: SignRequestInput): Record<string, string> {
  const key = typeof input.privateKeyPem === 'string' ? parseEd25519PrivateKey(input.privateKeyPem) : input.privateKeyPem;
  const timestamp = String(Math.floor((input.now ?? new Date()).getTime() / 1000));
  const nonce = input.nonce ?? randomBytes(16).toString('hex');
  const toSign = buildStringToSign({
    method: input.method,
    path: input.path,
    timestamp,
    nonce,
    bodySha256: sha256Hex(input.body),
  });
  return {
    [Headers.credential]: input.credentialId,
    [Headers.timestamp]: timestamp,
    [Headers.nonce]: nonce,
    [Headers.signature]: base64UrlEncode(ed25519Sign(key, Buffer.from(toSign, 'utf8'))),
  };
}

/**
 * Signing callback. Lets the private key live outside the agent/LLM process
 * (sidecar, OS keychain, KMS/HSM): the caller hands over bytes, gets a signature.
 */
export type SignFn = (data: Buffer) => Buffer | Promise<Buffer>;

export async function signRequestWith(
  input: Omit<SignRequestInput, 'privateKeyPem'> & { sign: SignFn },
): Promise<Record<string, string>> {
  const timestamp = String(Math.floor((input.now ?? new Date()).getTime() / 1000));
  const nonce = input.nonce ?? randomBytes(16).toString('hex');
  const toSign = buildStringToSign({ method: input.method, path: input.path, timestamp, nonce, bodySha256: sha256Hex(input.body) });
  const signature = await input.sign(Buffer.from(toSign, 'utf8'));
  return {
    [Headers.credential]: input.credentialId,
    [Headers.timestamp]: timestamp,
    [Headers.nonce]: nonce,
    [Headers.signature]: base64UrlEncode(signature),
  };
}

export interface ParsedSignatureHeaders {
  credentialId: string;
  timestamp: number;
  nonce: string;
  signature: Buffer;
}

export type ParseResult =
  | { ok: true; value: ParsedSignatureHeaders }
  | { ok: false; reason: string };

export function parseSignatureHeaders(get: (name: string) => string | undefined): ParseResult {
  const credentialId = get(Headers.credential);
  const ts = get(Headers.timestamp);
  const nonce = get(Headers.nonce);
  const sig = get(Headers.signature);
  if (!credentialId || !ts || !nonce || !sig) return { ok: false, reason: 'missing signature headers' };
  if (!/^(akc|ags)_[a-f0-9]{32}$/.test(credentialId)) return { ok: false, reason: 'malformed credential id' };
  if (!/^\d{1,12}$/.test(ts)) return { ok: false, reason: 'malformed timestamp' };
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) return { ok: false, reason: 'malformed nonce' };
  let signature: Buffer;
  try {
    signature = base64UrlDecode(sig);
  } catch {
    return { ok: false, reason: 'malformed signature' };
  }
  if (signature.length !== 64) return { ok: false, reason: 'malformed signature' };
  return { ok: true, value: { credentialId, timestamp: Number(ts), nonce, signature } };
}

export interface VerifyRequestInput {
  publicKey: KeyObject;
  method: string;
  path: string;
  rawBody: Buffer | string;
  headers: ParsedSignatureHeaders;
  now?: Date;
  maxSkewSeconds?: number;
}

export function verifyRequestSignature(input: VerifyRequestInput): { ok: true } | { ok: false; reason: string } {
  const nowSec = Math.floor((input.now ?? new Date()).getTime() / 1000);
  const skew = input.maxSkewSeconds ?? 300;
  if (Math.abs(nowSec - input.headers.timestamp) > skew) {
    return { ok: false, reason: 'timestamp outside allowed window' };
  }
  const toSign = buildStringToSign({
    method: input.method,
    path: input.path,
    timestamp: String(input.headers.timestamp),
    nonce: input.headers.nonce,
    bodySha256: sha256Hex(input.rawBody),
  });
  const ok = ed25519Verify(input.publicKey, Buffer.from(toSign, 'utf8'), input.headers.signature);
  return ok ? { ok: true } : { ok: false, reason: 'invalid signature' };
}
