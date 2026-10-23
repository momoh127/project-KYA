import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

export function hmacSha256Hex(secret: string | Buffer, data: string | Buffer): string {
  return createHmac('sha256', secret).update(data).digest('hex');
}

/** Constant-time comparison for hex/base64 strings of equal expected length. */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function base64UrlEncode(data: Buffer | string): string {
  return Buffer.from(data).toString('base64url');
}

export function base64UrlDecode(data: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(data)) {
    throw new TypeError('invalid base64url');
  }
  return Buffer.from(data, 'base64url');
}
