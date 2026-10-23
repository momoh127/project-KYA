import type { KeyObject } from 'node:crypto';
import {
  base64UrlDecode,
  base64UrlEncode,
  canonicalJson,
  safeEqual,
  transactionFingerprint,
  type TransactionIntent,
} from '@agenttrust/shared';
import { ed25519Verify, type Signer } from '@agenttrust/identity';

/**
 * Transaction-bound authorization tokens.
 *
 * Format: compact JWS (RFC 7515) with EdDSA / Ed25519 (RFC 8037).
 * The token binds every parameter of the approved transaction. It is a
 * statement of permission for ONE exact transaction; it is single-use
 * (enforced by the execution gateway in the database) and short-lived.
 */
export const TOKEN_TYPE = 'agenttrust-authz+jws';

export interface AuthorizationClaims {
  iss: 'agenttrust';
  /** Authorization id; also the single-use identifier. */
  jti: string;
  org: string;
  agt: string;
  dlg: string;
  pol: string;
  pv: number;
  /** Transaction fingerprint (hash over all transaction parameters). */
  fp: string;
  sup: string | null;
  pd: string;
  amt: number;
  cur: string;
  po: string | null;
  inv: string | null;
  iat: number;
  exp: number;
  nonce: string;
}

interface JwsHeader {
  alg: 'EdDSA';
  typ: typeof TOKEN_TYPE;
  kid: string;
}

export function signAuthorizationToken(claims: AuthorizationClaims, signer: Signer): string {
  const header: JwsHeader = { alg: 'EdDSA', typ: TOKEN_TYPE, kid: signer.keyId };
  const encodedHeader = base64UrlEncode(canonicalJson(header));
  const encodedPayload = base64UrlEncode(canonicalJson(claims));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = signer.sign(Buffer.from(signingInput, 'ascii'));
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

export type VerifyTokenResult =
  | { ok: true; claims: AuthorizationClaims; kid: string }
  | { ok: false; reason: TokenRejection };

export type TokenRejection =
  | 'MALFORMED'
  | 'UNSUPPORTED_ALGORITHM'
  | 'UNKNOWN_KEY'
  | 'BAD_SIGNATURE'
  | 'EXPIRED'
  | 'NOT_YET_VALID';

export interface VerifyTokenOptions {
  resolveKey: (kid: string) => KeyObject | null;
  now?: Date;
  clockSkewSeconds?: number;
}

export function verifyAuthorizationToken(token: string, opts: VerifyTokenOptions): VerifyTokenResult {
  if (typeof token !== 'string' || token.length > 8192) return { ok: false, reason: 'MALFORMED' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'MALFORMED' };
  const [h, p, s] = parts as [string, string, string];

  let header: Partial<JwsHeader>;
  let claims: AuthorizationClaims;
  let signature: Buffer;
  try {
    header = JSON.parse(base64UrlDecode(h).toString('utf8'));
    claims = JSON.parse(base64UrlDecode(p).toString('utf8'));
    signature = base64UrlDecode(s);
  } catch {
    return { ok: false, reason: 'MALFORMED' };
  }

  // Never let the token choose the algorithm.
  if (header.alg !== 'EdDSA' || header.typ !== TOKEN_TYPE) return { ok: false, reason: 'UNSUPPORTED_ALGORITHM' };
  if (typeof header.kid !== 'string') return { ok: false, reason: 'MALFORMED' };
  const key = opts.resolveKey(header.kid);
  if (!key) return { ok: false, reason: 'UNKNOWN_KEY' };
  if (!ed25519Verify(key, Buffer.from(`${h}.${p}`, 'ascii'), signature)) {
    return { ok: false, reason: 'BAD_SIGNATURE' };
  }
  if (!isClaims(claims)) return { ok: false, reason: 'MALFORMED' };

  const now = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  const skew = opts.clockSkewSeconds ?? 30;
  if (claims.exp <= now) return { ok: false, reason: 'EXPIRED' };
  if (claims.iat > now + skew) return { ok: false, reason: 'NOT_YET_VALID' };
  return { ok: true, claims, kid: header.kid };
}

/**
 * Checks that a verified token authorizes exactly this transaction intent.
 * Returns the list of mismatching fields (empty = exact match).
 */
export function tokenMismatches(claims: AuthorizationClaims, intent: TransactionIntent): string[] {
  const mismatches: string[] = [];
  if (claims.org !== intent.organizationId) mismatches.push('organizationId');
  if (claims.agt !== intent.agentId) mismatches.push('agentId');
  if (claims.sup !== intent.supplierId) mismatches.push('supplierId');
  if (claims.pd !== intent.paymentDestinationFingerprint) mismatches.push('paymentDestination');
  if (claims.amt !== intent.amountCents) mismatches.push('amountCents');
  if (claims.cur !== intent.currency) mismatches.push('currency');
  if (claims.po !== intent.purchaseOrderId) mismatches.push('purchaseOrderId');
  if (claims.inv !== intent.invoiceId) mismatches.push('invoiceId');
  if (!safeEqual(claims.fp, transactionFingerprint(intent))) mismatches.push('fingerprint');
  return mismatches;
}

function isClaims(c: unknown): c is AuthorizationClaims {
  if (!c || typeof c !== 'object') return false;
  const o = c as Record<string, unknown>;
  const str = (k: string) => typeof o[k] === 'string';
  const strOrNull = (k: string) => typeof o[k] === 'string' || o[k] === null;
  const int = (k: string) => Number.isSafeInteger(o[k]);
  return (
    o.iss === 'agenttrust' &&
    str('jti') && str('org') && str('agt') && str('dlg') && str('pol') && int('pv') &&
    str('fp') && strOrNull('sup') && str('pd') && int('amt') && str('cur') &&
    strOrNull('po') && strOrNull('inv') && int('iat') && int('exp') && str('nonce')
  );
}
