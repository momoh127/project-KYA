import type { KeyObject } from 'node:crypto';
import {
  authorizationFingerprint,
  base64UrlDecode,
  base64UrlEncode,
  canonicalJson,
  safeEqual,
  type AuthorizationBinding,
} from '@agenttrust/shared';
import { ed25519Verify, type Signer } from '@agenttrust/identity';

/**
 * Transaction-bound authorization tokens.
 *
 * Format: compact JWS (RFC 7515) with EdDSA / Ed25519 (RFC 8037).
 * The token binds the COMPLETE payment instruction (see AuthorizationBinding):
 * organization, agent, supplier + supplier-record version, payment rail,
 * provider destination, payee fingerprint, amount, currency, PO, invoice,
 * policy version and delegation. It is single-use (enforced in the database
 * by the gateway) and short-lived.
 */
export const TOKEN_TYPE = 'agenttrust-authz+jws';

export interface AuthorizationClaims {
  iss: 'agenttrust';
  /** Authorization id; also the single-use identifier. */
  jti: string;
  org: string;
  agt: string;
  /** Session credential that requested it. */
  sid: string | null;
  dlg: string;
  pol: string;
  pv: number;
  /** Authorization fingerprint over the complete payment instruction. */
  fp: string;
  sup: string | null;
  sv: number;
  rail: string;
  dst: string;
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

export function claimsFromBinding(
  b: AuthorizationBinding,
  meta: { id: string; sessionId: string | null; iat: number; exp: number; nonce: string },
): AuthorizationClaims {
  return {
    iss: 'agenttrust',
    jti: meta.id,
    org: b.organizationId,
    agt: b.agentId,
    sid: meta.sessionId,
    dlg: b.delegationId,
    pol: b.policyId,
    pv: b.policyVersion,
    fp: authorizationFingerprint(b),
    sup: b.supplierId,
    sv: b.supplierVersion,
    rail: b.paymentRail,
    dst: b.destinationRef,
    pd: b.paymentDestinationFingerprint,
    amt: b.amountCents,
    cur: b.currency,
    po: b.purchaseOrderId,
    inv: b.invoiceId,
    iat: meta.iat,
    exp: meta.exp,
    nonce: meta.nonce,
  };
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
 * Compares a verified token against the payment instruction derived from
 * CURRENT trusted state. Returns the mismatching components (empty = exact
 * match). Callers map components to specific rejection reasons.
 */
export function tokenMismatches(claims: AuthorizationClaims, b: AuthorizationBinding): string[] {
  const m: string[] = [];
  if (claims.org !== b.organizationId) m.push('organizationId');
  if (claims.agt !== b.agentId) m.push('agentId');
  if (claims.sup !== b.supplierId) m.push('supplierId');
  if (claims.sv !== b.supplierVersion) m.push('supplierVersion');
  if (claims.rail !== b.paymentRail) m.push('paymentRail');
  if (claims.dst !== b.destinationRef) m.push('destinationRef');
  if (claims.pd !== b.paymentDestinationFingerprint) m.push('paymentDestination');
  if (claims.amt !== b.amountCents) m.push('amountCents');
  if (claims.cur !== b.currency) m.push('currency');
  if (claims.po !== b.purchaseOrderId) m.push('purchaseOrderId');
  if (claims.inv !== b.invoiceId) m.push('invoiceId');
  if (claims.pol !== b.policyId || claims.pv !== b.policyVersion) m.push('policyVersion');
  if (claims.dlg !== b.delegationId) m.push('delegation');
  if (!safeEqual(claims.fp, authorizationFingerprint(b))) m.push('fingerprint');
  return m;
}

function isClaims(c: unknown): c is AuthorizationClaims {
  if (!c || typeof c !== 'object') return false;
  const o = c as Record<string, unknown>;
  const str = (k: string) => typeof o[k] === 'string';
  const strOrNull = (k: string) => typeof o[k] === 'string' || o[k] === null;
  const int = (k: string) => Number.isSafeInteger(o[k]);
  return (
    o.iss === 'agenttrust' &&
    str('jti') && str('org') && str('agt') && strOrNull('sid') && str('dlg') && str('pol') && int('pv') &&
    str('fp') && strOrNull('sup') && int('sv') && str('rail') && str('dst') && str('pd') && int('amt') &&
    str('cur') && strOrNull('po') && strOrNull('inv') && int('iat') && int('exp') && str('nonce')
  );
}
