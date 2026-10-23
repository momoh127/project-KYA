import { Inject, Injectable } from '@nestjs/common';
import { base64UrlDecode, base64UrlEncode, canonicalJson, hmacSha256Hex, safeEqual } from '@agenttrust/shared';
import { APP_CONFIG, type AppConfig } from '../config';

export interface VerifiedHumanToken {
  /** Identity-provider subject; mapped to User.externalIdentityId. */
  subject: string;
  /** Unix seconds of the last interactive authentication. */
  authTime: number;
}

/**
 * Verifies human access tokens. Production implementation: an OIDC verifier
 * (Auth0 / Okta / WorkOS / Clerk) that validates RS256/EdDSA JWTs against the
 * provider's JWKS, issuer, audience and expiry. Local development uses the
 * HMAC dev issuer below, which the config refuses to enable in production.
 */
export interface HumanTokenVerifier {
  verify(token: string): VerifiedHumanToken | null;
}

export const HUMAN_TOKEN_VERIFIER = Symbol('HUMAN_TOKEN_VERIFIER');

const DEV_TTL_SECONDS = 3600;

@Injectable()
export class DevTokenService implements HumanTokenVerifier {
  private readonly secret: string | null;

  constructor(@Inject(APP_CONFIG) config: AppConfig) {
    this.secret = config.devAuth.enabled ? config.devAuth.secret : null;
  }

  get enabled(): boolean {
    return this.secret !== null;
  }

  issue(subject: string, now = new Date()): { accessToken: string; expiresAt: string } {
    if (!this.secret) throw new Error('dev auth disabled');
    const iat = Math.floor(now.getTime() / 1000);
    const header = base64UrlEncode(canonicalJson({ alg: 'HS256', typ: 'JWT' }));
    const payload = base64UrlEncode(
      canonicalJson({ iss: 'agenttrust-dev', sub: subject, iat, auth_time: iat, exp: iat + DEV_TTL_SECONDS }),
    );
    const sig = base64UrlEncode(Buffer.from(hmacSha256Hex(this.secret, `${header}.${payload}`), 'hex'));
    return { accessToken: `${header}.${payload}.${sig}`, expiresAt: new Date((iat + DEV_TTL_SECONDS) * 1000).toISOString() };
  }

  verify(token: string): VerifiedHumanToken | null {
    if (!this.secret || token.length > 4096) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, p, s] = parts as [string, string, string];
    try {
      const header = JSON.parse(base64UrlDecode(h).toString('utf8'));
      if (header.alg !== 'HS256' || header.typ !== 'JWT') return null;
      const expected = base64UrlEncode(Buffer.from(hmacSha256Hex(this.secret, `${h}.${p}`), 'hex'));
      if (!safeEqual(expected, s)) return null;
      const claims = JSON.parse(base64UrlDecode(p).toString('utf8'));
      const now = Math.floor(Date.now() / 1000);
      if (claims.iss !== 'agenttrust-dev' || typeof claims.sub !== 'string') return null;
      if (!Number.isSafeInteger(claims.exp) || claims.exp <= now) return null;
      if (!Number.isSafeInteger(claims.auth_time)) return null;
      return { subject: claims.sub, authTime: claims.auth_time };
    } catch {
      return null;
    }
  }
}

/** Used when no identity provider is configured: rejects every human token. */
export class RejectAllHumanTokens implements HumanTokenVerifier {
  verify(): null {
    return null;
  }
}
