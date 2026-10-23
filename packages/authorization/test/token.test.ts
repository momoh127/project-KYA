import { describe, expect, it } from 'vitest';
import { generateEd25519KeyPair, LocalEd25519Signer } from '@agenttrust/identity';
import {
  signAuthorizationToken,
  tokenMismatches,
  verifyAuthorizationToken,
  type AuthorizationClaims,
} from '@agenttrust/authorization';
import { base64UrlEncode, transactionFingerprint, type TransactionIntent } from '@agenttrust/shared';

const NOW = new Date('2026-10-22T12:00:00Z');
const nowSec = Math.floor(NOW.getTime() / 1000);

const intent: TransactionIntent = {
  organizationId: 'org_1',
  agentId: 'agt_104',
  action: 'purchase',
  supplierId: 'sup_100',
  paymentDestinationFingerprint: 'pd_good',
  amountCents: 50_000,
  currency: 'USD',
  purchaseOrderId: 'po_200',
  invoiceId: 'inv_900',
};

function setup() {
  const signer = new LocalEd25519Signer('key_1', generateEd25519KeyPair().privateKeyPem);
  const claims: AuthorizationClaims = {
    iss: 'agenttrust',
    jti: 'auth_1',
    org: intent.organizationId,
    agt: intent.agentId,
    dlg: 'dlg_1',
    pol: 'pol_1',
    pv: 3,
    fp: transactionFingerprint(intent),
    sup: intent.supplierId,
    pd: intent.paymentDestinationFingerprint,
    amt: intent.amountCents,
    cur: intent.currency,
    po: intent.purchaseOrderId,
    inv: intent.invoiceId,
    iat: nowSec,
    exp: nowSec + 600,
    nonce: 'n1',
  };
  const token = signAuthorizationToken(claims, signer);
  const resolveKey = (kid: string) => (kid === signer.keyId ? signer.publicKey : null);
  return { signer, claims, token, resolveKey };
}

describe('authorization tokens', () => {
  it('verifies and binds the exact transaction', () => {
    const { token, resolveKey } = setup();
    const r = verifyAuthorizationToken(token, { resolveKey, now: NOW });
    expect(r.ok).toBe(true);
    if (r.ok) expect(tokenMismatches(r.claims, intent)).toEqual([]);
  });

  it('rejects a token whose amount was edited ($500 -> $5,000)', () => {
    const { token, resolveKey } = setup();
    const [h, p, s] = token.split('.');
    const claims = JSON.parse(Buffer.from(p!, 'base64url').toString());
    claims.amt = 500_000;
    const forged = `${h}.${base64UrlEncode(JSON.stringify(claims))}.${s}`;
    expect(verifyAuthorizationToken(forged, { resolveKey, now: NOW })).toEqual({ ok: false, reason: 'BAD_SIGNATURE' });
  });

  it('detects a valid token presented for a different transaction', () => {
    const { token, resolveKey } = setup();
    const r = verifyAuthorizationToken(token, { resolveKey, now: NOW });
    if (!r.ok) throw new Error('expected ok');
    expect(tokenMismatches(r.claims, { ...intent, amountCents: 500_000 })).toEqual(['amountCents', 'fingerprint']);
    expect(tokenMismatches(r.claims, { ...intent, paymentDestinationFingerprint: 'pd_attacker' }))
      .toEqual(['paymentDestination', 'fingerprint']);
  });

  it('rejects expired tokens, unknown keys, other signers and alg confusion', () => {
    const { token, resolveKey, claims } = setup();
    expect(verifyAuthorizationToken(token, { resolveKey, now: new Date(NOW.getTime() + 601_000) }))
      .toEqual({ ok: false, reason: 'EXPIRED' });
    expect(verifyAuthorizationToken(token, { resolveKey: () => null, now: NOW }))
      .toEqual({ ok: false, reason: 'UNKNOWN_KEY' });

    const attacker = new LocalEd25519Signer('key_1', generateEd25519KeyPair().privateKeyPem);
    const forged = signAuthorizationToken(claims, attacker);
    expect(verifyAuthorizationToken(forged, { resolveKey, now: NOW })).toEqual({ ok: false, reason: 'BAD_SIGNATURE' });

    const [, p] = token.split('.');
    const none = `${base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'agenttrust-authz+jws', kid: 'key_1' }))}.${p}.`;
    expect(verifyAuthorizationToken(none, { resolveKey, now: NOW })).toEqual({ ok: false, reason: 'UNSUPPORTED_ALGORITHM' });
  });

  it('rejects garbage', () => {
    const { resolveKey } = setup();
    for (const t of ['', 'a.b', 'a.b.c', '!!!.###.$$$']) {
      expect(verifyAuthorizationToken(t, { resolveKey, now: NOW }).ok).toBe(false);
    }
  });
});
