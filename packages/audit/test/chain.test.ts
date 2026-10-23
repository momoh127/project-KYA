import { describe, expect, it } from 'vitest';
import { generateEd25519KeyPair, LocalEd25519Signer } from '@agenttrust/identity';
import { sealAuditEvent, verifyAuditChain, type SealedAuditEvent } from '@agenttrust/audit';

function buildChain(n: number) {
  const signer = new LocalEd25519Signer('key_1', generateEd25519KeyPair().privateKeyPem);
  const events: SealedAuditEvent[] = [];
  for (let i = 1; i <= n; i++) {
    events.push(
      sealAuditEvent(
        {
          id: `evt_${i}`,
          organizationId: 'org_1',
          sequence: i,
          actorType: 'agent',
          actorId: 'agt_104',
          eventType: 'authorization.decided',
          subjectId: `auth_${i}`,
          payload: { decision: i % 2 ? 'ALLOW' : 'DENY', amountCents: 50_000 * i },
          createdAt: new Date(Date.UTC(2026, 9, 22, 12, 0, i)).toISOString(),
          previousEventHash: events[i - 2]?.eventHash ?? null,
        },
        signer,
      ),
    );
  }
  const resolveKey = (kid: string) => (kid === signer.keyId ? signer.publicKey : null);
  return { events, resolveKey };
}

describe('audit hash chain', () => {
  it('verifies an untouched chain', () => {
    const { events, resolveKey } = buildChain(4);
    expect(verifyAuditChain(events, resolveKey)).toMatchObject({ valid: true, eventsChecked: 4 });
  });

  it('detects an edited payload (e.g. DENY rewritten to ALLOW)', () => {
    const { events, resolveKey } = buildChain(4);
    events[1] = { ...events[1]!, payload: { ...events[1]!.payload, decision: 'ALLOW' } };
    const r = verifyAuditChain(events, resolveKey);
    expect(r.valid).toBe(false);
    expect(r.problems[0]?.problem).toMatch(/payload hash mismatch/);
  });

  it('detects a deleted event', () => {
    const { events, resolveKey } = buildChain(4);
    events.splice(2, 1);
    expect(verifyAuditChain(events, resolveKey).valid).toBe(false);
  });

  it('detects a re-hashed event that was not re-signed by the platform key', () => {
    const { events, resolveKey } = buildChain(3);
    const attacker = new LocalEd25519Signer('key_1', generateEd25519KeyPair().privateKeyPem);
    const { payloadHash: _ph, eventHash: _eh, signature: _s, keyId: _k, ...draft } = events[2]!;
    events[2] = sealAuditEvent({ ...draft, payload: { decision: 'ALLOW', amountCents: 1 } }, attacker);
    const r = verifyAuditChain(events, resolveKey);
    expect(r.valid).toBe(false);
    expect(r.problems.map((p) => p.problem)).toContain('invalid signature');
  });
});

describe('Merkle anchoring', () => {
  it('roots, inclusion proofs, and detection of changes after anchoring', async () => {
    const { merkleRoot, inclusionProof, verifyInclusion, signAnchor, verifyAgainstAnchors } = await import('@agenttrust/audit');
    const { events, resolveKey } = buildChain(7);
    const hashes = events.map((e) => e.eventHash);
    const root = merkleRoot(hashes);
    for (let i = 0; i < hashes.length; i++) expect(verifyInclusion(hashes[i]!, inclusionProof(hashes, i), root)).toBe(true);
    expect(verifyInclusion('f'.repeat(64), inclusionProof(hashes, 0), root)).toBe(false);

    const signer = new LocalEd25519Signer('anchor_key', generateEd25519KeyPair().privateKeyPem);
    const resolve = (kid: string) => (kid === 'anchor_key' ? signer.publicKey : null);
    const anchor = signAnchor({
      v: 1, organizationId: 'org_1', fromSequence: 1, toSequence: 4, eventCount: 4,
      merkleRoot: merkleRoot(hashes.slice(0, 4)), chainHeadHash: hashes[3]!, previousMerkleRoot: null, createdAt: new Date().toISOString(),
    }, signer);
    const ok = verifyAgainstAnchors(events, [anchor], (kid) => resolveKey(kid) ?? resolve(kid));
    expect(ok.problems.filter((p) => p.startsWith('anchor'))).toEqual([]);
    expect(ok.unanchoredEvents).toBe(3);

    const forged = events.map((e, i) => (i === 1 ? { ...e, eventHash: 'a'.repeat(64) } : e));
    const bad = verifyAgainstAnchors(forged, [anchor], (kid) => resolveKey(kid) ?? resolve(kid));
    expect(bad.problems.some((p) => p.includes('Merkle root mismatch'))).toBe(true);
  });
});
