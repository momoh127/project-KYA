import type { KeyObject } from 'node:crypto';
import { base64UrlDecode, base64UrlEncode, canonicalJson, safeEqual, sha256Hex } from '@agenttrust/shared';
import { ed25519Verify, type Signer } from '@agenttrust/identity';

/**
 * Tamper-evident audit events.
 *
 * Each event commits to:
 *  - a hash of its payload,
 *  - the hash of the previous event in the same organization's chain,
 *  - its own metadata (sequence, actor, type, time),
 * and is signed by the platform's signing key.
 *
 * Editing, deleting or reordering any event breaks verification.
 *
 * LIMITATION (documented on purpose): someone with full database write access
 * AND the signing key could rewrite an entire chain. Production deployments
 * must additionally anchor chain heads in write-once storage (e.g. S3 Object
 * Lock) and keep the signing key in a KMS/HSM.
 */
export type ActorType = 'agent' | 'user' | 'system';

export interface AuditEventDraft {
  id: string;
  organizationId: string;
  sequence: number;
  actorType: ActorType;
  actorId: string;
  eventType: string;
  subjectId: string | null;
  payload: Record<string, unknown>;
  createdAt: string; // ISO-8601
  previousEventHash: string | null;
}

export interface SealedAuditEvent extends AuditEventDraft {
  payloadHash: string;
  eventHash: string;
  signature: string;
  keyId: string;
}

export function payloadHash(payload: Record<string, unknown>): string {
  return sha256Hex(canonicalJson(payload));
}

export function eventHash(e: Omit<AuditEventDraft, 'payload'> & { payloadHash: string }): string {
  return sha256Hex(
    canonicalJson({
      v: 1,
      id: e.id,
      organizationId: e.organizationId,
      sequence: e.sequence,
      actorType: e.actorType,
      actorId: e.actorId,
      eventType: e.eventType,
      subjectId: e.subjectId,
      payloadHash: e.payloadHash,
      createdAt: e.createdAt,
      previousEventHash: e.previousEventHash,
    }),
  );
}

export function sealAuditEvent(draft: AuditEventDraft, signer: Signer): SealedAuditEvent {
  const ph = payloadHash(draft.payload);
  const eh = eventHash({ ...draft, payloadHash: ph });
  const signature = base64UrlEncode(signer.sign(Buffer.from(eh, 'utf8')));
  return { ...draft, payloadHash: ph, eventHash: eh, signature, keyId: signer.keyId };
}

export interface ChainVerificationResult {
  valid: boolean;
  eventsChecked: number;
  problems: { sequence: number; eventId: string; problem: string }[];
}

/** Verifies a full organization chain. Events must be the complete chain from sequence 1. */
export function verifyAuditChain(
  events: SealedAuditEvent[],
  resolveKey: (keyId: string) => KeyObject | null,
): ChainVerificationResult {
  const problems: ChainVerificationResult['problems'] = [];
  const sorted = [...events].sort((a, b) => a.sequence - b.sequence);
  let previous: SealedAuditEvent | null = null;

  for (const e of sorted) {
    const report = (problem: string) => problems.push({ sequence: e.sequence, eventId: e.id, problem });
    const expectedSeq: number = previous ? previous.sequence + 1 : 1;
    if (e.sequence !== expectedSeq) report(`sequence gap: expected ${expectedSeq}`);
    if (previous && e.organizationId !== previous.organizationId) report('organization changed within chain');

    const expectedPrev = previous ? previous.eventHash : null;
    if (e.previousEventHash !== expectedPrev) report('previous-event hash does not link to prior event');

    const ph = payloadHash(e.payload);
    if (!safeEqual(ph, e.payloadHash)) report('payload hash mismatch (payload was modified)');

    const eh = eventHash({ ...e, payloadHash: e.payloadHash });
    if (!safeEqual(eh, e.eventHash)) report('event hash mismatch (metadata was modified)');

    const key = resolveKey(e.keyId);
    if (!key) report(`unknown signing key ${e.keyId}`);
    else {
      let sig: Buffer | null = null;
      try {
        sig = base64UrlDecode(e.signature);
      } catch {
        sig = null;
      }
      if (!sig || !ed25519Verify(key, Buffer.from(e.eventHash, 'utf8'), sig)) report('invalid signature');
    }
    previous = e;
  }

  return { valid: problems.length === 0, eventsChecked: sorted.length, problems };
}
