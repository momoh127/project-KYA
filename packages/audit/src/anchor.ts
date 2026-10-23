import type { KeyObject } from 'node:crypto';
import { createHash } from 'node:crypto';
import { base64UrlDecode, base64UrlEncode, canonicalJson, safeEqual } from '@agenttrust/shared';
import { ed25519Verify, type Signer } from '@agenttrust/identity';
import { verifyAuditChain, type SealedAuditEvent } from './chain';

/**
 * Merkle tree over audit event hashes (RFC 6962-style domain separation:
 * leaf = H(0x00 || eventHash), node = H(0x01 || left || right); an odd node is
 * promoted unchanged). The root of each batch is signed and written to
 * write-once storage OUTSIDE the database, so rewriting history in the
 * database (even with the platform key) no longer matches the anchors.
 */
const sha = (...parts: Buffer[]) => createHash('sha256').update(Buffer.concat(parts)).digest();

export function leafHash(eventHash: string): Buffer {
  return sha(Buffer.from([0]), Buffer.from(eventHash, 'utf8'));
}

export function merkleRoot(eventHashes: string[]): string {
  if (eventHashes.length === 0) throw new RangeError('cannot compute a Merkle root of zero events');
  let level = eventHashes.map(leafHash);
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? sha(Buffer.from([1]), level[i]!, level[i + 1]!) : level[i]!);
    }
    level = next;
  }
  return level[0]!.toString('hex');
}

export interface InclusionProof {
  index: number;
  siblings: { hash: string; side: 'left' | 'right' }[];
}

export function inclusionProof(eventHashes: string[], index: number): InclusionProof {
  let level = eventHashes.map(leafHash);
  let i = index;
  const siblings: InclusionProof['siblings'] = [];
  while (level.length > 1) {
    const isRight = i % 2 === 1;
    const sibling = isRight ? i - 1 : i + 1;
    if (sibling < level.length) siblings.push({ hash: level[sibling]!.toString('hex'), side: isRight ? 'left' : 'right' });
    const next: Buffer[] = [];
    for (let j = 0; j < level.length; j += 2) next.push(j + 1 < level.length ? sha(Buffer.from([1]), level[j]!, level[j + 1]!) : level[j]!);
    level = next;
    i = Math.floor(i / 2);
  }
  return { index, siblings };
}

export function verifyInclusion(eventHash: string, proof: InclusionProof, root: string): boolean {
  let h = leafHash(eventHash);
  for (const s of proof.siblings) {
    const sib = Buffer.from(s.hash, 'hex');
    h = s.side === 'left' ? sha(Buffer.from([1]), sib, h) : sha(Buffer.from([1]), h, sib);
  }
  return safeEqual(h.toString('hex'), root);
}

/** The signed statement written to immutable storage for each batch. */
export interface AnchorStatement {
  v: 1;
  organizationId: string;
  fromSequence: number;
  toSequence: number;
  eventCount: number;
  merkleRoot: string;
  /** eventHash of the event at toSequence (links the batch to the chain). */
  chainHeadHash: string;
  previousMerkleRoot: string | null;
  createdAt: string;
}

export interface SignedAnchor {
  statement: AnchorStatement;
  signature: string;
  keyId: string;
}

export function signAnchor(statement: AnchorStatement, signer: Signer): SignedAnchor {
  const sig = signer.sign(Buffer.from(canonicalJson(statement), 'utf8'));
  return { statement, signature: base64UrlEncode(sig), keyId: signer.keyId };
}

export interface AnchoredVerificationResult {
  valid: boolean;
  chain: ReturnType<typeof verifyAuditChain>;
  anchorsChecked: number;
  eventsCovered: number;
  /** Events newer than the latest anchor (not yet externally protected). */
  unanchoredEvents: number;
  problems: string[];
}

/**
 * Independent verification: checks the exported event chain AND that every
 * anchor read from immutable storage matches it (signature, contiguity,
 * Merkle root, chain head). Run outside AgentTrust with only public keys.
 */
export function verifyAgainstAnchors(
  events: SealedAuditEvent[],
  anchors: SignedAnchor[],
  resolveKey: (keyId: string) => KeyObject | null,
): AnchoredVerificationResult {
  const problems: string[] = [];
  const chain = verifyAuditChain(events, resolveKey);
  for (const p of chain.problems) problems.push(`chain seq ${p.sequence}: ${p.problem}`);

  const bySeq = new Map(events.map((e) => [e.sequence, e]));
  const sorted = [...anchors].sort((a, b) => a.statement.fromSequence - b.statement.fromSequence);
  let expectedFrom = 1;
  let previousRoot: string | null = null;
  let covered = 0;
  for (const a of sorted) {
    const s = a.statement;
    const tag = `anchor ${s.fromSequence}-${s.toSequence}`;
    const key = resolveKey(a.keyId);
    let sigOk = false;
    try {
      sigOk = !!key && ed25519Verify(key, Buffer.from(canonicalJson(s), 'utf8'), base64UrlDecode(a.signature));
    } catch {
      sigOk = false;
    }
    if (!sigOk) problems.push(`${tag}: invalid anchor signature`);
    if (s.fromSequence !== expectedFrom) problems.push(`${tag}: not contiguous (expected from ${expectedFrom})`);
    if (s.previousMerkleRoot !== previousRoot) problems.push(`${tag}: does not link to previous anchor`);
    const batch: SealedAuditEvent[] = [];
    for (let q = s.fromSequence; q <= s.toSequence; q++) {
      const e = bySeq.get(q);
      if (!e) {
        problems.push(`${tag}: event ${q} missing from export`);
        break;
      }
      batch.push(e);
    }
    if (batch.length === s.eventCount) {
      const root = merkleRoot(batch.map((e) => e.eventHash));
      if (!safeEqual(root, s.merkleRoot)) problems.push(`${tag}: Merkle root mismatch: events in this range were altered after anchoring`);
      if (batch[batch.length - 1]!.eventHash !== s.chainHeadHash) problems.push(`${tag}: chain head mismatch`);
    }
    covered += s.eventCount;
    expectedFrom = s.toSequence + 1;
    previousRoot = s.merkleRoot;
  }
  const lastAnchored = expectedFrom - 1;
  const unanchored = events.filter((e) => e.sequence > lastAnchored).length;
  return { valid: problems.length === 0, chain, anchorsChecked: sorted.length, eventsCovered: covered, unanchoredEvents: unanchored, problems };
}
