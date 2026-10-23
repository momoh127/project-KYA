/**
 * External audit anchoring. Demonstrates the attack the hash chain alone
 * cannot stop: an insider with database superuser rights AND the platform
 * signing key rewrites history and re-signs it. The in-database verifier says
 * "valid"; the independent verifier, reading anchors from write-once storage,
 * detects the rewrite.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { PrismaClient } from '@prisma/client';
import { readAnchorsFromDirectory, sealAuditEvent, verifyExport, type AuditExport, type SealedAuditEvent } from '@agenttrust/audit';
import { LocalEd25519Signer } from '@agenttrust/identity';
import { LocalWriteOnceStorage, WriteOnceViolation } from '../src/audit/immutable-storage';
import { BANK_ATTACKER, createWorld, purchase, startServer, type TestServer, type World } from './helpers';

let server: TestServer;
let world: World;
const prisma = new PrismaClient();
const anchorDir = process.env.AGENTTRUST_ANCHOR_DIR!;
const cli = path.resolve(__dirname, '../../../packages/audit/dist/cli.js');

beforeAll(async () => {
  server = await startServer();
  world = await createWorld(server.baseUrl, 'Stark Procurement');
  const agent = await world.createAgent('Agent X', { maxTransactionCents: 500_000, monthlyLimitCents: 5_000_000 });
  const o = await world.order(agent, 10_000);
  await purchase(agent, { ...o, amountCents: 10_000 });
  await purchase(agent, { supplierId: world.supplierId, payee: BANK_ATTACKER, amountCents: 10_000 }); // DENY: payee mismatch
});
afterAll(async () => {
  await prisma.$disconnect();
  await server?.close();
});

function runCli(exp: AuditExport): number {
  const file = path.join(tmpdir(), `agenttrust-export-${exp.organizationId}-${Date.now()}.json`);
  writeFileSync(file, JSON.stringify(exp));
  try {
    execFileSync(process.execPath, [cli, '--export', file, '--anchors', anchorDir], { stdio: 'pipe' });
    return 0;
  } catch (e) {
    return (e as { status: number }).status;
  }
}

describe('external audit anchoring', () => {
  it('anchors a signed Merkle root to write-once storage', async () => {
    const { anchor } = await world.admin.post<{ anchor: { fromSequence: number; toSequence: number; storageUri: string } }>('/v1/audit/anchors', {});
    expect(anchor.fromSequence).toBe(1);
    const file = anchor.storageUri.replace('file://', '');
    expect(statSync(file).mode & 0o222).toBe(0); // read-only

    const storage = new LocalWriteOnceStorage(anchorDir);
    const key = path.relative(anchorDir, file);
    await expect(storage.putOnce(key, '{"forged":true}')).rejects.toBeInstanceOf(WriteOnceViolation);

    // A second anchor covers only newer events and links to the first.
    await world.admin.post('/v1/audit/anchors', {});
    const { anchors } = await world.admin.get<{ anchors: { fromSequence: number; toSequence: number }[] }>('/v1/audit/anchors');
    expect(anchors[1]!.fromSequence).toBe(anchors[0]!.toSequence + 1);
  });

  it('the independent verifier accepts the untouched history (library and CLI)', async () => {
    const exp = await world.admin.get<AuditExport>('/v1/audit/export');
    const result = verifyExport(exp, readAnchorsFromDirectory(anchorDir, exp.organizationId));
    expect(result.problems).toEqual([]);
    expect(result.valid).toBe(true);
    expect(result.anchorsChecked).toBe(2);
    expect(runCli(exp)).toBe(0);
  });

  it('detects a full rewrite by an insider holding DB superuser rights AND the platform signing key', async () => {
    const orgId = world.orgId;
    const rows = await prisma.auditEvent.findMany({ where: { organizationId: orgId }, orderBy: { sequence: 'asc' } });
    const target = rows.findIndex((r) => r.eventType === 'authorization.denied');
    expect(target).toBeGreaterThan(0);

    // --- The attack: disable the append-only trigger, flip DENY→ALLOW, re-hash and re-sign everything after it.
    const signer = new LocalEd25519Signer(process.env.AGENTTRUST_SIGNING_KEY_ID!, Buffer.from(process.env.AGENTTRUST_SIGNING_KEY_PEM_B64!, 'base64').toString('utf8'));
    await prisma.$executeRawUnsafe('ALTER TABLE "AuditEvent" DISABLE TRIGGER USER');
    try {
      let prev = rows[target - 1]!.eventHash;
      for (let i = target; i < rows.length; i++) {
        const r = rows[i]!;
        const payload = { ...(r.payload as Record<string, unknown>) };
        if (i === target) payload.decision = 'ALLOW';
        const sealed = sealAuditEvent(
          { id: r.id, organizationId: r.organizationId, sequence: r.sequence, actorType: r.actorType, actorId: r.actorId, eventType: i === target ? 'authorization.allowed' : r.eventType,
            subjectId: r.subjectId, payload, createdAt: r.createdAt.toISOString(), previousEventHash: prev },
          signer,
        );
        await prisma.auditEvent.update({
          where: { id: r.id },
          data: { eventType: sealed.eventType, payload: sealed.payload as object, payloadHash: sealed.payloadHash, previousEventHash: sealed.previousEventHash, eventHash: sealed.eventHash, signature: sealed.signature },
        });
        prev = sealed.eventHash;
      }
      await prisma.auditChainHead.update({ where: { organizationId: orgId }, data: { lastEventHash: prev } });
    } finally {
      await prisma.$executeRawUnsafe('ALTER TABLE "AuditEvent" ENABLE TRIGGER USER');
    }

    // The in-database verifier cannot tell: hashes link and signatures are valid.
    const inDb = await world.admin.get<{ valid: boolean }>('/v1/audit/verify');
    expect(inDb.valid).toBe(true);

    // The independent verifier, reading anchors from write-once storage, can.
    const exp = await world.admin.get<AuditExport>('/v1/audit/export');
    const tampered = (exp.events as SealedAuditEvent[]).find((e) => e.sequence === rows[target]!.sequence)!;
    expect(tampered.payload.decision).toBe('ALLOW');
    const result = verifyExport(exp, readAnchorsFromDirectory(anchorDir, exp.organizationId));
    expect(result.valid).toBe(false);
    expect(result.problems.some((p) => p.includes('Merkle root mismatch'))).toBe(true);
    expect(runCli(exp)).toBe(1);
  });
});
