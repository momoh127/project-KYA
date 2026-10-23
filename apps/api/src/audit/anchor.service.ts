import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { merkleRoot, signAnchor, type AnchorStatement, type SealedAuditEvent } from '@agenttrust/audit';
import { canonicalJson, IdPrefix, newId } from '@agenttrust/shared';
import { APP_CONFIG, type AppConfig } from '../config';
import { CryptoService } from '../common/crypto.service';
import { PrismaService } from '../common/prisma.service';
import { AuditService } from './audit.service';
import { IMMUTABLE_STORAGE, type ImmutableStorage } from './immutable-storage';

/**
 * External integrity anchoring for the audit log:
 *  1. take the not-yet-anchored events of an organization,
 *  2. compute their Merkle root and the chain-head hash,
 *  3. sign a statement (linked to the previous anchor's root),
 *  4. write it to write-once storage OUTSIDE the database,
 *  5. index it in AuditAnchor (append-only).
 * An independent verifier (packages/audit cli) later reads the anchors from
 * storage and checks the exported events against them.
 */
@Injectable()
export class AnchorService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger('AuditAnchor');
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly crypto: CryptoService,
    private readonly audit: AuditService,
    @Inject(IMMUTABLE_STORAGE) private readonly storage: ImmutableStorage,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onModuleInit(): void {
    if (this.config.anchorIntervalMs <= 0) return;
    this.timer = setInterval(() => void this.anchorAll(), this.config.anchorIntervalMs);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  async anchorAll(): Promise<number> {
    let n = 0;
    const heads = await this.prisma.auditChainHead.findMany({ select: { organizationId: true } });
    for (const h of heads) {
      try {
        if (await this.anchor(h.organizationId)) n++;
      } catch (e) {
        this.logger.error(`anchoring ${h.organizationId} failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
    return n;
  }

  /** Anchors all events after the last anchor. Returns null if there is nothing new. */
  async anchor(organizationId: string) {
    return this.prisma.tx(async (tx) => {
      // One anchoring job per organization at a time (does not block audit writers).
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`anchor:${organizationId}`}))`;
      const last = await tx.auditAnchor.findFirst({ where: { organizationId }, orderBy: { toSequence: 'desc' } });
      const from = (last?.toSequence ?? 0) + 1;
      const events = await tx.auditEvent.findMany({
        where: { organizationId, sequence: { gte: from } },
        orderBy: { sequence: 'asc' },
        select: { sequence: true, eventHash: true },
      });
      if (events.length === 0) return null;
      const to = events[events.length - 1]!.sequence;
      if (events[0]!.sequence !== from || to - from + 1 !== events.length) throw new Error('audit sequence gap; refusing to anchor');

      const statement: AnchorStatement = {
        v: 1,
        organizationId,
        fromSequence: from,
        toSequence: to,
        eventCount: events.length,
        merkleRoot: merkleRoot(events.map((e) => e.eventHash)),
        chainHeadHash: events[events.length - 1]!.eventHash,
        previousMerkleRoot: last?.merkleRoot ?? null,
        createdAt: new Date().toISOString(),
      };
      const signed = signAnchor(statement, this.crypto.signer);
      const key = `${organizationId}/anchor-${String(to).padStart(12, '0')}.json`;
      const uri = await this.storage.putOnce(key, canonicalJson(signed as unknown as Record<string, unknown>));
      const row = await tx.auditAnchor.create({
        data: {
          id: newId(IdPrefix.auditAnchor), organizationId, fromSequence: from, toSequence: to, eventCount: events.length,
          merkleRoot: statement.merkleRoot, chainHeadHash: statement.chainHeadHash, previousMerkleRoot: statement.previousMerkleRoot,
          statement: statement as unknown as Prisma.InputJsonObject, signature: signed.signature, keyId: signed.keyId, storageUri: uri,
        },
      });
      await this.audit.append(tx, {
        organizationId, actorType: 'system', actorId: 'audit-anchor', eventType: 'audit.anchored', subjectId: row.id,
        payload: { fromSequence: from, toSequence: to, eventCount: events.length, merkleRoot: statement.merkleRoot, storage: this.storage.name },
      });
      return serializeAnchor(row);
    });
  }

  async list(organizationId: string) {
    const rows = await this.prisma.auditAnchor.findMany({ where: { organizationId }, orderBy: { toSequence: 'asc' } });
    return { storage: this.storage.name, anchors: rows.map(serializeAnchor) };
  }

  /** Everything an independent verifier needs except the anchors (read those from storage). */
  async export(organizationId: string) {
    const events = (await this.audit.list(organizationId, { limit: 1_000_000 })) as SealedAuditEvent[];
    return {
      organizationId,
      exportedAt: new Date().toISOString(),
      events,
      publicKeys: [{ keyId: this.crypto.signer.keyId, publicKeyPem: this.crypto.signer.publicKey.export({ type: 'spki', format: 'pem' }).toString() }],
      note: 'Verify with: agenttrust-verify --export <this file> --anchors <write-once anchor storage>. Read anchors from storage, not from this API.',
    };
  }
}

function serializeAnchor(a: { id: string; fromSequence: number; toSequence: number; eventCount: number; merkleRoot: string; chainHeadHash: string; storageUri: string; createdAt: Date }) {
  return {
    id: a.id,
    fromSequence: a.fromSequence,
    toSequence: a.toSequence,
    eventCount: a.eventCount,
    merkleRoot: a.merkleRoot,
    chainHeadHash: a.chainHeadHash,
    storageUri: a.storageUri,
    createdAt: a.createdAt.toISOString(),
  };
}
