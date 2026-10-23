import { Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { sealAuditEvent, verifyAuditChain, type ActorType, type SealedAuditEvent } from '@agenttrust/audit';
import { IdPrefix, newId } from '@agenttrust/shared';
import { CryptoService } from '../common/crypto.service';
import { PrismaService, type Tx } from '../common/prisma.service';
import { Errors } from '../common/errors';

export interface AuditInput {
  organizationId: string;
  actorType: ActorType;
  actorId: string;
  eventType: string;
  subjectId?: string | null;
  /** Integers, strings, booleans, null, arrays, objects only (canonical JSON). */
  payload: Record<string, unknown>;
}

@Injectable()
export class AuditService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly crypto: CryptoService,
  ) {}

  /**
   * Appends a signed, hash-chained event inside the caller's transaction, so
   * the decision and its evidence commit (or roll back) together. Takes the
   * per-organization chain-head lock LAST (see lock ordering in PrismaService).
   */
  async append(tx: Tx, input: AuditInput): Promise<SealedAuditEvent> {
    const heads = await tx.$queryRaw<{ lastSequence: number; lastEventHash: string | null }[]>`
      SELECT "lastSequence", "lastEventHash" FROM "AuditChainHead"
      WHERE "organizationId" = ${input.organizationId} FOR UPDATE`;
    const head = heads[0];
    if (!head) throw new Error(`audit chain missing for organization ${input.organizationId}`);

    const sealed = sealAuditEvent(
      {
        id: newId(IdPrefix.auditEvent),
        organizationId: input.organizationId,
        sequence: head.lastSequence + 1,
        actorType: input.actorType,
        actorId: input.actorId,
        eventType: input.eventType,
        subjectId: input.subjectId ?? null,
        payload: input.payload,
        createdAt: new Date().toISOString(),
        previousEventHash: head.lastEventHash,
      },
      this.crypto.signer,
    );

    await tx.auditEvent.create({
      data: { ...sealed, payload: sealed.payload as Prisma.InputJsonObject, createdAt: new Date(sealed.createdAt) },
    });
    await tx.auditChainHead.update({
      where: { organizationId: input.organizationId },
      data: { lastSequence: sealed.sequence, lastEventHash: sealed.eventHash },
    });
    return sealed;
  }

  /** Standalone append (own transaction), used for rejected-request evidence. */
  appendStandalone(input: AuditInput): Promise<SealedAuditEvent> {
    return this.prisma.tx((tx) => this.append(tx, input));
  }

  async list(organizationId: string, opts: { limit: number; afterSequence?: number; eventType?: string; actorId?: string }) {
    const rows = await this.prisma.auditEvent.findMany({
      where: {
        organizationId,
        ...(opts.afterSequence !== undefined ? { sequence: { gt: opts.afterSequence } } : {}),
        ...(opts.eventType ? { eventType: opts.eventType } : {}),
        ...(opts.actorId ? { actorId: opts.actorId } : {}),
      },
      orderBy: { sequence: 'asc' },
      take: opts.limit,
    });
    return rows.map(toSealed);
  }

  async get(organizationId: string, id: string) {
    const row = await this.prisma.auditEvent.findFirst({ where: { id, organizationId } });
    if (!row) throw Errors.notFound('Audit event');
    return toSealed(row);
  }

  async verifyChain(organizationId: string) {
    const rows = await this.prisma.auditEvent.findMany({ where: { organizationId }, orderBy: { sequence: 'asc' } });
    const head = await this.prisma.auditChainHead.findUnique({ where: { organizationId } });
    const result = verifyAuditChain(rows.map(toSealed), this.crypto.resolveKey);
    const last = rows[rows.length - 1];
    const headMatches = head ? head.lastSequence === (last?.sequence ?? 0) && head.lastEventHash === (last?.eventHash ?? null) : false;
    return {
      ...result,
      valid: result.valid && headMatches,
      chainHead: head ? { sequence: head.lastSequence, eventHash: head.lastEventHash } : null,
      headMatches,
      note: 'Verifies integrity and platform signatures of this organization\'s chain. Anchor chain heads externally for protection against full-database rewrites.',
    };
  }
}

function toSealed(row: {
  id: string; organizationId: string; sequence: number; actorType: ActorType; actorId: string; eventType: string;
  subjectId: string | null; payload: Prisma.JsonValue; payloadHash: string; previousEventHash: string | null;
  eventHash: string; signature: string; keyId: string; createdAt: Date;
}): SealedAuditEvent {
  return {
    id: row.id,
    organizationId: row.organizationId,
    sequence: row.sequence,
    actorType: row.actorType,
    actorId: row.actorId,
    eventType: row.eventType,
    subjectId: row.subjectId,
    payload: row.payload as Record<string, unknown>,
    payloadHash: row.payloadHash,
    previousEventHash: row.previousEventHash,
    eventHash: row.eventHash,
    signature: row.signature,
    keyId: row.keyId,
    createdAt: row.createdAt.toISOString(),
  };
}
