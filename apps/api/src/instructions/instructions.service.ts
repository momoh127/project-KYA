import { Injectable } from '@nestjs/common';
import type { PurchaseInstruction, PurchaseInstructionLine } from '@prisma/client';
import { z } from 'zod';
import {
  canonicalJson,
  exactLineTotal,
  formatQuantity,
  IdPrefix,
  newId,
  parseQuantity,
  sha256Hex,
  toSafeNumber,
} from '@agenttrust/shared';
import type { HumanPrincipal, IntegrationPrincipal } from '../auth/principal';
import { AuditService } from '../audit/audit.service';
import { invalidateLiveAuthorizations, lockLiveAuthorizationsBy } from '../authorizations/invalidation';
import { Errors } from '../common/errors';
import { cents, PrismaService, type Tx } from '../common/prisma.service';
import { zCents, zCurrency, zId } from '../common/validation';

const MAX_INSTRUCTION_DAYS = 366;

export const FULFILLMENT_TYPES = ['physical_goods', 'services', 'subscription', 'digital_goods'] as const;

export const zInstructionLine = z
  .object({
    lineNumber: z.number().int().min(1).max(999),
    sku: z.string().min(1).max(100).optional(),
    description: z.string().min(1).max(500),
    unit: z.string().min(1).max(20).optional(),
    /** Decimal string, ≤ 3 fractional digits, e.g. "10" or "2.5". */
    quantity: z.string().min(1).max(20),
    unitPriceCents: z.number().int().min(0).max(100_000_000_000),
  })
  .strict();

const instructionShape = {
  agentId: zId('agt'),
  supplierId: zId('sup'),
  purchaseOrderId: zId('po').optional(),
  fulfillmentType: z.enum(FULFILLMENT_TYPES),
  currency: zCurrency,
  lines: z.array(zInstructionLine).min(1).max(100),
  /** Defaults to the lines total; may be lower (a cap), never higher. */
  maxAmountCents: zCents.optional(),
  /** How many separate payments may draw on this instruction. */
  maxUses: z.number().int().min(1).max(100).default(1),
  validFrom: z.string().datetime().optional(),
  expiresAt: z.string().datetime(),
  description: z.string().max(1000).optional(),
};

export const InstructionBody = z.object(instructionShape).strict();
export type InstructionInput = z.infer<typeof InstructionBody>;

export const ErpSyncBody = z
  .object({
    ...instructionShape,
    externalId: z.string().min(1).max(200),
    externalVersion: z.string().min(1).max(100),
    /** Monotonic ERP modification time; older payloads are rejected as stale. */
    externalUpdatedAt: z.string().datetime(),
    erpApproval: z
      .object({
        status: z.enum(['approved', 'pending', 'rejected']),
        approvedBy: z.string().min(1).max(200).optional(),
        approvedAt: z.string().datetime().optional(),
      })
      .strict(),
  })
  .strict();
export type ErpSyncInput = z.infer<typeof ErpSyncBody>;

interface NormalizedLine {
  lineNumber: number;
  sku: string | null;
  description: string;
  unit: string | null;
  quantityMilli: bigint;
  unitPriceCents: bigint;
  lineTotalCents: bigint;
}

interface Normalized {
  lines: NormalizedLine[];
  maxAmountCents: bigint;
  validFrom: Date;
  expiresAt: Date;
  materialHash: string;
  linesHash: string;
}

type InstructionWithLines = PurchaseInstruction & { lines: PurchaseInstructionLine[] };

/**
 * Purchase instructions: the independently approved business intent a payment
 * must match. Trusted sources only: humans in AgentTrust, or ERP integrations.
 * Agents can read the instructions assigned to them, never create/modify/approve.
 */
@Injectable()
export class InstructionsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  // ---------------------------------------------------------------- human source

  async createByHuman(user: HumanPrincipal, body: InstructionInput) {
    return this.prisma.tx(async (tx) => {
      const n = await this.normalize(tx, user.organizationId, body);
      const id = newId(IdPrefix.instruction);
      await tx.purchaseInstruction.create({
        data: {
          id, organizationId: user.organizationId, source: 'human', agentId: body.agentId, supplierId: body.supplierId,
          purchaseOrderId: body.purchaseOrderId ?? null, fulfillmentType: body.fulfillmentType, currency: body.currency,
          maxAmountCents: n.maxAmountCents, maxUses: body.maxUses, validFrom: n.validFrom, expiresAt: n.expiresAt,
          description: body.description, materialHash: n.materialHash, linesHash: n.linesHash, status: 'pending_approval',
          createdByUserId: user.userId,
        },
      });
      await this.writeLines(tx, id, n.lines);
      const created = await this.load(tx, user.organizationId, id);
      await this.snapshot(tx, created, 'created', `user:${user.userId}`);
      await this.audit.append(tx, {
        organizationId: user.organizationId, actorType: 'user', actorId: user.userId, eventType: 'instruction.created', subjectId: id,
        payload: { version: 1, agentId: body.agentId, supplierId: body.supplierId, maxAmountCents: toSafeNumber(n.maxAmountCents), maxUses: body.maxUses, linesHash: n.linesHash },
      });
      return serializeInstruction(created);
    });
  }

  /** Material amendment by a human: new version, back to pending approval, outstanding authorizations invalidated. */
  async amendByHuman(user: HumanPrincipal, id: string, body: InstructionInput) {
    return this.prisma.tx(async (tx) => {
      await lockLiveAuthorizationsBy(tx, 'instructionId', id);
      const current = await this.lock(tx, user.organizationId, id);
      if (current.source !== 'human') throw Errors.conflict('ERP_MANAGED', 'ERP-synced instructions can only change through the ERP integration');
      if (current.status === 'revoked' || current.status === 'rejected') throw Errors.conflict('INSTRUCTION_CLOSED', `Instruction is ${current.status}`);
      const n = await this.normalize(tx, user.organizationId, body, current.validFrom);
      if (n.materialHash === current.materialHash) {
        const updated = await tx.purchaseInstruction.update({ where: { id }, data: { description: body.description }, include: { lines: true } });
        return serializeInstruction(updated);
      }
      const version = current.version + 1;
      await tx.purchaseInstruction.update({
        where: { id },
        data: {
          version, agentId: body.agentId, supplierId: body.supplierId, purchaseOrderId: body.purchaseOrderId ?? null,
          fulfillmentType: body.fulfillmentType, currency: body.currency, maxAmountCents: n.maxAmountCents, maxUses: body.maxUses,
          validFrom: n.validFrom, expiresAt: n.expiresAt, description: body.description, materialHash: n.materialHash, linesHash: n.linesHash,
          status: 'pending_approval', approvedByUserId: null, approvedAt: null, approvalSource: null, createdByUserId: user.userId,
        },
      });
      await tx.purchaseInstructionLine.deleteMany({ where: { instructionId: id } });
      await this.writeLines(tx, id, n.lines);
      const updated = await this.load(tx, user.organizationId, id);
      await this.snapshot(tx, updated, 'amended', `user:${user.userId}`);
      await invalidateLiveAuthorizations(tx, this.audit, {
        organizationId: user.organizationId, where: { instructionId: id },
        reason: `purchase instruction changed (v${version}: amended)`, actor: { type: 'user', id: user.userId },
      });
      await this.audit.append(tx, {
        organizationId: user.organizationId, actorType: 'user', actorId: user.userId, eventType: 'instruction.amended', subjectId: id,
        payload: { version, linesHash: n.linesHash, maxAmountCents: toSafeNumber(n.maxAmountCents), status: 'pending_approval' },
      });
      return serializeInstruction(updated);
    });
  }

  /**
   * Independent approval by an authenticated human: a different person from
   * the requester, holding at least the instruction's amount in authority.
   */
  async approve(user: HumanPrincipal, id: string, comment?: string) {
    return this.prisma.tx(async (tx) => {
      await lockLiveAuthorizationsBy(tx, 'instructionId', id);
      const ins = await this.lock(tx, user.organizationId, id);
      if (ins.status !== 'pending_approval') throw Errors.conflict('NOT_PENDING_APPROVAL', `Instruction is ${ins.status}`);
      if (ins.expiresAt <= new Date()) throw Errors.conflict('INSTRUCTION_EXPIRED', 'Instruction has expired');
      if (ins.createdByUserId === user.userId) {
        throw Errors.forbidden('SEPARATION_OF_DUTIES', 'The person who requested or amended an instruction cannot approve it');
      }
      if (cents(ins.maxAmountCents) > user.spendingAuthorityCents) {
        throw Errors.forbidden('INSUFFICIENT_AUTHORITY', 'Instruction amount exceeds your approval authority');
      }
      await tx.purchaseInstruction.update({
        where: { id },
        data: { status: 'approved', approvedByUserId: user.userId, approvedAt: new Date(), approvalSource: 'agenttrust_user' },
      });
      const approved = await this.load(tx, user.organizationId, id);
      await this.snapshot(tx, approved, 'approved', `user:${user.userId}`);
      // Clear stale non-approvable reviews that referenced the unapproved instruction.
      await invalidateLiveAuthorizations(tx, this.audit, {
        organizationId: user.organizationId, where: { instructionId: id },
        reason: 'purchase instruction approval changed; resubmit', actor: { type: 'user', id: user.userId },
      });
      await this.audit.append(tx, {
        organizationId: user.organizationId, actorType: 'user', actorId: user.userId, eventType: 'instruction.approved', subjectId: id,
        payload: { version: ins.version, linesHash: ins.linesHash, maxAmountCents: cents(ins.maxAmountCents), comment: comment ?? null },
      });
      return serializeInstruction(approved);
    });
  }

  async reject(user: HumanPrincipal, id: string, reason: string) {
    return this.close(user, id, 'rejected', reason, ['pending_approval']);
  }

  /** Revocation is final: outstanding authorizations die immediately. */
  async revoke(user: HumanPrincipal, id: string, reason: string) {
    return this.close(user, id, 'revoked', reason, ['pending_approval', 'approved']);
  }

  private async close(user: HumanPrincipal, id: string, status: 'rejected' | 'revoked', reason: string, from: string[]) {
    return this.prisma.tx(async (tx) => {
      await lockLiveAuthorizationsBy(tx, 'instructionId', id);
      const ins = await this.lock(tx, user.organizationId, id);
      if (!from.includes(ins.status)) throw Errors.conflict('INVALID_TRANSITION', `Instruction is ${ins.status}`);
      await tx.purchaseInstruction.update({
        where: { id },
        data: { status, revokedAt: new Date(), revokedBy: `user:${user.userId}`, revokeReason: reason },
      });
      const closed = await this.load(tx, user.organizationId, id);
      await this.snapshot(tx, closed, status, `user:${user.userId}`);
      await invalidateLiveAuthorizations(tx, this.audit, {
        organizationId: user.organizationId, where: { instructionId: id },
        reason: `purchase instruction ${status}: ${reason}`, actor: { type: 'user', id: user.userId },
      });
      await this.audit.append(tx, {
        organizationId: user.organizationId, actorType: 'user', actorId: user.userId, eventType: `instruction.${status}`, subjectId: id,
        payload: { version: ins.version, reason },
      });
      return serializeInstruction(closed);
    });
  }

  // ------------------------------------------------------------------ ERP source

  /**
   * Upserts an instruction from a trusted ERP. A successful sync NEVER implies
   * approval: an instruction becomes approved only if the ERP reports an
   * approval AND the integration was explicitly granted
   * `instructions:attest_approval`; otherwise a human approves in AgentTrust.
   */
  async syncFromErp(integration: IntegrationPrincipal, body: ErpSyncInput) {
    const orgId = integration.organizationId;
    const updatedAt = new Date(body.externalUpdatedAt);
    return this.prisma.tx(async (tx) => {
      const existing = await tx.purchaseInstruction.findFirst({
        where: { organizationId: orgId, sourceSystem: integration.sourceSystem, externalId: body.externalId },
      });
      if (existing) await lockLiveAuthorizationsBy(tx, 'instructionId', existing.id);
      const current = existing ? await this.lock(tx, orgId, existing.id) : null;
      if (current?.externalUpdatedAt && updatedAt < current.externalUpdatedAt) {
        throw Errors.conflict('STALE_SYNC', 'ERP payload is older than the stored version');
      }
      if (current && (current.status === 'revoked')) {
        throw Errors.conflict('INSTRUCTION_REVOKED', 'Revoked in AgentTrust; sync a new external id to re-issue');
      }

      const n = await this.normalize(tx, orgId, body, current?.validFrom);
      const erpApproved = body.erpApproval.status === 'approved' && !!body.erpApproval.approvedBy && !!body.erpApproval.approvedAt;
      const attestable = erpApproved && integration.scopes.includes('instructions:attest_approval');
      const erpFields = {
        externalVersion: body.externalVersion, externalUpdatedAt: updatedAt, syncedAt: new Date(), integrationId: integration.integrationId,
        erpApprovalStatus: body.erpApproval.status, erpApprovedBy: body.erpApproval.approvedBy ?? null,
        erpApprovedAt: body.erpApproval.approvedAt ? new Date(body.erpApproval.approvedAt) : null,
      };
      const content = {
        agentId: body.agentId, supplierId: body.supplierId, purchaseOrderId: body.purchaseOrderId ?? null, fulfillmentType: body.fulfillmentType,
        currency: body.currency, maxAmountCents: n.maxAmountCents, maxUses: body.maxUses, validFrom: n.validFrom, expiresAt: n.expiresAt,
        description: body.description, materialHash: n.materialHash, linesHash: n.linesHash,
      };
      const approvalFields = body.erpApproval.status === 'rejected'
        ? { status: 'rejected' as const, approvedByUserId: null, approvedAt: null, approvalSource: null }
        : attestable
          ? { status: 'approved' as const, approvedByUserId: null, approvedAt: erpFields.erpApprovedAt, approvalSource: 'erp_attested' }
          : { status: 'pending_approval' as const, approvedByUserId: null, approvedAt: null, approvalSource: null };

      const actor = { type: 'integration' as const, id: integration.integrationId };
      let id: string;
      let changeType: string;
      let version: number;
      let invalidate = false;

      if (!current) {
        id = newId(IdPrefix.instruction);
        version = 1;
        changeType = 'synced_new';
        await tx.purchaseInstruction.create({
          data: { id, organizationId: orgId, source: 'erp', sourceSystem: integration.sourceSystem, externalId: body.externalId, ...content, ...erpFields, ...approvalFields },
        });
        await this.writeLines(tx, id, n.lines);
      } else {
        id = current.id;
        const material = n.materialHash !== current.materialHash;
        const keepHumanApproval = !material && current.status === 'approved' && current.approvalSource === 'agenttrust_user' && body.erpApproval.status !== 'rejected';
        const nextStatus = keepHumanApproval ? current.status : approvalFields.status;
        version = material ? current.version + 1 : current.version;
        changeType = material ? 'synced_material_change' : nextStatus !== current.status ? `synced_status_${nextStatus}` : 'synced_unchanged';
        invalidate = material || (current.status === 'approved' && nextStatus !== 'approved');
        await tx.purchaseInstruction.update({
          where: { id },
          data: { ...content, ...erpFields, version, ...(keepHumanApproval ? {} : approvalFields) },
        });
        if (material) {
          await tx.purchaseInstructionLine.deleteMany({ where: { instructionId: id } });
          await this.writeLines(tx, id, n.lines);
        }
      }

      const saved = await this.load(tx, orgId, id);
      if (changeType !== 'synced_unchanged') await this.snapshot(tx, saved, changeType, `integration:${integration.integrationId}`);
      if (invalidate) {
        await invalidateLiveAuthorizations(tx, this.audit, {
          organizationId: orgId, where: { instructionId: id }, reason: `purchase instruction changed by ERP sync (v${version}: ${changeType})`, actor,
        });
      }
      await this.audit.append(tx, {
        organizationId: orgId, actorType: 'integration', actorId: integration.integrationId, eventType: 'instruction.synced', subjectId: id,
        payload: {
          sourceSystem: integration.sourceSystem, externalId: body.externalId, externalVersion: body.externalVersion, version, changeType,
          status: saved.status, erpApprovalStatus: body.erpApproval.status, approvalAttested: saved.approvalSource === 'erp_attested',
        },
      });
      return serializeInstruction(saved);
    });
  }

  // ----------------------------------------------------------------------- reads

  async list(orgId: string, filter: { agentId?: string; status?: PurchaseInstruction['status'] }) {
    const rows = await this.prisma.purchaseInstruction.findMany({
      where: { organizationId: orgId, ...(filter.agentId ? { agentId: filter.agentId } : {}), ...(filter.status ? { status: filter.status } : {}) },
      include: { lines: true },
      orderBy: { createdAt: 'desc' },
      take: 200,
    });
    return { instructions: rows.map(serializeInstruction) };
  }

  async get(orgId: string, id: string, opts: { agentId?: string } = {}) {
    const row = await this.prisma.purchaseInstruction.findFirst({
      where: { id, organizationId: orgId, ...(opts.agentId ? { agentId: opts.agentId } : {}) },
      include: { lines: true },
    });
    if (!row) throw Errors.notFound('Purchase instruction');
    return serializeInstruction(row);
  }

  async versions(orgId: string, id: string) {
    await this.get(orgId, id);
    const rows = await this.prisma.purchaseInstructionVersion.findMany({ where: { instructionId: id }, orderBy: { createdAt: 'asc' } });
    return { versions: rows.map((v) => ({ version: v.version, changeType: v.changeType, changedBy: v.changedBy, createdAt: v.createdAt.toISOString(), snapshot: v.snapshot })) };
  }

  // --------------------------------------------------------------------- helpers

  /** Validates references and computes exact totals + hashes. All money stays integer cents. */
  private async normalize(tx: Tx, orgId: string, body: InstructionInput, defaultValidFrom?: Date): Promise<Normalized> {
    const seen = new Set<number>();
    const lines: NormalizedLine[] = body.lines.map((l) => {
      if (seen.has(l.lineNumber)) throw Errors.invalid(`Duplicate line number ${l.lineNumber}`);
      seen.add(l.lineNumber);
      let quantityMilli: bigint;
      try {
        quantityMilli = parseQuantity(l.quantity);
      } catch (e) {
        throw Errors.invalid(`Line ${l.lineNumber}: ${e instanceof Error ? e.message : 'invalid quantity'}`);
      }
      const total = exactLineTotal(quantityMilli, BigInt(l.unitPriceCents));
      if (total === null) throw Errors.invalid(`Line ${l.lineNumber}: quantity × unit price is not an exact number of cents`);
      return { lineNumber: l.lineNumber, sku: l.sku ?? null, description: l.description, unit: l.unit ?? null, quantityMilli, unitPriceCents: BigInt(l.unitPriceCents), lineTotalCents: total };
    });
    const linesTotal = lines.reduce((acc, l) => acc + l.lineTotalCents, 0n);
    if (linesTotal <= 0n) throw Errors.invalid('Instruction total must be positive');
    const maxAmountCents = body.maxAmountCents !== undefined ? BigInt(body.maxAmountCents) : linesTotal;
    if (maxAmountCents > linesTotal) throw Errors.invalid('maxAmountCents cannot exceed the approved lines total');

    const now = new Date();
    // An omitted validFrom keeps the existing start (amend/re-sync) so re-sending identical content is not a "change".
    const validFrom = body.validFrom ? new Date(body.validFrom) : defaultValidFrom ?? now;
    const expiresAt = new Date(body.expiresAt);
    if (expiresAt <= validFrom || expiresAt <= now) throw Errors.invalid('expiresAt must be in the future and after validFrom');
    if (expiresAt.getTime() - validFrom.getTime() > MAX_INSTRUCTION_DAYS * 86_400_000) throw Errors.invalid(`Instructions may not exceed ${MAX_INSTRUCTION_DAYS} days`);

    const agent = await tx.agent.findFirst({ where: { id: body.agentId, organizationId: orgId } });
    if (!agent || agent.status === 'revoked') throw Errors.invalid('agentId must be a non-revoked agent in your organization');
    const supplier = await tx.supplier.findFirst({ where: { id: body.supplierId, organizationId: orgId } });
    if (!supplier) throw Errors.invalid('supplierId must be a supplier in your organization');
    if (body.purchaseOrderId) {
      const po = await tx.purchaseOrder.findFirst({ where: { id: body.purchaseOrderId, organizationId: orgId } });
      if (!po) throw Errors.invalid('purchaseOrderId must be a purchase order in your organization');
      if (po.supplierId !== body.supplierId) throw Errors.invalid('Purchase order is for a different supplier');
      if (po.currency !== body.currency) throw Errors.invalid('Purchase order currency differs; currencies are never converted');
      if (maxAmountCents > po.approvedAmountCents) throw Errors.invalid('Instruction amount exceeds the purchase order amount');
    }

    const lineMaterial = lines.map((l) => ({
      n: l.lineNumber, sku: l.sku, unit: l.unit, q: toSafeNumber(l.quantityMilli), p: toSafeNumber(l.unitPriceCents), t: toSafeNumber(l.lineTotalCents),
    }));
    const linesHash = `il_${sha256Hex(canonicalJson(lineMaterial))}`;
    const materialHash = sha256Hex(
      canonicalJson({
        agentId: body.agentId, supplierId: body.supplierId, purchaseOrderId: body.purchaseOrderId ?? null, fulfillmentType: body.fulfillmentType,
        currency: body.currency, maxAmountCents: toSafeNumber(maxAmountCents), maxUses: body.maxUses,
        validFrom: validFrom.toISOString(), expiresAt: expiresAt.toISOString(), lines: lineMaterial,
      }),
    );
    return { lines, maxAmountCents, validFrom, expiresAt, materialHash, linesHash };
  }

  private async writeLines(tx: Tx, instructionId: string, lines: NormalizedLine[]) {
    await tx.purchaseInstructionLine.createMany({
      data: lines.map((l) => ({
        id: newId(IdPrefix.instructionLine), instructionId, lineNumber: l.lineNumber, sku: l.sku, description: l.description, unit: l.unit,
        quantityMilli: l.quantityMilli, unitPriceCents: l.unitPriceCents, lineTotalCents: l.lineTotalCents,
      })),
    });
  }

  private async lock(tx: Tx, orgId: string, id: string): Promise<PurchaseInstruction> {
    const rows = await tx.$queryRaw<{ id: string }[]>`
      SELECT id FROM "PurchaseInstruction" WHERE id = ${id} AND "organizationId" = ${orgId} FOR UPDATE`;
    if (rows.length !== 1) throw Errors.notFound('Purchase instruction');
    return (await tx.purchaseInstruction.findUnique({ where: { id } }))!;
  }

  private async load(tx: Tx, orgId: string, id: string): Promise<InstructionWithLines> {
    const row = await tx.purchaseInstruction.findFirst({ where: { id, organizationId: orgId }, include: { lines: true } });
    if (!row) throw Errors.notFound('Purchase instruction');
    return row;
  }

  private async snapshot(tx: Tx, ins: InstructionWithLines, changeType: string, changedBy: string) {
    await tx.purchaseInstructionVersion.create({
      data: {
        id: newId(IdPrefix.instructionVersion), organizationId: ins.organizationId, instructionId: ins.id, version: ins.version, changeType, changedBy,
        snapshot: JSON.parse(JSON.stringify(serializeInstruction(ins))),
      },
    });
  }
}

export function serializeInstruction(i: InstructionWithLines) {
  return {
    id: i.id,
    organizationId: i.organizationId,
    version: i.version,
    status: i.status,
    source: i.source,
    sourceSystem: i.sourceSystem,
    externalId: i.externalId,
    externalVersion: i.externalVersion,
    syncedAt: i.syncedAt?.toISOString() ?? null,
    erpApprovalStatus: i.erpApprovalStatus,
    agentId: i.agentId,
    supplierId: i.supplierId,
    purchaseOrderId: i.purchaseOrderId,
    fulfillmentType: i.fulfillmentType,
    currency: i.currency,
    maxAmountCents: cents(i.maxAmountCents),
    maxUses: i.maxUses,
    validFrom: i.validFrom.toISOString(),
    expiresAt: i.expiresAt.toISOString(),
    description: i.description,
    linesHash: i.linesHash,
    createdByUserId: i.createdByUserId,
    approvedByUserId: i.approvedByUserId,
    approvedAt: i.approvedAt?.toISOString() ?? null,
    approvalSource: i.approvalSource,
    revokeReason: i.revokeReason,
    lines: [...i.lines]
      .sort((a, b) => a.lineNumber - b.lineNumber)
      .map((l) => ({
        lineNumber: l.lineNumber, sku: l.sku, description: l.description, unit: l.unit,
        quantity: formatQuantity(l.quantityMilli), unitPriceCents: cents(l.unitPriceCents), lineTotalCents: cents(l.lineTotalCents),
      })),
  };
}
