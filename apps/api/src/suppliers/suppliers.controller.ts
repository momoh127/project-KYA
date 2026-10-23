import { Body, Controller, Get, Param, Patch, Post } from '@nestjs/common';
import type { Prisma, Supplier } from '@prisma/client';
import { z } from 'zod';
import { IdPrefix, newId } from '@agenttrust/shared';
import { CurrentUser, FreshAuth, Human, type HumanPrincipal } from '../auth/principal';
import { AuditService } from '../audit/audit.service';
import { invalidateLiveAuthorizations } from '../authorizations/invalidation';
import { CryptoService } from '../common/crypto.service';
import { Errors } from '../common/errors';
import { PrismaService, type Tx } from '../common/prisma.service';
import { zPaymentDestination, ZodPipe } from '../common/validation';

/** Bank-detail changes require a login within this many seconds (step-up authentication). */
export const STEP_UP_MAX_AGE_SECONDS = 300;

const CreateSupplier = z
  .object({
    name: z.string().min(1).max(200),
    externalReference: z.string().max(200).optional(),
    paymentDestination: zPaymentDestination.optional(),
  })
  .strict();

const UpdateSupplier = z
  .object({
    name: z.string().min(1).max(200).optional(),
    status: z.enum(['active', 'blocked']).optional(),
    paymentDestination: zPaymentDestination.optional(),
  })
  .strict();

const VerifyDestination = z
  .object({
    /**
     * How ownership was confirmed out-of-band, e.g. "Called supplier AP at
     * +1-555-0100 (number from signed contract, not from the invoice/email);
     * confirmed account ending 3456". A fingerprint alone proves nothing about
     * WHO owns an account; this records the human verification step.
     */
    evidence: z.string().min(20).max(2000),
    /** Must equal the last 4 digits on record, so the verifier confirms the right account. */
    confirmedLast4: z.string().regex(/^[A-Z0-9]{4}$/),
  })
  .strict();

/**
 * Supplier records are the trusted source for payee verification, so changes
 * to them are treated as high-risk operations:
 *
 *  - Bank details are always created/changed in `pending` state. They become
 *    `verified` only through a separate verification step performed by a
 *    DIFFERENT administrator (dual control), with step-up authentication and
 *    recorded out-of-band evidence. This applies to onboarding too.
 *  - Changing bank details requires step-up authentication.
 *  - Every change creates a new immutable supplier version.
 *  - Every change invalidates live authorizations for that supplier; the
 *    gateway additionally refuses any authorization bound to an old version.
 *  - Raw account numbers are never stored (keyed fingerprint + last 4).
 */
@Controller('v1/suppliers')
export class SuppliersController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly crypto: CryptoService,
  ) {}

  @Post()
  @Human('admin')
  async create(@CurrentUser() admin: HumanPrincipal, @Body(new ZodPipe(CreateSupplier)) body: z.infer<typeof CreateSupplier>) {
    if (body.paymentDestination) this.requireStepUp(admin);
    const pd = body.paymentDestination ? this.crypto.payeeFingerprint(body.paymentDestination) : null;
    const id = newId(IdPrefix.supplier);
    const now = new Date();
    return this.prisma.tx(async (tx) => {
      const s = await tx.supplier.create({
        data: {
          id,
          organizationId: admin.organizationId,
          name: body.name,
          externalReference: body.externalReference,
          verificationStatus: pd ? 'pending' : 'unverified',
          paymentDestinationFingerprint: pd?.fingerprint,
          paymentDestinationType: pd?.type,
          paymentDestinationLast4: pd?.last4,
          paymentCounterpartyRef: pd ? counterpartyRef(id, 1) : null,
          paymentDestinationChangedByUserId: pd ? admin.userId : null,
          paymentDestinationChangedAt: pd ? now : null,
          version: 1,
        },
      });
      await this.snapshot(tx, s, 'created', admin.userId);
      await this.audit.append(tx, {
        organizationId: admin.organizationId,
        actorType: 'user',
        actorId: admin.userId,
        eventType: 'supplier.created',
        subjectId: id,
        payload: { name: body.name, version: 1, verificationStatus: s.verificationStatus, paymentDestinationLast4: pd?.last4 ?? null, paymentDestinationFingerprint: pd?.fingerprint ?? null },
      });
      return serializeSupplier(s);
    });
  }

  @Get()
  @Human()
  async list(@CurrentUser() user: HumanPrincipal) {
    const suppliers = await this.prisma.supplier.findMany({ where: { organizationId: user.organizationId }, orderBy: { createdAt: 'asc' } });
    return { suppliers: suppliers.map(serializeSupplier) };
  }

  @Get(':id')
  @Human()
  async get(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    return serializeSupplier(await this.find(this.prisma, user, id));
  }

  @Get(':id/versions')
  @Human('admin', 'approver')
  async versions(@CurrentUser() user: HumanPrincipal, @Param('id') id: string) {
    await this.find(this.prisma, user, id);
    const versions = await this.prisma.supplierVersion.findMany({ where: { supplierId: id }, orderBy: { version: 'asc' } });
    return { versions: versions.map((v) => ({ version: v.version, changeType: v.changeType, changedByUserId: v.changedByUserId, createdAt: v.createdAt.toISOString(), snapshot: v.snapshot })) };
  }

  @Patch(':id')
  @Human('admin')
  update(@CurrentUser() admin: HumanPrincipal, @Param('id') id: string, @Body(new ZodPipe(UpdateSupplier)) body: z.infer<typeof UpdateSupplier>) {
    if (body.paymentDestination) this.requireStepUp(admin);
    return this.prisma.tx(async (tx) => {
      const s = await this.lockSupplier(tx, admin, id);
      const now = new Date();
      const version = s.version + 1;
      const data: Prisma.SupplierUpdateInput = { version };
      const changes: Record<string, unknown> = {};
      let changeType = 'updated';

      if (body.name !== undefined && body.name !== s.name) { data.name = body.name; changes.name = body.name; }
      if (body.status !== undefined && body.status !== s.status) { data.status = body.status; changes.status = body.status; changeType = `status_${body.status}`; }
      if (body.paymentDestination) {
        const pd = this.crypto.payeeFingerprint(body.paymentDestination);
        if (pd.fingerprint !== s.paymentDestinationFingerprint) {
          changeType = 'payment_destination_changed';
          Object.assign(data, {
            paymentDestinationFingerprint: pd.fingerprint,
            paymentDestinationType: pd.type,
            paymentDestinationLast4: pd.last4,
            paymentCounterpartyRef: counterpartyRef(id, version),
            paymentDestinationChangedByUserId: admin.userId,
            paymentDestinationChangedAt: now,
            verificationStatus: 'pending',
            verifiedByUserId: null,
            verifiedAt: null,
            verificationEvidence: null,
          } satisfies Prisma.SupplierUpdateInput);
          changes.paymentDestinationLast4 = pd.last4;
          changes.previousPaymentDestinationLast4 = s.paymentDestinationLast4;
          changes.verificationStatus = 'pending';
        }
      }
      if (Object.keys(changes).length === 0) return serializeSupplier(s);

      const updated = await tx.supplier.update({ where: { id }, data });
      await this.snapshot(tx, updated, changeType, admin.userId);
      await this.audit.append(tx, {
        organizationId: admin.organizationId,
        actorType: 'user',
        actorId: admin.userId,
        eventType: changeType === 'payment_destination_changed' ? 'supplier.payment_destination_changed' : 'supplier.updated',
        subjectId: id,
        payload: { version, ...changes },
      });
      await invalidateLiveAuthorizations(tx, this.audit, {
        organizationId: admin.organizationId,
        where: { supplierId: id },
        reason: `supplier record changed (v${version}: ${changeType})`,
        actor: { type: 'user', id: admin.userId },
      });
      return serializeSupplier(updated);
    });
  }

  /** Second-person verification of a pending payment destination (dual control + step-up + evidence). */
  @Post(':id/verify-payment-destination')
  @Human('admin')
  @FreshAuth(STEP_UP_MAX_AGE_SECONDS)
  verify(@CurrentUser() admin: HumanPrincipal, @Param('id') id: string, @Body(new ZodPipe(VerifyDestination)) body: z.infer<typeof VerifyDestination>) {
    return this.prisma.tx(async (tx) => {
      const s = await this.lockSupplier(tx, admin, id);
      if (!s.paymentDestinationFingerprint) throw Errors.invalid('Supplier has no payment destination to verify');
      if (s.verificationStatus === 'verified') throw Errors.conflict('ALREADY_VERIFIED', 'Payment destination is already verified');
      if (s.paymentDestinationChangedByUserId === admin.userId) {
        throw Errors.forbidden('DUAL_CONTROL_REQUIRED', 'The administrator who entered the bank details cannot also verify them');
      }
      if (body.confirmedLast4 !== s.paymentDestinationLast4) {
        throw Errors.conflict('VERIFICATION_MISMATCH', 'Confirmed last 4 digits do not match the account on record');
      }
      const version = s.version + 1;
      const updated = await tx.supplier.update({
        where: { id },
        data: { verificationStatus: 'verified', verifiedByUserId: admin.userId, verifiedAt: new Date(), verificationEvidence: body.evidence, version },
      });
      await this.snapshot(tx, updated, 'payment_destination_verified', admin.userId);
      await this.audit.append(tx, {
        organizationId: admin.organizationId,
        actorType: 'user',
        actorId: admin.userId,
        eventType: 'supplier.payment_destination_verified',
        subjectId: id,
        payload: { version, paymentDestinationLast4: s.paymentDestinationLast4, enteredByUserId: s.paymentDestinationChangedByUserId, evidence: body.evidence },
      });
      await invalidateLiveAuthorizations(tx, this.audit, {
        organizationId: admin.organizationId,
        where: { supplierId: id },
        reason: `supplier record changed (v${version}: payment_destination_verified)`,
        actor: { type: 'user', id: admin.userId },
      });
      return serializeSupplier(updated);
    });
  }

  private requireStepUp(admin: HumanPrincipal): void {
    if (Math.floor(Date.now() / 1000) - admin.authTime > STEP_UP_MAX_AGE_SECONDS) {
      throw Errors.forbidden('REAUTHENTICATION_REQUIRED', 'Changing bank details requires a recent sign-in (step-up authentication)');
    }
  }

  private async find(db: Tx | PrismaService, user: HumanPrincipal, id: string): Promise<Supplier> {
    const s = await db.supplier.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!s) throw Errors.notFound('Supplier');
    return s;
  }

  private async lockSupplier(tx: Tx, user: HumanPrincipal, id: string): Promise<Supplier> {
    const rows = await tx.$queryRaw<{ id: string }[]>`
      SELECT id FROM "Supplier" WHERE id = ${id} AND "organizationId" = ${user.organizationId} FOR UPDATE`;
    if (rows.length !== 1) throw Errors.notFound('Supplier');
    return (await tx.supplier.findUnique({ where: { id } }))!;
  }

  private async snapshot(tx: Tx, s: Supplier, changeType: string, userId: string): Promise<void> {
    await tx.supplierVersion.create({
      data: {
        id: newId(IdPrefix.supplierVersion),
        organizationId: s.organizationId,
        supplierId: s.id,
        version: s.version,
        changeType,
        changedByUserId: userId,
        snapshot: {
          name: s.name,
          status: s.status,
          verificationStatus: s.verificationStatus,
          paymentDestinationType: s.paymentDestinationType,
          paymentDestinationLast4: s.paymentDestinationLast4,
          paymentDestinationFingerprint: s.paymentDestinationFingerprint,
          paymentCounterpartyRef: s.paymentCounterpartyRef,
          verifiedByUserId: s.verifiedByUserId,
          verificationEvidence: s.verificationEvidence,
        },
      },
    });
  }
}

/** Sandbox counterparty id; a new destination always gets a new provider counterparty. */
function counterpartyRef(supplierId: string, version: number): string {
  return `sandbox_cp_${supplierId.slice(4, 16)}_v${version}`;
}

export function serializeSupplier(s: Supplier) {
  return {
    id: s.id,
    organizationId: s.organizationId,
    name: s.name,
    externalReference: s.externalReference,
    version: s.version,
    verificationStatus: s.verificationStatus,
    status: s.status,
    paymentDestination: s.paymentDestinationLast4 ? { type: s.paymentDestinationType, last4: s.paymentDestinationLast4 } : null,
    verifiedAt: s.verifiedAt?.toISOString() ?? null,
    createdAt: s.createdAt.toISOString(),
  };
}
