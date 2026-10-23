import { Body, Controller, Get, Param, Patch, Post } from '@nestjs/common';
import { z } from 'zod';
import { IdPrefix, newId } from '@agenttrust/shared';
import { CurrentUser, Human, type HumanPrincipal } from '../auth/principal';
import { AuditService } from '../audit/audit.service';
import { CryptoService } from '../common/crypto.service';
import { Errors } from '../common/errors';
import { PrismaService } from '../common/prisma.service';
import { zPaymentDestination, ZodPipe } from '../common/validation';

const CreateSupplier = z
  .object({
    name: z.string().min(1).max(200),
    externalReference: z.string().max(200).optional(),
    paymentDestination: zPaymentDestination.optional(),
    /** Admin attests the supplier and bank details were verified out-of-band. */
    verificationStatus: z.enum(['unverified', 'pending', 'verified']).default('pending'),
  })
  .strict();

const UpdateSupplier = z
  .object({
    name: z.string().min(1).max(200).optional(),
    status: z.enum(['active', 'blocked']).optional(),
    paymentDestination: zPaymentDestination.optional(),
    verificationStatus: z.enum(['unverified', 'pending', 'verified']).optional(),
  })
  .strict();

/**
 * Supplier records are the trusted source for payee verification. Only humans
 * (admins) write them, never agents. Bank details are stored only as a keyed
 * fingerprint + last 4 digits.
 *
 * Dual control: when an existing supplier's bank details change, the record
 * drops to `pending` and must be re-verified by a DIFFERENT administrator
 * than the one who entered the new details. This blocks the classic "change
 * the vendor's bank account" fraud, including by a single compromised insider
 * account. (Initial onboarding may be created directly as `verified`, on the
 * assumption it follows the organization's offline vendor-vetting process.)
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
    const pd = body.paymentDestination ? this.crypto.payeeFingerprint(body.paymentDestination) : null;
    if (body.verificationStatus === 'verified' && !pd) throw Errors.invalid('A verified supplier needs a payment destination');
    const id = newId(IdPrefix.supplier);
    const now = new Date();
    return this.prisma.tx(async (tx) => {
      const s = await tx.supplier.create({
        data: {
          id,
          organizationId: admin.organizationId,
          name: body.name,
          externalReference: body.externalReference,
          verificationStatus: body.verificationStatus,
          paymentDestinationFingerprint: pd?.fingerprint,
          paymentDestinationType: pd?.type,
          paymentDestinationLast4: pd?.last4,
          paymentCounterpartyRef: pd ? `sandbox_cp_${id.slice(4, 16)}` : null,
          paymentDestinationChangedByUserId: pd ? admin.userId : null,
          paymentDestinationChangedAt: pd ? now : null,
          verifiedByUserId: body.verificationStatus === 'verified' ? admin.userId : null,
          verifiedAt: body.verificationStatus === 'verified' ? now : null,
        },
      });
      await this.audit.append(tx, {
        organizationId: admin.organizationId,
        actorType: 'user',
        actorId: admin.userId,
        eventType: 'supplier.created',
        subjectId: id,
        payload: { name: body.name, verificationStatus: body.verificationStatus, paymentDestinationLast4: pd?.last4 ?? null, paymentDestinationFingerprint: pd?.fingerprint ?? null },
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
    const s = await this.prisma.supplier.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!s) throw Errors.notFound('Supplier');
    return serializeSupplier(s);
  }

  @Patch(':id')
  @Human('admin')
  update(@CurrentUser() admin: HumanPrincipal, @Param('id') id: string, @Body(new ZodPipe(UpdateSupplier)) body: z.infer<typeof UpdateSupplier>) {
    return this.prisma.tx(async (tx) => {
      const s = await tx.supplier.findFirst({ where: { id, organizationId: admin.organizationId } });
      if (!s) throw Errors.notFound('Supplier');
      const now = new Date();
      const data: Parameters<typeof tx.supplier.update>[0]['data'] = {};
      const changes: Record<string, unknown> = {};

      if (body.name !== undefined) { data.name = body.name; changes.name = body.name; }
      if (body.status !== undefined) { data.status = body.status; changes.status = body.status; }

      let bankChanged = false;
      if (body.paymentDestination) {
        const pd = this.crypto.payeeFingerprint(body.paymentDestination);
        if (pd.fingerprint !== s.paymentDestinationFingerprint) {
          bankChanged = true;
          Object.assign(data, {
            paymentDestinationFingerprint: pd.fingerprint,
            paymentDestinationType: pd.type,
            paymentDestinationLast4: pd.last4,
            paymentCounterpartyRef: `sandbox_cp_${id.slice(4, 12)}_${now.getTime().toString(36)}`,
            paymentDestinationChangedByUserId: admin.userId,
            paymentDestinationChangedAt: now,
            verificationStatus: 'pending',
            verifiedByUserId: null,
            verifiedAt: null,
          });
          changes.paymentDestinationLast4 = pd.last4;
          changes.previousPaymentDestinationLast4 = s.paymentDestinationLast4;
          changes.verificationStatus = 'pending';
        }
      }

      if (body.verificationStatus !== undefined) {
        if (bankChanged && body.verificationStatus === 'verified') {
          throw Errors.forbidden('DUAL_CONTROL_REQUIRED', 'Bank details changed: a different administrator must verify them');
        }
        if (body.verificationStatus === 'verified') {
          if (!s.paymentDestinationFingerprint) throw Errors.invalid('Supplier has no payment destination to verify');
          // Whoever last set the bank details cannot be the one who verifies them.
          if (s.verificationStatus !== 'verified' && s.paymentDestinationChangedByUserId === admin.userId) {
            throw Errors.forbidden('DUAL_CONTROL_REQUIRED', 'The administrator who set the bank details cannot also verify them');
          }
          data.verifiedByUserId = admin.userId;
          data.verifiedAt = now;
        }
        if (!bankChanged) {
          data.verificationStatus = body.verificationStatus;
          changes.verificationStatus = body.verificationStatus;
        }
      }

      const updated = await tx.supplier.update({ where: { id }, data });
      await this.audit.append(tx, {
        organizationId: admin.organizationId,
        actorType: 'user',
        actorId: admin.userId,
        eventType: bankChanged ? 'supplier.payment_destination_changed' : 'supplier.updated',
        subjectId: id,
        payload: changes,
      });
      return serializeSupplier(updated);
    });
  }
}

export function serializeSupplier(s: {
  id: string; organizationId: string; name: string; externalReference: string | null; verificationStatus: string;
  paymentDestinationType: string | null; paymentDestinationLast4: string | null; status: string; verifiedAt: Date | null; createdAt: Date;
}) {
  return {
    id: s.id,
    organizationId: s.organizationId,
    name: s.name,
    externalReference: s.externalReference,
    verificationStatus: s.verificationStatus,
    status: s.status,
    paymentDestination: s.paymentDestinationLast4 ? { type: s.paymentDestinationType, last4: s.paymentDestinationLast4 } : null,
    verifiedAt: s.verifiedAt?.toISOString() ?? null,
    createdAt: s.createdAt.toISOString(),
  };
}
