import { DEFAULT_POLICY_RULES } from '@agenttrust/policy-engine';
import { IdPrefix, newId } from '@agenttrust/shared';
import type { Prisma } from '@prisma/client';
import type { AuditService } from '../audit/audit.service';

export interface NewOrganizationInput {
  name: string;
  admin: { email: string; spendingAuthorityCents: number };
  /** Who created it (audit actor id): `platform` (bootstrap) or `sandbox_signup`. */
  createdBy: string;
}

/**
 * Creates an organization, its first administrator, its default policy (v1)
 * and its audit chain, inside the caller's transaction. Shared by the
 * platform-operator endpoint and self-service sandbox signup so both go
 * through the same records and audit events.
 */
export async function createOrganizationRecords(tx: Prisma.TransactionClient, audit: AuditService, input: NewOrganizationInput) {
  const orgId = newId(IdPrefix.organization);
  const userId = newId(IdPrefix.user);
  const policyId = newId(IdPrefix.policy);

  const org = await tx.organization.create({ data: { id: orgId, name: input.name } });
  const admin = await tx.user.create({
    data: {
      id: userId,
      organizationId: orgId,
      externalIdentityId: `dev|${userId}`,
      email: input.admin.email,
      role: 'admin',
      spendingAuthorityCents: BigInt(input.admin.spendingAuthorityCents),
    },
  });
  await tx.policy.create({
    data: { id: policyId, organizationId: orgId, name: 'Default purchasing policy', version: 1, rules: JSON.parse(JSON.stringify(DEFAULT_POLICY_RULES)), status: 'active' },
  });
  await tx.auditChainHead.create({ data: { organizationId: orgId } });
  await audit.append(tx, {
    organizationId: orgId,
    actorType: 'system',
    actorId: input.createdBy,
    eventType: 'organization.created',
    subjectId: orgId,
    payload: { name: input.name, adminUserId: userId, policyId, policyVersion: 1 },
  });
  return { org, admin, policy: { id: policyId, version: 1 } };
}
