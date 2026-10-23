import type { Prisma } from '@prisma/client';
import type { ActorType } from '@agenttrust/audit';
import type { AuditService } from '../audit/audit.service';
import type { Tx } from '../common/prisma.service';

/**
 * Invalidates every LIVE authorization (allowed or pending review) matching
 * `where` in the organization, releases their budget/PO/invoice holds, and
 * records one audit event. Called whenever a record an authorization depends
 * on changes: supplier record, delegation, policy version, agent status.
 *
 * The gateway independently re-verifies all of these at execution time; this
 * proactive step makes the state visible and frees held budget immediately.
 */
export async function invalidateLiveAuthorizations(
  tx: Tx,
  audit: AuditService,
  opts: { organizationId: string; where: Prisma.AuthorizationWhereInput; reason: string; actor: { type: ActorType; id: string } },
): Promise<number> {
  const live = await tx.authorization.findMany({
    where: { ...opts.where, organizationId: opts.organizationId, status: { in: ['allowed', 'pending_review'] } },
    select: { id: true },
  });
  if (live.length === 0) return 0;
  const ids = live.map((a) => a.id);
  await tx.authorization.updateMany({
    where: { id: { in: ids }, status: { in: ['allowed', 'pending_review'] } },
    data: { status: 'invalidated', invalidatedReason: opts.reason },
  });
  await tx.budgetReservation.updateMany({ where: { authorizationId: { in: ids }, status: 'active' }, data: { status: 'released' } });
  await audit.append(tx, {
    organizationId: opts.organizationId,
    actorType: opts.actor.type,
    actorId: opts.actor.id,
    eventType: 'authorization.invalidated',
    subjectId: null,
    payload: { reason: opts.reason, authorizationIds: ids, count: ids.length },
  });
  return ids.length;
}
