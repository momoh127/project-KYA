import type { Prisma } from '@prisma/client';
import type { ActorType } from '@agenttrust/audit';
import type { AuditService } from '../audit/audit.service';
import type { Tx } from '../common/prisma.service';

/**
 * Locks the LIVE authorizations matching a column value (FOR UPDATE, ordered
 * by id) BEFORE the caller locks the record they depend on. This keeps the
 * global lock order `Authorization → (Agent | Instruction | ...) → AuditChainHead`
 * and prevents deadlocks with the approval and gateway paths, which lock the
 * Authorization row first.
 */
export async function lockLiveAuthorizationsBy(tx: Tx, column: 'instructionId' | 'agentId', value: string): Promise<void> {
  // `column` is one of two hard-coded identifiers, never user input.
  await tx.$queryRawUnsafe(
    `SELECT id FROM "Authorization" WHERE "${column}" = $1 AND status IN ('allowed', 'pending_review') ORDER BY id FOR UPDATE`,
    value,
  );
}

/**
 * Invalidates every LIVE authorization (allowed or pending review) matching
 * `where` in the organization, releases their holds, and records one audit
 * event. Called whenever a record an authorization depends on changes:
 * supplier record, purchase instruction, receipt, delegation, policy version,
 * agent status.
 *
 * ORDERING RULE: call this after all other row writes in the transaction and
 * before any other audit append, so the AuditChainHead lock is always taken
 * last (it is taken here). The gateway independently re-verifies everything.
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
