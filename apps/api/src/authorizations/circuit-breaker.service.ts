import { Injectable, Logger } from '@nestjs/common';
import { DEFAULT_POLICY_RULES } from '@agenttrust/policy-engine';
import { AuditService } from '../audit/audit.service';
import { PrismaService } from '../common/prisma.service';
import { parseStoredRules } from '../policies/policies.controller';

export const SUSPICIOUS_EVENT_TYPES = ['authorization.denied', 'execution.rejected'];

/**
 * Rogue-agent circuit breaker. Counts an agent's denied authorizations and
 * rejected execution attempts in a sliding window; at the policy threshold the
 * agent is automatically suspended (fail-safe) until an administrator
 * investigates and reactivates it.
 *
 * This is a backstop on top of prevention: none of the denied attempts moved
 * money, but repeated attempts are a strong signal of a compromised,
 * prompt-injected or malfunctioning agent.
 */
@Injectable()
export class CircuitBreakerService {
  private readonly logger = new Logger('CircuitBreaker');

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  async check(organizationId: string, agentId: string): Promise<boolean> {
    try {
      const policy = await this.prisma.policy.findFirst({ where: { organizationId, status: 'active' } });
      const { denyThreshold, windowSeconds } = (policy && parseStoredRules(policy.rules)?.circuitBreaker) || DEFAULT_POLICY_RULES.circuitBreaker;
      const since = new Date(Date.now() - windowSeconds * 1000);
      const count = await this.prisma.auditEvent.count({
        where: { organizationId, actorId: agentId, eventType: { in: SUSPICIOUS_EVENT_TYPES }, createdAt: { gte: since } },
      });
      if (count < denyThreshold) return false;

      return await this.prisma.tx(async (tx) => {
        const rows = await tx.$queryRaw<{ status: string }[]>`
          SELECT status FROM "Agent" WHERE id = ${agentId} AND "organizationId" = ${organizationId} FOR UPDATE`;
        if (rows[0]?.status !== 'active') return false;
        const reason = `circuit breaker: ${count} denied/rejected attempts within ${windowSeconds}s (threshold ${denyThreshold})`;
        await tx.agent.update({ where: { id: agentId }, data: { status: 'suspended', statusReason: reason } });
        await this.audit.append(tx, {
          organizationId,
          actorType: 'system',
          actorId: 'circuit-breaker',
          eventType: 'agent.auto_suspended',
          subjectId: agentId,
          payload: { suspiciousEvents: count, windowSeconds, denyThreshold },
        });
        this.logger.warn(`Agent ${agentId} auto-suspended: ${reason}`);
        return true;
      });
    } catch (e) {
      // The breaker is a backstop; its failure must never turn a DENY into an ALLOW.
      this.logger.error(`circuit breaker check failed: ${e instanceof Error ? e.message : String(e)}`);
      return false;
    }
  }
}
