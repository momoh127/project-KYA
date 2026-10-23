import { Injectable, Logger } from '@nestjs/common';
import { DEFAULT_POLICY_RULES, type SecurityResponseRules } from '@agenttrust/policy-engine';
import { IdPrefix, newId } from '@agenttrust/shared';
import { AuditService } from '../audit/audit.service';
import { PrismaService } from '../common/prisma.service';
import { parseStoredRules } from '../policies/policies.controller';

/** Denial reasons that suggest fraud (e.g. a scam invoice) rather than a routine policy limit. */
export const FRAUD_SIGNAL_CODES = ['PAYEE_MISMATCH', 'SUPPLIER_BLOCKED', 'SUPPLIER_NOT_DELEGATED'] as const;

/**
 * Gateway rejections that only the holder of the agent's own valid session
 * key can produce, and that have no benign explanation (forged or tampered
 * authorizations, presenting another agent's authorization). High confidence
 * of compromise, so these may suspend the agent.
 */
export const SECURITY_VIOLATION_CODES = new Set([
  'TOKEN_BAD_SIGNATURE',
  'TOKEN_UNSUPPORTED_ALGORITHM',
  'TOKEN_UNKNOWN_KEY',
  'TOKEN_NOT_ISSUED_TO_CALLER',
  'TRANSACTION_MISMATCH',
]);

export type AlertCategory = 'auth_failures' | 'fraud_signal' | 'repeated_denials' | 'reconciliation_required' | 'payment_exception' | 'provider_event_conflict';

/**
 * Graded responses to suspicious activity (replaces a blunt circuit breaker).
 *
 * | Signal                                   | Who can cause it            | Response                               |
 * |------------------------------------------|-----------------------------|----------------------------------------|
 * | Authenticated security violation         | only the agent's key holder | audit; suspend at threshold            |
 * | Unauthenticated failure (bad sig/replay) | anyone who knows a key id   | signal; alert + flag credential        |
 * | Fraud-signal denial (payee mismatch)     | outsiders via scam invoices | audit (already); alert, no suspension  |
 * | Business-policy denial (budget, PO)      | normal operation            | alert at threshold, no suspension      |
 *
 * Never throws: monitoring failures must not change an authorization outcome.
 */
@Injectable()
export class SecurityMonitorService {
  private readonly logger = new Logger('SecurityMonitor');

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  private async rules(organizationId: string): Promise<SecurityResponseRules> {
    const policy = await this.prisma.policy.findFirst({ where: { organizationId, status: 'active' } });
    return (policy && parseStoredRules(policy.rules)?.securityResponse) || DEFAULT_POLICY_RULES.securityResponse;
  }

  /** Unauthenticated: bad signature, replayed nonce, expired/revoked key. Alert + flag, never suspend. */
  async recordAuthFailure(organizationId: string, agentId: string, credentialId: string, keyId: string, reason: string): Promise<void> {
    await this.safely(async () => {
      await this.prisma.securitySignal.create({
        data: { id: newId(IdPrefix.signal), organizationId, agentId, keyId, kind: 'auth_failure', reason: reason.slice(0, 200) },
      });
      const r = await this.rules(organizationId);
      const since = new Date(Date.now() - r.alertWindowSeconds * 1000);
      const count = await this.prisma.securitySignal.count({ where: { organizationId, agentId, kind: 'auth_failure', createdAt: { gte: since } } });
      if (count < r.authFailureAlertThreshold) return;
      const raised = await this.raiseAlert(organizationId, agentId, 'auth_failures', since, {
        severity: 'high',
        count,
        windowSeconds: r.alertWindowSeconds,
        message: 'Repeated failed authentication attempts against this agent\'s credentials. Investigate possible key probing or misconfiguration. The agent was NOT suspended (unauthenticated failures can be caused by outsiders).',
        lastReason: reason.slice(0, 200),
      });
      if (raised) {
        await this.prisma.agentCredential.updateMany({
          where: { id: credentialId, flaggedAt: null },
          data: { flaggedAt: new Date(), flagReason: `${count} failed authentications in ${r.alertWindowSeconds}s` },
        });
      }
    });
  }

  /** Authenticated, high-confidence violation. Suspends at threshold. Returns true if suspended now. */
  async recordViolation(organizationId: string, agentId: string, code: string, subjectId: string | null, details: Record<string, unknown> | null): Promise<boolean> {
    return (
      (await this.safely(async () => {
        await this.audit.appendStandalone({
          organizationId, actorType: 'agent', actorId: agentId, eventType: 'security.violation', subjectId,
          payload: { code, details },
        });
        const r = await this.rules(organizationId);
        const since = new Date(Date.now() - r.violationWindowSeconds * 1000);
        const count = await this.prisma.auditEvent.count({
          where: { organizationId, actorId: agentId, eventType: 'security.violation', createdAt: { gte: since } },
        });
        if (count < r.violationSuspendThreshold) return false;

        return this.prisma.tx(async (tx) => {
          const rows = await tx.$queryRaw<{ status: string }[]>`
            SELECT status FROM "Agent" WHERE id = ${agentId} AND "organizationId" = ${organizationId} FOR UPDATE`;
          if (rows[0]?.status !== 'active') return false;
          const reason = `security violations: ${count} forged/tampered/misused authorizations within ${r.violationWindowSeconds}s`;
          await tx.agent.update({ where: { id: agentId }, data: { status: 'suspended', statusReason: reason } });
          await tx.agentSession.updateMany({ where: { agentId, revokedAt: null }, data: { revokedAt: new Date() } });
          await this.audit.append(tx, {
            organizationId, actorType: 'system', actorId: 'security-monitor', eventType: 'agent.auto_suspended', subjectId: agentId,
            payload: { violations: count, windowSeconds: r.violationWindowSeconds, threshold: r.violationSuspendThreshold, lastCode: code },
          });
          this.logger.warn(`Agent ${agentId} auto-suspended: ${reason}`);
          return true;
        });
      })) ?? false
    );
  }

  /** Records a non-malicious gateway rejection (expired, already used, record changed, ...). */
  async recordOperationalRejection(organizationId: string, agentId: string, code: string, subjectId: string | null, details: Record<string, unknown> | null): Promise<void> {
    await this.safely(async () => {
      await this.audit.appendStandalone({
        organizationId, actorType: 'agent', actorId: agentId, eventType: 'execution.rejected', subjectId,
        payload: { code, details },
      });
      await this.checkRepeatedDenials(organizationId, agentId);
    });
  }

  /** Called after a DENY decision (already audited as authorization.denied). Alerts only. */
  async recordDenial(organizationId: string, agentId: string, authorizationId: string, reasonCodes: string[]): Promise<void> {
    await this.safely(async () => {
      const fraud = reasonCodes.filter((c) => (FRAUD_SIGNAL_CODES as readonly string[]).includes(c));
      if (fraud.length > 0) {
        const r = await this.rules(organizationId);
        const since = new Date(Date.now() - r.alertWindowSeconds * 1000);
        await this.raiseAlert(organizationId, agentId, 'fraud_signal', since, {
          severity: 'high',
          authorizationId,
          reasonCodes: fraud,
          message: 'The agent tried to pay a destination that does not match verified supplier records. Possible scam invoice / business email compromise reaching the agent. Payment was blocked; the agent was NOT suspended (outsiders can trigger this).',
        });
      }
      await this.checkRepeatedDenials(organizationId, agentId);
    });
  }

  private async checkRepeatedDenials(organizationId: string, agentId: string): Promise<void> {
    const r = await this.rules(organizationId);
    const since = new Date(Date.now() - r.alertWindowSeconds * 1000);
    const count = await this.prisma.auditEvent.count({
      where: { organizationId, actorId: agentId, eventType: { in: ['authorization.denied', 'execution.rejected'] }, createdAt: { gte: since } },
    });
    if (count < r.denialAlertThreshold) return;
    await this.raiseAlert(organizationId, agentId, 'repeated_denials', since, {
      severity: 'medium',
      count,
      windowSeconds: r.alertWindowSeconds,
      message: 'Unusually many denied or rejected requests. Review the agent\'s instructions and inputs.',
    });
  }

  /** Raises at most one alert per (agent, category) per window. Returns true if a new alert was raised. */
  async raiseAlert(organizationId: string, subjectId: string, category: AlertCategory, since: Date, payload: Record<string, unknown>): Promise<boolean> {
    const existing = await this.prisma.auditEvent.findFirst({
      where: {
        organizationId, eventType: 'alert.raised', subjectId, createdAt: { gte: since },
        payload: { path: ['category'], equals: category },
      },
    });
    if (existing) return false;
    await this.audit.appendStandalone({
      organizationId, actorType: 'system', actorId: 'security-monitor', eventType: 'alert.raised', subjectId,
      payload: { category, ...payload },
    });
    return true;
  }

  private async safely<T>(fn: () => Promise<T>): Promise<T | undefined> {
    try {
      return await fn();
    } catch (e) {
      this.logger.error(`security monitor failure: ${e instanceof Error ? e.message : String(e)}`);
      return undefined;
    }
  }
}
