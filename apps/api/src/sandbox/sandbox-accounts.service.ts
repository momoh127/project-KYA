import { Inject, Injectable } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import { hmacSha256Hex, IdPrefix, newId } from '@agenttrust/shared';
import type { SandboxAccount } from '@prisma/client';
import { APP_CONFIG, type AppConfig } from '../config';
import { AuditService } from '../audit/audit.service';
import { DevTokenService } from '../auth/human-token';
import { ApiError, Errors } from '../common/errors';
import { PrismaService } from '../common/prisma.service';
import { createOrganizationRecords } from '../organizations/create-organization';
import { HttpStatus } from '@nestjs/common';

export const SANDBOX_KEY_HEADER = 'x-agenttrust-sandbox-key';
export const SANDBOX_PERSONAS = ['admin', 'verifier', 'approver'] as const;
export type SandboxPersona = (typeof SANDBOX_PERSONAS)[number];

const KEY_PATTERN = /^atsk_sbx_[a-f0-9]{48}$/;

/** Spending authority given to sandbox personas (sandbox money only). */
const ADMIN_AUTHORITY_CENTS = 10_000_000; // $100,000.00
const APPROVER_AUTHORITY_CENTS = 1_000_000; // $10,000.00

/**
 * Self-service sandbox organizations for external evaluation.
 *
 * Each signup creates a real, fully isolated organization through the same
 * code path as the platform operator, with three personas so that dual
 * control can be exercised alone: `admin` (the developer), `verifier` (a
 * second administrator for supplier bank-detail verification) and `approver`
 * (approves purchase instructions and delegations). Separation of duties is
 * NOT relaxed in the sandbox: the same person still cannot both enter and
 * verify a bank account; the sandbox simply hands one developer all three
 * badges so the flow can be tried end to end.
 */
@Injectable()
export class SandboxAccountsService {
  constructor(
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    @Inject(DevTokenService) private readonly devTokens: DevTokenService,
  ) {}

  get enabled(): boolean {
    return this.config.sandboxSignup.enabled && this.devTokens.enabled;
  }

  private assertEnabled() {
    if (!this.enabled) throw Errors.notFound('Endpoint');
  }

  private hashKey(key: string): string {
    // Domain-separated from payee fingerprints, which use the same pepper.
    return hmacSha256Hex(this.config.payeePepper, `sandbox-key:v1:${key}`);
  }

  async signup(input: { organizationName: string; email: string }) {
    this.assertEnabled();
    const since = new Date(Date.now() - 86_400_000);
    const recent = await this.prisma.sandboxAccount.count({ where: { createdAt: { gte: since } } });
    if (recent >= this.config.sandboxSignup.maxPerDay) {
      throw new ApiError(HttpStatus.SERVICE_UNAVAILABLE, 'SANDBOX_CAPACITY', 'Sandbox signups are temporarily at capacity; try again later');
    }

    const key = `atsk_sbx_${randomBytes(24).toString('hex')}`;
    const tag = randomBytes(3).toString('hex');
    const expiresAt = new Date(Date.now() + this.config.sandboxSignup.ttlDays * 86_400_000);

    const result = await this.prisma.tx(async (tx) => {
      const { org, admin, policy } = await createOrganizationRecords(tx, this.audit, {
        name: input.organizationName,
        admin: { email: input.email, spendingAuthorityCents: ADMIN_AUTHORITY_CENTS },
        createdBy: 'sandbox_signup',
      });
      const persona = async (role: 'admin' | 'approver', label: string, authority: number) => {
        const id = newId(IdPrefix.user);
        const email = `${label}+${tag}@sandbox.agenttrust.invalid`;
        const user = await tx.user.create({
          data: { id, organizationId: org.id, externalIdentityId: `dev|${id}`, email, role, spendingAuthorityCents: BigInt(authority) },
        });
        await this.audit.append(tx, {
          organizationId: org.id,
          actorType: 'system',
          actorId: 'sandbox_signup',
          eventType: 'user.created',
          subjectId: id,
          payload: { role, spendingAuthorityCents: authority, sandboxPersona: label },
        });
        return user;
      };
      const verifier = await persona('admin', 'verifier', ADMIN_AUTHORITY_CENTS);
      const approver = await persona('approver', 'approver', APPROVER_AUTHORITY_CENTS);
      await tx.sandboxAccount.create({
        data: {
          organizationId: org.id,
          keyHash: this.hashKey(key),
          keyPrefix: key.slice(0, 13),
          email: input.email,
          adminUserId: admin.id,
          verifierUserId: verifier.id,
          approverUserId: approver.id,
          expiresAt,
        },
      });
      await this.audit.append(tx, {
        organizationId: org.id,
        actorType: 'system',
        actorId: 'sandbox_signup',
        eventType: 'sandbox.account_created',
        subjectId: org.id,
        payload: { keyPrefix: key.slice(0, 13), expiresAt: expiresAt.toISOString() },
      });
      return { org, admin, verifier, approver, policy };
    });

    const user = (u: { id: string; email: string; role: string }) => ({ id: u.id, email: u.email, role: u.role });
    return {
      environment: 'sandbox' as const,
      organizationId: result.org.id,
      organizationName: result.org.name,
      /** Shown once. Store it like a password; it is only stored hashed. */
      sandboxKey: key,
      expiresAt: expiresAt.toISOString(),
      personas: { admin: user(result.admin), verifier: user(result.verifier), approver: user(result.approver) },
      policy: result.policy,
      notice: 'Sandbox only: no real money moves, human logins are development tokens, data may be deleted after expiry.',
    };
  }

  /** Resolves a sandbox key to its account (constant-time via keyed-hash lookup). */
  async authenticate(key: string | undefined): Promise<SandboxAccount> {
    this.assertEnabled();
    if (!key || !KEY_PATTERN.test(key)) throw Errors.unauthenticated('Missing or malformed sandbox key');
    const account = await this.prisma.sandboxAccount.findUnique({ where: { keyHash: this.hashKey(key) } });
    if (!account) throw Errors.unauthenticated('Invalid sandbox key');
    if (account.expiresAt.getTime() <= Date.now()) {
      throw Errors.forbidden('SANDBOX_EXPIRED', 'This sandbox has expired; sign up again for a new one');
    }
    await this.prisma.sandboxAccount.update({ where: { organizationId: account.organizationId }, data: { lastUsedAt: new Date() } });
    return account;
  }

  async token(account: SandboxAccount, persona: SandboxPersona) {
    const userId = { admin: account.adminUserId, verifier: account.verifierUserId, approver: account.approverUserId }[persona];
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || user.organizationId !== account.organizationId || user.status !== 'active') throw Errors.notFound('User');
    return { ...this.devTokens.issue(user.externalIdentityId), userId: user.id, persona, role: user.role };
  }

  /** Integration funnel for one sandbox: how far, and how fast, a developer got. */
  async progress(account: SandboxAccount) {
    const organizationId = account.organizationId;
    const [agent, instruction, auth, allow, tx, settled] = await Promise.all([
      this.prisma.agent.aggregate({ where: { organizationId }, _min: { createdAt: true } }),
      this.prisma.purchaseInstruction.aggregate({ where: { organizationId, approvedAt: { not: null } }, _min: { approvedAt: true } }),
      this.prisma.authorization.aggregate({ where: { organizationId }, _min: { createdAt: true } }),
      this.prisma.authorization.aggregate({ where: { organizationId, decision: 'ALLOW' }, _min: { createdAt: true } }),
      this.prisma.transaction.aggregate({ where: { organizationId }, _min: { createdAt: true } }),
      this.prisma.transaction.aggregate({ where: { organizationId, settledAt: { not: null } }, _min: { settledAt: true } }),
    ]);
    const start = account.createdAt.getTime();
    const minutes = (d: Date | null | undefined) => (d ? Math.round(((d.getTime() - start) / 60_000) * 10) / 10 : null);
    const steps = {
      signedUp: account.createdAt,
      agentRegistered: agent._min.createdAt,
      instructionApproved: instruction._min.approvedAt,
      firstAuthorization: auth._min.createdAt,
      firstAllow: allow._min.createdAt,
      firstExecution: tx._min.createdAt,
      firstSettledPayment: settled._min.settledAt,
    };
    return {
      organizationId,
      keyPrefix: account.keyPrefix,
      steps: Object.fromEntries(Object.entries(steps).map(([k, v]) => [k, v ? { at: v.toISOString(), minutesFromSignup: minutes(v) } : null])),
      minutesToFirstSettledPayment: minutes(steps.firstSettledPayment),
      completed: steps.firstSettledPayment !== null,
    };
  }

  /** Operator view across all sandboxes (no secrets): the time-to-integration measurement. */
  async metrics() {
    const accounts = await this.prisma.sandboxAccount.findMany({ orderBy: { createdAt: 'desc' }, take: 500 });
    const rows = await Promise.all(accounts.map(async (a) => ({ email: a.email, createdAt: a.createdAt.toISOString(), ...(await this.progress(a)) })));
    const done = rows.map((r) => r.minutesToFirstSettledPayment).filter((m): m is number => m !== null).sort((x, y) => x - y);
    const median = done.length ? (done.length % 2 ? done[(done.length - 1) / 2]! : (done[done.length / 2 - 1]! + done[done.length / 2]!) / 2) : null;
    return {
      sandboxes: rows.length,
      completedFirstSettledPayment: done.length,
      medianMinutesToFirstSettledPayment: median,
      under30Minutes: done.filter((m) => m <= 30).length,
      accounts: rows,
    };
  }
}
