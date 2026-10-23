import { CanActivate, ExecutionContext, Inject, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Prisma } from '@prisma/client';
import type { Request } from 'express';
import { parseEd25519PublicKey, parseSignatureHeaders, verifyRequestSignature } from '@agenttrust/identity';
import { safeEqual } from '@agenttrust/shared';
import { APP_CONFIG, type AppConfig } from '../config';
import { cents, PrismaService } from '../common/prisma.service';
import { Errors } from '../common/errors';
import { SecurityMonitorService } from '../security/security-monitor.service';
import { ACCESS_KEY, FRESH_AUTH_KEY, type AccessRule, type AgentPrincipal, type HumanPrincipal, type Principal } from './principal';
import { HUMAN_TOKEN_VERIFIER, type HumanTokenVerifier } from './human-token';

type AuthedRequest = Request & { principal?: Principal; rawBody?: Buffer };

interface SigningKey {
  keyId: string;
  kind: 'workload' | 'session';
  agentId: string;
  organizationId: string;
  credentialId: string;
  sessionId: string | null;
  publicKeyPem: string;
  usable: boolean;
  unusableReason?: string;
}

/**
 * Global authentication guard. Fails closed: a route without an access
 * decorator is rejected. Identity and organization always come from verified
 * credentials, never from request bodies or headers the caller controls.
 *
 * Agents have two kinds of keys:
 *  - a long-lived WORKLOAD credential, which can only mint sessions, and
 *  - short-lived SESSION keys (default 15 min), which are the only keys that
 *    can request authorizations or execute payments.
 * A stolen session key expires quickly; the workload key should live in a
 * sidecar/KMS outside the LLM-accessible environment (see docs/SECURITY.md).
 */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly prisma: PrismaService,
    private readonly security: SecurityMonitorService,
    @Inject(HUMAN_TOKEN_VERIFIER) private readonly humanTokens: HumanTokenVerifier,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const rule = this.reflector.getAllAndOverride<AccessRule | undefined>(ACCESS_KEY, [ctx.getHandler(), ctx.getClass()]);
    if (!rule) throw Errors.forbidden('NO_ACCESS_RULE', 'Endpoint is not accessible');
    const req = ctx.switchToHttp().getRequest<AuthedRequest>();

    switch (rule.type) {
      case 'public':
        return true;
      case 'bootstrap': {
        const token = req.header('x-agenttrust-bootstrap-token') ?? '';
        if (!safeEqual(token, this.config.bootstrapToken)) throw Errors.unauthenticated('Invalid bootstrap token');
        return true;
      }
      case 'human': {
        const human = await this.authenticateHuman(req);
        if (rule.roles.length > 0 && !rule.roles.includes(human.role)) {
          throw Errors.forbidden('ROLE_REQUIRED', `Requires role: ${rule.roles.join(' or ')}`);
        }
        this.checkFreshAuth(ctx, human);
        req.principal = human;
        return true;
      }
      case 'agent':
        req.principal = await this.authenticateAgent(req, 'session');
        return true;
      case 'agent_workload':
        req.principal = await this.authenticateAgent(req, 'workload');
        return true;
      case 'human_or_agent':
        req.principal = req.header('authorization') ? await this.authenticateHuman(req) : await this.authenticateAgent(req, 'session');
        return true;
    }
  }

  private checkFreshAuth(ctx: ExecutionContext, human: HumanPrincipal): void {
    const maxAge = this.reflector.getAllAndOverride<number | undefined>(FRESH_AUTH_KEY, [ctx.getHandler(), ctx.getClass()]);
    if (maxAge === undefined) return;
    if (Math.floor(Date.now() / 1000) - human.authTime > maxAge) {
      throw Errors.forbidden('REAUTHENTICATION_REQUIRED', 'Sign in again to perform this action');
    }
  }

  private async authenticateHuman(req: AuthedRequest): Promise<HumanPrincipal> {
    const header = req.header('authorization') ?? '';
    const match = /^Bearer ([A-Za-z0-9_\-.]+)$/.exec(header);
    if (!match) throw Errors.unauthenticated();
    const verified = this.humanTokens.verify(match[1]!);
    if (!verified) throw Errors.unauthenticated('Invalid or expired access token');

    const user = await this.prisma.user.findUnique({ where: { externalIdentityId: verified.subject } });
    if (!user || user.status !== 'active') throw Errors.unauthenticated('User is not active');
    const org = await this.prisma.organization.findUnique({ where: { id: user.organizationId } });
    if (!org || org.status !== 'active') throw Errors.forbidden('ORGANIZATION_SUSPENDED', 'Organization is not active');

    return {
      kind: 'user',
      userId: user.id,
      organizationId: user.organizationId,
      role: user.role,
      spendingAuthorityCents: cents(user.spendingAuthorityCents),
      authTime: verified.authTime,
    };
  }

  private async loadKey(keyId: string, now: Date): Promise<SigningKey | null> {
    if (keyId.startsWith('ags_')) {
      const s = await this.prisma.agentSession.findUnique({ where: { id: keyId } });
      if (!s) return null;
      const usable = !s.revokedAt && s.expiresAt > now;
      return {
        keyId, kind: 'session', agentId: s.agentId, organizationId: s.organizationId, credentialId: s.credentialId,
        sessionId: s.id, publicKeyPem: s.publicKeyPem, usable, unusableReason: usable ? undefined : 'session expired or revoked',
      };
    }
    const c = await this.prisma.agentCredential.findUnique({ where: { id: keyId } });
    if (!c) return null;
    const usable = c.status === 'active' && (!c.expiresAt || c.expiresAt > now);
    return {
      keyId, kind: 'workload', agentId: c.agentId, organizationId: c.organizationId, credentialId: c.id,
      sessionId: null, publicKeyPem: c.publicKeyPem, usable, unusableReason: usable ? undefined : 'credential expired or revoked',
    };
  }

  private async authenticateAgent(req: AuthedRequest, required: 'session' | 'workload'): Promise<AgentPrincipal> {
    const parsed = parseSignatureHeaders((name) => req.header(name) ?? undefined);
    if (!parsed.ok) throw Errors.unauthenticated(`Agent signature required: ${parsed.reason}`);
    const h = parsed.value;
    const now = new Date();

    const key = await this.loadKey(h.credentialId, now);
    if (!key) throw Errors.unauthenticated('Unknown agent credential');

    // Failures below are UNAUTHENTICATED: anyone who knows a key id can cause
    // them. They are recorded as low-confidence signals (alert + flag), and
    // never suspend the agent, so outsiders cannot knock an agent offline.
    const fail = async (reason: string): Promise<never> => {
      await this.security.recordAuthFailure(key.organizationId, key.agentId, key.credentialId, key.keyId, reason);
      throw Errors.unauthenticated(`Agent authentication failed: ${reason}`);
    };

    if (!key.usable) return fail(key.unusableReason ?? 'credential not usable');
    const result = verifyRequestSignature({
      publicKey: parseEd25519PublicKey(key.publicKeyPem),
      method: req.method,
      path: req.originalUrl,
      rawBody: req.rawBody ?? Buffer.alloc(0),
      headers: h,
      now,
    });
    if (!result.ok) return fail(result.reason);

    try {
      await this.prisma.agentRequestNonce.create({ data: { credentialId: key.keyId, nonce: h.nonce } });
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') return fail('Replayed request (nonce already used)');
      throw e;
    }

    if (key.kind !== required) {
      throw Errors.forbidden(
        required === 'session' ? 'SESSION_REQUIRED' : 'WORKLOAD_CREDENTIAL_REQUIRED',
        required === 'session'
          ? 'Workload credentials can only create sessions; sign this request with a short-lived session key'
          : 'Sessions must be created with the workload credential',
      );
    }

    const agent = await this.prisma.agent.findUnique({ where: { id: key.agentId } });
    if (!agent || agent.organizationId !== key.organizationId) throw Errors.unauthenticated();
    const org = await this.prisma.organization.findUnique({ where: { id: agent.organizationId } });
    if (!org || org.status !== 'active') throw Errors.forbidden('ORGANIZATION_SUSPENDED', 'Organization is not active');

    return {
      kind: 'agent',
      agentId: agent.id,
      organizationId: agent.organizationId,
      credentialId: key.credentialId,
      keyKind: key.kind,
      sessionId: key.sessionId,
      agentStatus: agent.status,
    };
  }
}
