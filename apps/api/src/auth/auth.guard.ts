import { CanActivate, ExecutionContext, Inject, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Prisma } from '@prisma/client';
import type { Request } from 'express';
import { parseEd25519PublicKey, parseSignatureHeaders, verifyRequestSignature } from '@agenttrust/identity';
import { safeEqual } from '@agenttrust/shared';
import { APP_CONFIG, type AppConfig } from '../config';
import { cents, PrismaService } from '../common/prisma.service';
import { Errors } from '../common/errors';
import { ACCESS_KEY, FRESH_AUTH_KEY, type AccessRule, type AgentPrincipal, type HumanPrincipal, type Principal } from './principal';
import { HUMAN_TOKEN_VERIFIER, type HumanTokenVerifier } from './human-token';

type AuthedRequest = Request & { principal?: Principal; rawBody?: Buffer };

/**
 * Global authentication guard. Fails closed: a route without an access
 * decorator is rejected. Identity and organization always come from verified
 * credentials, never from request bodies or headers the caller controls.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly prisma: PrismaService,
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
        req.principal = await this.authenticateAgent(req);
        return true;
      case 'human_or_agent':
        req.principal = req.header('authorization') ? await this.authenticateHuman(req) : await this.authenticateAgent(req);
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

  private async authenticateAgent(req: AuthedRequest): Promise<AgentPrincipal> {
    const parsed = parseSignatureHeaders((name) => req.header(name) ?? undefined);
    if (!parsed.ok) throw Errors.unauthenticated(`Agent signature required: ${parsed.reason}`);
    const h = parsed.value;

    const credential = await this.prisma.agentCredential.findUnique({ where: { id: h.credentialId } });
    const now = new Date();
    if (!credential || credential.status !== 'active' || (credential.expiresAt && credential.expiresAt <= now)) {
      throw Errors.unauthenticated('Agent credential is invalid, expired or revoked');
    }

    const result = verifyRequestSignature({
      publicKey: parseEd25519PublicKey(credential.publicKeyPem),
      method: req.method,
      path: req.originalUrl,
      rawBody: req.rawBody ?? Buffer.alloc(0),
      headers: h,
      now,
    });
    if (!result.ok) throw Errors.unauthenticated(`Agent signature rejected: ${result.reason}`);

    // Replay protection: each (credential, nonce) pair is accepted exactly once.
    try {
      await this.prisma.agentRequestNonce.create({ data: { credentialId: credential.id, nonce: h.nonce } });
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
        throw Errors.unauthenticated('Replayed request (nonce already used)');
      }
      throw e;
    }

    const agent = await this.prisma.agent.findUnique({ where: { id: credential.agentId } });
    if (!agent || agent.organizationId !== credential.organizationId) throw Errors.unauthenticated();
    const org = await this.prisma.organization.findUnique({ where: { id: agent.organizationId } });
    if (!org || org.status !== 'active') throw Errors.forbidden('ORGANIZATION_SUSPENDED', 'Organization is not active');

    return {
      kind: 'agent',
      agentId: agent.id,
      organizationId: agent.organizationId,
      credentialId: credential.id,
      agentStatus: agent.status,
    };
  }
}
