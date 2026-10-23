import { SetMetadata } from '@nestjs/common';
import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import type { UserRole } from '@prisma/client';

export interface HumanPrincipal {
  kind: 'user';
  userId: string;
  organizationId: string;
  role: UserRole;
  spendingAuthorityCents: number;
  /** Unix seconds when the human last actively authenticated. */
  authTime: number;
}

export interface AgentPrincipal {
  kind: 'agent';
  agentId: string;
  organizationId: string;
  credentialId: string;
  /** Authenticated, but the agent may be suspended/revoked; endpoints decide. */
  agentStatus: 'active' | 'suspended' | 'revoked';
}

export type Principal = HumanPrincipal | AgentPrincipal;

export type AccessRule =
  | { type: 'public' }
  | { type: 'bootstrap' }
  | { type: 'human'; roles: UserRole[] }
  | { type: 'agent' }
  | { type: 'human_or_agent' };

export const ACCESS_KEY = 'agenttrust:access';
export const FRESH_AUTH_KEY = 'agenttrust:fresh-auth';

/** No authentication (health checks only). */
export const Public = () => SetMetadata(ACCESS_KEY, { type: 'public' } satisfies AccessRule);
/** Platform operator: requires the bootstrap token. */
export const Bootstrap = () => SetMetadata(ACCESS_KEY, { type: 'bootstrap' } satisfies AccessRule);
/** Authenticated human; if roles are given, the user must hold one of them. */
export const Human = (...roles: UserRole[]) => SetMetadata(ACCESS_KEY, { type: 'human', roles } satisfies AccessRule);
/** Authenticated agent (signed request). */
export const AgentOnly = () => SetMetadata(ACCESS_KEY, { type: 'agent' } satisfies AccessRule);
export const HumanOrAgent = () => SetMetadata(ACCESS_KEY, { type: 'human_or_agent' } satisfies AccessRule);
/** Requires the human to have authenticated within `maxAgeSeconds` (sensitive actions). */
export const FreshAuth = (maxAgeSeconds = 900) => SetMetadata(FRESH_AUTH_KEY, maxAgeSeconds);

export const CurrentPrincipal = createParamDecorator((_: unknown, ctx: ExecutionContext): Principal => {
  const req = ctx.switchToHttp().getRequest<{ principal?: Principal }>();
  if (!req.principal) throw new Error('principal missing: route lacks an access decorator');
  return req.principal;
});

export const CurrentUser = createParamDecorator((_: unknown, ctx: ExecutionContext): HumanPrincipal => {
  const p = ctx.switchToHttp().getRequest<{ principal?: Principal }>().principal;
  if (p?.kind !== 'user') throw new Error('route requires a human principal');
  return p;
});

export const CurrentAgent = createParamDecorator((_: unknown, ctx: ExecutionContext): AgentPrincipal => {
  const p = ctx.switchToHttp().getRequest<{ principal?: Principal }>().principal;
  if (p?.kind !== 'agent') throw new Error('route requires an agent principal');
  return p;
});
