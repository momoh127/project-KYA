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
  /** Long-lived workload credential (directly, or as the parent of the session). */
  credentialId: string;
  /** Which key signed this request. Only `session` keys may authorize or pay. */
  keyKind: 'workload' | 'session';
  sessionId: string | null;
  /** Authenticated, but the agent may be suspended/revoked; endpoints decide. */
  agentStatus: 'active' | 'suspended' | 'revoked';
}

/** Trusted ERP integration: privileged machine identity with narrow scopes. */
export interface IntegrationPrincipal {
  kind: 'integration';
  integrationId: string;
  organizationId: string;
  sourceSystem: string;
  scopes: IntegrationScope[];
}

export const INTEGRATION_SCOPES = ['instructions:sync', 'instructions:attest_approval', 'receipts:confirm', 'invoices:write'] as const;
export type IntegrationScope = (typeof INTEGRATION_SCOPES)[number];

export type Principal = HumanPrincipal | AgentPrincipal | IntegrationPrincipal;

export type AccessRule =
  | { type: 'public' }
  | { type: 'bootstrap' }
  | { type: 'human'; roles: UserRole[] }
  | { type: 'agent' }
  | { type: 'agent_workload' }
  | { type: 'human_or_agent' }
  | { type: 'integration'; scope: IntegrationScope }
  | { type: 'human_or_integration'; roles: UserRole[]; scope: IntegrationScope };

export const ACCESS_KEY = 'agenttrust:access';
export const FRESH_AUTH_KEY = 'agenttrust:fresh-auth';

/** No authentication (health checks only). */
export const Public = () => SetMetadata(ACCESS_KEY, { type: 'public' } satisfies AccessRule);
/** Platform operator: requires the bootstrap token. */
export const Bootstrap = () => SetMetadata(ACCESS_KEY, { type: 'bootstrap' } satisfies AccessRule);
/** Authenticated human; if roles are given, the user must hold one of them. */
export const Human = (...roles: UserRole[]) => SetMetadata(ACCESS_KEY, { type: 'human', roles } satisfies AccessRule);
/** Authenticated agent SESSION (short-lived key). Workload credentials are refused. */
export const AgentOnly = () => SetMetadata(ACCESS_KEY, { type: 'agent' } satisfies AccessRule);
/** Authenticated agent WORKLOAD credential: only used to mint sessions. */
export const AgentWorkload = () => SetMetadata(ACCESS_KEY, { type: 'agent_workload' } satisfies AccessRule);
export const HumanOrAgent = () => SetMetadata(ACCESS_KEY, { type: 'human_or_agent' } satisfies AccessRule);
/** Trusted ERP integration holding `scope`. */
export const Integration = (scope: IntegrationScope) => SetMetadata(ACCESS_KEY, { type: 'integration', scope } satisfies AccessRule);
/** A human with one of `roles`, or an ERP integration holding `scope`. Never an agent. */
export const HumanOrIntegration = (roles: UserRole[], scope: IntegrationScope) =>
  SetMetadata(ACCESS_KEY, { type: 'human_or_integration', roles, scope } satisfies AccessRule);
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

export const CurrentIntegration = createParamDecorator((_: unknown, ctx: ExecutionContext): IntegrationPrincipal => {
  const p = ctx.switchToHttp().getRequest<{ principal?: Principal }>().principal;
  if (p?.kind !== 'integration') throw new Error('route requires an integration principal');
  return p;
});
