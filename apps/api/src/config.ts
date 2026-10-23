import path from 'node:path';
import { z } from 'zod';

const EnvSchema = z.object({
  NODE_ENV: z.string().default('development'),
  DATABASE_URL: z.string().url(),
  PORT: z.coerce.number().int().positive().default(4000),
  AGENTTRUST_SIGNING_KEY_ID: z.string().min(1),
  AGENTTRUST_SIGNING_KEY_PEM_B64: z.string().min(1),
  AGENTTRUST_PAYEE_PEPPER: z.string().min(32),
  AGENTTRUST_BOOTSTRAP_TOKEN: z.string().min(24),
  AGENTTRUST_DEV_AUTH: z.enum(['true', 'false']).default('false'),
  AGENTTRUST_DEV_AUTH_SECRET: z.string().min(32).optional(),
  /** HMAC secret for sandbox payment-provider webhooks (>= 32 chars). Without it, webhooks are refused. */
  AGENTTRUST_SANDBOX_WEBHOOK_SECRET: z.string().min(32).optional(),
  /** Directory for the local write-once anchor storage (dev/test stand-in for S3 Object Lock). */
  AGENTTRUST_ANCHOR_DIR: z.string().min(1).optional(),
  /** Background audit anchoring interval. 0 disables. */
  AGENTTRUST_ANCHOR_INTERVAL_MS: z.coerce.number().int().min(0).default(300_000),
  /** Background reconciliation interval for unknown payment outcomes. 0 disables. */
  AGENTTRUST_RECONCILE_INTERVAL_MS: z.coerce.number().int().min(0).default(30_000),
  /** Self-service sandbox signup (hosted evaluation sandbox). Refused in production; requires dev auth. */
  AGENTTRUST_SANDBOX_SIGNUP: z.enum(['true', 'false']).default('false'),
  /** Platform-wide cap on new sandbox organizations per rolling 24 h (abuse limit). */
  AGENTTRUST_SANDBOX_MAX_SIGNUPS_PER_DAY: z.coerce.number().int().min(1).max(100_000).default(200),
  /** Sandbox organization lifetime. */
  AGENTTRUST_SANDBOX_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(30),
});

export interface AppConfig {
  nodeEnv: string;
  databaseUrl: string;
  port: number;
  signingKeyId: string;
  signingKeyPem: string;
  payeePepper: string;
  bootstrapToken: string;
  devAuth: { enabled: boolean; secret: string | null };
  reconcileIntervalMs: number;
  sandboxWebhookSecret: string | null;
  anchorDir: string;
  anchorIntervalMs: number;
  sandboxSignup: { enabled: boolean; maxPerDay: number; ttlDays: number };
}

export const APP_CONFIG = Symbol('APP_CONFIG');

/** Validates configuration at startup. Missing or weak secrets abort boot (fail closed). */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    const fields = parsed.error.issues.map((i) => i.path.join('.')).join(', ');
    throw new Error(`Invalid configuration: ${fields}. Run \`pnpm setup:env\` for local development.`);
  }
  const e = parsed.data;
  const devEnabled = e.AGENTTRUST_DEV_AUTH === 'true';
  if (devEnabled && e.NODE_ENV === 'production') {
    throw new Error('AGENTTRUST_DEV_AUTH must not be enabled in production');
  }
  if (devEnabled && !e.AGENTTRUST_DEV_AUTH_SECRET) {
    throw new Error('AGENTTRUST_DEV_AUTH_SECRET is required when dev auth is enabled');
  }
  const signupEnabled = e.AGENTTRUST_SANDBOX_SIGNUP === 'true';
  if (signupEnabled && e.NODE_ENV === 'production') {
    throw new Error('AGENTTRUST_SANDBOX_SIGNUP must not be enabled in production');
  }
  if (signupEnabled && !devEnabled) {
    throw new Error('AGENTTRUST_SANDBOX_SIGNUP requires AGENTTRUST_DEV_AUTH=true (sandbox personas use development tokens)');
  }
  if (signupEnabled && !e.AGENTTRUST_SANDBOX_WEBHOOK_SECRET) {
    throw new Error('AGENTTRUST_SANDBOX_SIGNUP requires AGENTTRUST_SANDBOX_WEBHOOK_SECRET (payments settle via signed webhooks)');
  }
  return {
    nodeEnv: e.NODE_ENV,
    databaseUrl: e.DATABASE_URL,
    port: e.PORT,
    signingKeyId: e.AGENTTRUST_SIGNING_KEY_ID,
    signingKeyPem: Buffer.from(e.AGENTTRUST_SIGNING_KEY_PEM_B64, 'base64').toString('utf8'),
    payeePepper: e.AGENTTRUST_PAYEE_PEPPER,
    bootstrapToken: e.AGENTTRUST_BOOTSTRAP_TOKEN,
    devAuth: { enabled: devEnabled, secret: e.AGENTTRUST_DEV_AUTH_SECRET ?? null },
    reconcileIntervalMs: e.AGENTTRUST_RECONCILE_INTERVAL_MS,
    sandboxWebhookSecret: e.AGENTTRUST_SANDBOX_WEBHOOK_SECRET ?? null,
    anchorDir: e.AGENTTRUST_ANCHOR_DIR ?? path.resolve(process.cwd(), '.local', 'anchors'),
    anchorIntervalMs: e.AGENTTRUST_ANCHOR_INTERVAL_MS,
    sandboxSignup: { enabled: signupEnabled, maxPerDay: e.AGENTTRUST_SANDBOX_MAX_SIGNUPS_PER_DAY, ttlDays: e.AGENTTRUST_SANDBOX_TTL_DAYS },
  };
}
