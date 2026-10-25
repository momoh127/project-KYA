import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

const root = path.resolve(__dirname, '../..');
const pkg = (name: string) => path.resolve(root, 'packages', name, 'src', 'index.ts');

function readDotEnv(file: string): Record<string, string> {
  if (!existsSync(file)) return {};
  const out: Record<string, string> = {};
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
    if (m) out[m[1]!] = m[2]!;
  }
  return out;
}

export default defineConfig(() => {
  const env = { ...readDotEnv(path.join(root, '.env')), ...process.env } as Record<string, string>;
  return {
    // SWC emits the decorator metadata NestJS dependency injection needs.
    plugins: [swc.vite({ module: { type: 'es6' } })],
    resolve: {
      alias: {
        '@agenttrust/shared': pkg('shared'),
        '@agenttrust/policy-engine': pkg('policy-engine'),
        '@agenttrust/identity': pkg('identity'),
        '@agenttrust/authorization': pkg('authorization'),
        '@agenttrust/audit': pkg('audit'),
        '@agenttrust/sdk': pkg('sdk-typescript'),
      },
    },
    test: {
      include: ['test/**/*.test.ts'],
      env: { ...env, DATABASE_URL: env.TEST_DATABASE_URL ?? '', AGENTTRUST_RECONCILE_INTERVAL_MS: '0', AGENTTRUST_ANCHOR_INTERVAL_MS: '0', AGENTTRUST_ANCHOR_DIR: path.join(root, '.local', 'anchors-test'), AGENTTRUST_SANDBOX_SIGNUP: 'true' },
      testTimeout: 30_000,
      hookTimeout: 60_000,
      fileParallelism: false,
      pool: 'forks',
    },
  };
});
