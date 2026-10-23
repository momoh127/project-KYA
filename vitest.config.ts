import { defineConfig } from 'vitest/config';
import path from 'node:path';

const pkg = (name: string) => path.resolve(__dirname, 'packages', name, 'src', 'index.ts');

// Unit tests for the pure packages. API integration tests have their own config
// in apps/api because NestJS needs decorator metadata (SWC).
export default defineConfig({
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
    include: ['packages/*/test/**/*.test.ts'],
  },
});
