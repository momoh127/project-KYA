import { defineConfig } from 'tsup';

/**
 * Standalone distribution of the SDK: the internal @agenttrust/* workspace
 * packages are bundled in (code AND type declarations), so the published
 * tarball has zero runtime dependencies (Node >= 18.17 built-ins only:
 * crypto, fetch).
 */
export default defineConfig({
  entry: { index: 'src/index.ts' },
  outDir: 'release/dist',
  format: ['cjs', 'esm'],
  platform: 'node',
  target: 'node18',
  dts: { resolve: [/^@agenttrust\//] },
  noExternal: [/^@agenttrust\//],
  clean: true,
  sourcemap: false,
  splitting: false,
  tsconfig: 'tsconfig.bundle.json',
});
