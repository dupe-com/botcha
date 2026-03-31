import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    'lib/index': 'lib/index.ts',
    'lib/client/index': 'lib/client/index.ts',
    'src/middleware/tap-enhanced-verify': 'src/middleware/tap-enhanced-verify.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  splitting: false,
  clean: true,
  outDir: 'dist',
});
