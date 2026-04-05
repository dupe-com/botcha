import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'middleware/express': 'src/middleware/express.ts',
    'middleware/hono': 'src/middleware/hono.ts',
  },
  format: ['esm', 'cjs'],
  noExternal: ['jose'],
  dts: true,
  splitting: false,
  clean: true,
  outDir: 'dist',
});
