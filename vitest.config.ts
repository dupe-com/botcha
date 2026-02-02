import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'happy-dom',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts', 'lib/**/*.ts'],
      exclude: ['src/index.ts', '**/*.d.ts', '**/node_modules/**'],
    },
  },
});
