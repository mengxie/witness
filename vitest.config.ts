import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: ['packages/*', 'apps/*'],
    coverage: {
      provider: 'v8',
      include: ['packages/*/src/**', 'apps/*/src/**'],
      exclude: ['apps/server/src/main.ts', 'packages/cli/src/bin.ts'],
      reporter: ['text', 'lcov'],
    },
  },
});
