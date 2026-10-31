import { defineProject } from 'vitest/config';

export default defineProject({
  test: { name: 'sdk', include: ['test/**/*.test.ts'], environment: 'node', testTimeout: 20_000 },
});
