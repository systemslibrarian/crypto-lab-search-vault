import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-search-vault/',
  build: {
    target: 'es2022',
  },
  test: {
    // Colocated unit tests only — never collect the Playwright specs in e2e/.
    include: ['src/**/*.test.ts'],
  },
});
