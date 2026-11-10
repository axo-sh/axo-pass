import path from 'node:path';

import {defineConfig} from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@test': path.resolve(import.meta.dirname, 'test'),
      '@': path.resolve(import.meta.dirname, 'src'),
    },
  },
  test: {
    environment: 'jsdom',
    include: ['test/**/*.test.ts'],
  },
});
