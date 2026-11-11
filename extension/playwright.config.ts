import {defineConfig} from '@playwright/test';

// One Chromium with the unpacked extension serves every test, so the tests run
// one at a time. `axo e2e` builds `build/chrome` first.
export default defineConfig({
  testDir: 'e2e',
  workers: 1,
  fullyParallel: false,
  timeout: 15_000,
  expect: {timeout: 3_000},
  use: {actionTimeout: 3_000},
  reporter: 'list',
});
