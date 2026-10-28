import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 360_000,
  expect: { timeout: 15_000 },
  use: {
    baseURL: 'http://127.0.0.1:4200',
    trace: 'retain-on-failure',
    ...devices['Desktop Chrome'],
  },
  reporter: 'list',
});
