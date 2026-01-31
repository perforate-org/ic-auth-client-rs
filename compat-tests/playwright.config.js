import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  testMatch: '**/*.spec.js',
  timeout: 60_000,
  use: {
    baseURL: 'http://127.0.0.1:4173',
    headless: true,
  },
  webServer: {
    command: 'pnpm vite --config vite.config.js --host 127.0.0.1 --port 4173',
    reuseExistingServer: !process.env.CI,
  },
});
