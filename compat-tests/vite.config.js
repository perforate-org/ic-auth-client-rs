import { defineConfig } from 'vite';
import path from 'node:path';

const repoRoot = path.resolve(__dirname, '..');

export default defineConfig({
  root: __dirname,
  resolve: {
    alias: {
      '@ic-auth-client-wasm': path.resolve(__dirname, '../pkg/ic_auth_client.js'),
    },
  },
  server: {
    host: '127.0.0.1',
    port: 4173,
    fs: {
      allow: [repoRoot],
    },
  },
  optimizeDeps: {
    exclude: ['@ic-auth-client-wasm'],
  },
});
