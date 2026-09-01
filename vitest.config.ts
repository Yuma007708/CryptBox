import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';

export default defineConfig({
  test: {
    projects: [
      {
        // Worker / D1 / R2 を実際に動かす結合テスト
        plugins: [
          cloudflareTest({
            main: './src/index.ts',
            miniflare: {
              compatibilityDate: '2026-08-01',
              d1Databases: ['DB'],
              r2Buckets: ['BUCKET'],
              bindings: {
                GRANT_SECRET: 'test-grant-secret',
                MAX_FILE_SIZE: String(1024 * 1024 * 1024),
              },
            },
          }),
        ],
        test: { name: 'workers', include: ['test/*.test.ts'] },
      },
      {
        // workerd は実行時の WebAssembly.compile を禁じているため、
        // Argon2id (WASM) を含むテストは Node 環境で回す
        test: { name: 'node', environment: 'node', include: ['test/node/*.test.ts'] },
      },
    ],
  },
});
