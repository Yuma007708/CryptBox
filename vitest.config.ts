import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';

export default defineConfig({
  test: {
    projects: [
      {
        // Worker / D1 / R2 を実際に動かす結合テスト
        // TURNSTILE_SECRET / UPLOAD_LIMITER は未設定。ここに混ぜると全テストの
        // upload() ヘルパー（turnstileToken を送らない）が軒並み 403 になり、
        // 共有の IP キー（CF-Connecting-IP 未指定 = "unknown"）でレート制限にも
        // ひっかかってしまうため、専用プロジェクト（下）に分離している。
        plugins: [
          cloudflareTest({
            main: './src/index.ts',
            miniflare: {
              compatibilityDate: '2026-08-01',
              d1Databases: ['DB'],
              r2Buckets: ['BUCKET'],
              bindings: {
                GRANT_SECRET: 'test-grant-secret',
                MAX_FILE_SIZE: String(5 * 1024 * 1024 * 1024),
              },
            },
          }),
        ],
        test: { name: 'workers', include: ['test/*.test.ts'] },
      },
      {
        // Turnstile 検証のみを対象にした結合テスト（TURNSTILE_SECRET を設定）
        plugins: [
          cloudflareTest({
            main: './src/index.ts',
            miniflare: {
              compatibilityDate: '2026-08-01',
              d1Databases: ['DB'],
              r2Buckets: ['BUCKET'],
              bindings: {
                GRANT_SECRET: 'test-grant-secret',
                MAX_FILE_SIZE: String(5 * 1024 * 1024 * 1024),
                TURNSTILE_SECRET: 'test-turnstile-secret',
                TURNSTILE_SITE_KEY: 'test-site-key',
              },
            },
          }),
        ],
        test: { name: 'turnstile', include: ['test/abuse/turnstile.test.ts'] },
      },
      {
        // hostname 照合 (TURNSTILE_HOSTNAMES) のみを対象にした結合テスト
        plugins: [
          cloudflareTest({
            main: './src/index.ts',
            miniflare: {
              compatibilityDate: '2026-08-01',
              d1Databases: ['DB'],
              r2Buckets: ['BUCKET'],
              bindings: {
                GRANT_SECRET: 'test-grant-secret',
                MAX_FILE_SIZE: String(5 * 1024 * 1024 * 1024),
                TURNSTILE_SECRET: 'test-turnstile-secret',
                TURNSTILE_SITE_KEY: 'test-site-key',
                TURNSTILE_HOSTNAMES: 'cryptbox.test,example.com',
              },
            },
          }),
        ],
        test: { name: 'turnstile-hostname', include: ['test/abuse/turnstile-hostname.test.ts'] },
      },
      {
        // TURNSTILE_SECRET はあるが TURNSTILE_SITE_KEY が無い「片肺デプロイ」を再現する結合テスト
        plugins: [
          cloudflareTest({
            main: './src/index.ts',
            miniflare: {
              compatibilityDate: '2026-08-01',
              d1Databases: ['DB'],
              r2Buckets: ['BUCKET'],
              bindings: {
                GRANT_SECRET: 'test-grant-secret',
                MAX_FILE_SIZE: String(5 * 1024 * 1024 * 1024),
                TURNSTILE_SECRET: 'test-turnstile-secret',
              },
            },
          }),
        ],
        test: { name: 'turnstile-failclosed', include: ['test/abuse/turnstile-failclosed.test.ts'] },
      },
      {
        // レート制限のみを対象にした結合テスト（UPLOAD_LIMITER を小さい上限で設定）
        plugins: [
          cloudflareTest({
            main: './src/index.ts',
            miniflare: {
              compatibilityDate: '2026-08-01',
              d1Databases: ['DB'],
              r2Buckets: ['BUCKET'],
              bindings: {
                GRANT_SECRET: 'test-grant-secret',
                MAX_FILE_SIZE: String(5 * 1024 * 1024 * 1024),
              },
              ratelimits: {
                UPLOAD_LIMITER: { namespace_id: '1', simple: { limit: 3, period: 60 } },
              },
            },
          }),
        ],
        test: { name: 'ratelimit', include: ['test/abuse/ratelimit.test.ts'] },
      },
      {
        // workerd は実行時の WebAssembly.compile を禁じているため、
        // Argon2id (WASM) を含むテストは Node 環境で回す
        test: { name: 'node', environment: 'node', include: ['test/node/*.test.ts'] },
      },
      {
        // フロントエンド（web/src）用。DOM API が要るため happy-dom で回す
        test: { name: 'web', environment: 'happy-dom', include: ['test/web/*.test.ts'] },
      },
    ],
  },
});
