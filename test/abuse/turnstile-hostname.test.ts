import { SELF } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { applySchema, resetTables } from '../helpers.js';

/**
 * `TURNSTILE_HOSTNAMES` を設定した場合の hostname 照合のみを対象にした結合テスト
 * （vitest.config.ts の 'turnstile-hostname' プロジェクト。TURNSTILE_HOSTNAMES=cryptbox.test,example.com）。
 */
const ORIGIN = 'https://cryptbox.test';
const CHUNK_SIZE = 5 * 1024 * 1024;

const uploadBody = (extra: Record<string, unknown> = {}) => ({
  chunkSize: CHUNK_SIZE,
  files: [{ plainSize: 100 }],
  turnstileToken: 'good-token',
  ...extra,
});

const post = (body: unknown): Promise<Response> =>
  SELF.fetch(`${ORIGIN}/api/uploads`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

beforeAll(applySchema);
beforeEach(resetTables);
afterEach(() => {
  vi.restoreAllMocks();
});

describe('Turnstile hostname 照合 (TURNSTILE_HOSTNAMES 設定時)', () => {
  it('hostname が許可リストに無ければ 403', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      Response.json({ success: true, action: 'upload', hostname: 'evil.example.net' }),
    );
    const response = await post(uploadBody());
    expect(response.status).toBe(403);
  });

  it('hostname が許可リストにあれば通す', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      Response.json({ success: true, action: 'upload', hostname: 'cryptbox.test' }),
    );
    const response = await post(uploadBody());
    expect(response.status).toBe(200);
  });
});
