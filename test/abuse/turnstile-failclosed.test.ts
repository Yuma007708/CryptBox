import { SELF } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { applySchema, resetTables } from '../helpers.js';

/**
 * TURNSTILE_SECRET はあるが TURNSTILE_SITE_KEY が無い「片肺デプロイ」の安全弁。
 * サイトキーが公開されていなければクライアントはトークンを送りようがないため、
 * この状態では検証をスキップしないと誰も送信できなくなってしまう。
 * （vitest.config.ts の 'turnstile-failclosed' プロジェクト）
 */
const ORIGIN = 'https://cryptbox.test';
const CHUNK_SIZE = 5 * 1024 * 1024;

const uploadBody = { chunkSize: CHUNK_SIZE, files: [{ plainSize: 100 }] };

beforeAll(applySchema);
beforeEach(resetTables);
afterEach(() => {
  vi.restoreAllMocks();
});

describe('Turnstile 片肺デプロイ (secret あり・site key 無し)', () => {
  it('turnstileToken が無くても siteverify を呼ばずに通す', async () => {
    const spy = vi.spyOn(globalThis, 'fetch');
    const response = await SELF.fetch(`${ORIGIN}/api/uploads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(uploadBody),
    });
    expect(response.status).toBe(200);
    expect(spy).not.toHaveBeenCalled();
  });
});
