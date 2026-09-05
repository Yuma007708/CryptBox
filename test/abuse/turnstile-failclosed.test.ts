import { SELF, env } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { applySchema, resetTables } from '../helpers.js';

/**
 * TURNSTILE_SECRET はあるが TURNSTILE_SITE_KEY が無い「片肺デプロイ」。
 * サイトキーを配れていない = クライアントはトークンを送りようがないが、
 * 検証をスキップして通してしまうと「Turnstile を入れたつもりで素通し」になる。
 * 設定不備として 503 で止める（fail-closed）。
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
  const post = (body: unknown): Promise<Response> =>
    SELF.fetch(`${ORIGIN}/api/uploads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

  it('siteverify を呼ばずに 503（設定不備として止める）', async () => {
    const spy = vi.spyOn(globalThis, 'fetch');
    const response = await post(uploadBody);
    expect(response.status).toBe(503);
    const body = (await response.json()) as { error?: string };
    expect(body.error).toContain('Turnstile');
    expect(spy).not.toHaveBeenCalled();
  });

  it('トークンを添えても 503（検証できない構成なので通さない）', async () => {
    const response = await post({ ...uploadBody, turnstileToken: 'good-token' });
    expect(response.status).toBe(503);
  });

  it('アップロードセッションは作られない', async () => {
    await post(uploadBody);
    const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM uploads`).first<{ n: number }>();
    expect(row?.n).toBe(0);
  });
});
