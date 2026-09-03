import { SELF } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { applySchema, resetTables } from '../helpers.js';

/**
 * このプロジェクトのみ TURNSTILE_SECRET を設定している（vitest.config.ts 参照）。
 * 通常の結合テスト（test/worker.test.ts）は turnstileToken を送らないため、
 * TURNSTILE_SECRET を混ぜると軒並み 403 になってしまう。そのため専用プロジェクトに分離した。
 */
const ORIGIN = 'https://cryptbox.test';
const CHUNK_SIZE = 5 * 1024 * 1024;
const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

const uploadBody = (extra: Record<string, unknown> = {}) => ({
  chunkSize: CHUNK_SIZE,
  files: [{ plainSize: 100 }],
  ...extra,
});

const post = (body: unknown, headers: Record<string, string> = {}): Promise<Response> =>
  SELF.fetch(`${ORIGIN}/api/uploads`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });

beforeAll(applySchema);
beforeEach(resetTables);
afterEach(() => {
  vi.restoreAllMocks();
});

describe('Turnstile 検証 (TURNSTILE_SECRET 設定時)', () => {
  it('turnstileToken が無ければ 403', async () => {
    const response = await post(uploadBody());
    expect(response.status).toBe(403);
  });

  it('siteverify が成功を返せば通す', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = typeof input === 'string' ? input : (input as Request).url;
      expect(url).toBe(SITEVERIFY_URL);
      return Response.json({ success: true });
    });

    const response = await post(uploadBody({ turnstileToken: 'good-token' }));
    expect(response.status).toBe(200);
  });

  it('siteverify が失敗を返せば 403', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => Response.json({ success: false }));

    const response = await post(uploadBody({ turnstileToken: 'bad-token' }));
    expect(response.status).toBe(403);
  });

  it('CF-Connecting-IP を remoteip として siteverify に渡す', async () => {
    let capturedBody = '';
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      capturedBody = String(init?.body ?? '');
      return Response.json({ success: true });
    });

    const response = await post(uploadBody({ turnstileToken: 'good-token' }), {
      'CF-Connecting-IP': '203.0.113.5',
    });
    expect(response.status).toBe(200);
    const params = new URLSearchParams(capturedBody);
    expect(params.get('remoteip')).toBe('203.0.113.5');
    expect(params.get('response')).toBe('good-token');
    expect(params.get('secret')).toBe('test-turnstile-secret');
  });

  it('siteverify への通信自体が失敗しても 403 (fail-closed)', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      throw new Error('network error');
    });

    const response = await post(uploadBody({ turnstileToken: 'good-token' }));
    expect(response.status).toBe(403);
  });

  it('トークンが文字列でなければ siteverify を呼ばずに 403', async () => {
    const spy = vi.spyOn(globalThis, 'fetch');
    const response = await post(uploadBody({ turnstileToken: 12345 }));
    expect(response.status).toBe(403);
    expect(spy).not.toHaveBeenCalled();
  });
});
