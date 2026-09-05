import { SELF } from 'cloudflare:test';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { applySchema } from '../helpers.js';

/**
 * GRANT_SECRET が未設定・短すぎる構成の安全弁（vitest.config.ts の 'grant-secret' プロジェクト。
 * GRANT_SECRET='short' = 5 文字）。
 * この状態ではダウンロードグラントも削除レシートも誰でも偽造できるため、
 * API (`/api/*`) はすべて 500 で止める（fail-closed）。
 * 一方、静的アセット（SPA の HTML）は署名と無関係なので配り続ける
 * ＝ 設定不備をユーザーに伝える画面すら出せなくなるのを避ける。
 */
const ORIGIN = 'https://cryptbox.test';
const CHUNK_SIZE = 5 * 1024 * 1024;

beforeAll(applySchema);
afterEach(() => {
  vi.restoreAllMocks();
});

describe('GRANT_SECRET が短すぎる場合', () => {
  it('アップロード API は 500 を返す', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/uploads`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chunkSize: CHUNK_SIZE, files: [{ plainSize: 100 }] }),
    });
    expect(response.status).toBe(500);
    const body = (await response.json()) as { error?: string };
    expect(body.error).toBeTruthy();
  });

  it('GET /api/config も 500 を返す（設定が直るまで何も配らない）', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/config`);
    expect(response.status).toBe(500);
  });

  it('静的アセット (/) は 200 で HTML を返す（ガードは /api/* だけ）', async () => {
    const response = await SELF.fetch(`${ORIGIN}/`);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
  });

  it('console.error に設定不備を出す', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    await SELF.fetch(`${ORIGIN}/api/config`);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('GRANT_SECRET'));
  });
});
