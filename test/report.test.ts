import { SELF, env } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { applySchema, resetTables } from './helpers.js';

const ORIGIN = 'https://cryptbox.test';

const json = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

async function countReports(bundleId: string): Promise<number> {
  const row = await env.DB.prepare(`SELECT COUNT(*) as n FROM reports WHERE bundle_id = ?`)
    .bind(bundleId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

beforeAll(applySchema);
beforeEach(resetTables);

describe('POST /api/files/:token/report', () => {
  it('D1 に記録される', async () => {
    const response = await SELF.fetch(
      `${ORIGIN}/api/files/some-token/report`,
      json({ reason: 'malware', detail: 'あやしいファイルです' }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean };
    expect(body).toEqual({ ok: true });

    const row = await env.DB.prepare(`SELECT bundle_id, reason, detail FROM reports LIMIT 1`).first<{
      bundle_id: string;
      reason: string;
      detail: string;
    }>();
    expect(row?.reason).toBe('malware');
    expect(row?.detail).toBe('あやしいファイルです');
    expect(row?.bundle_id).toHaveLength(64);
  });

  it('detail が無くても記録できる', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/files/some-token/report`, json({ reason: 'other' }));
    expect(response.status).toBe(200);
  });

  it('不正な reason は 400', async () => {
    const response = await SELF.fetch(
      `${ORIGIN}/api/files/some-token/report`,
      json({ reason: 'not-a-reason' }),
    );
    expect(response.status).toBe(400);
  });

  it('detail が 501 文字なら 400', async () => {
    const response = await SELF.fetch(
      `${ORIGIN}/api/files/some-token/report`,
      json({ reason: 'other', detail: 'あ'.repeat(501) }),
    );
    expect(response.status).toBe(400);
  });

  it('detail がちょうど 500 文字なら通る', async () => {
    const response = await SELF.fetch(
      `${ORIGIN}/api/files/some-token/report`,
      json({ reason: 'other', detail: 'あ'.repeat(500) }),
    );
    expect(response.status).toBe(200);
  });

  it('存在しないトークンでも同じ 200 を返す（存在オラクルにしない）', async () => {
    const response = await SELF.fetch(
      `${ORIGIN}/api/files/no-such-token-at-all/report`,
      json({ reason: 'illegal' }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean };
    expect(body).toEqual({ ok: true });
  });

  it('同一 bundle への通報は 20 件までしか記録しない', async () => {
    const token = 'repeat-token';
    for (let i = 0; i < 25; i++) {
      const response = await SELF.fetch(`${ORIGIN}/api/files/${token}/report`, json({ reason: 'copyright' }));
      expect(response.status).toBe(200);
    }
    const bundleId = await sha256Hex(token);
    expect(await countReports(bundleId)).toBe(20);
  });
});

describe('管理 API: ADMIN_TOKEN 未設定なら 404', () => {
  it('POST /api/admin/takedown は 404', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/admin/takedown`, json({ bundleId: 'x'.repeat(64) }));
    expect(response.status).toBe(404);
  });

  it('Bearer トークンを付けても 404', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/admin/takedown`, {
      ...json({ bundleId: 'x'.repeat(64) }),
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer whatever' },
    });
    expect(response.status).toBe(404);
  });

  it('GET /api/admin/reports は 404', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/admin/reports`);
    expect(response.status).toBe(404);
  });
});

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}
