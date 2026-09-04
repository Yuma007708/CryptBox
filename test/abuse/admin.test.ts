import { SELF, env } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { applySchema, resetTables } from '../helpers.js';
import {
  deriveAuthToken,
  deriveKeysFromMaterial,
  encryptChunk,
  encryptMeta,
  importCek,
  randomBytes,
  sha256Hex as sha256HexBytes,
  wrapCek,
} from '../../web/src/crypto.js';
import {
  KDF_SALT_BYTES,
  KEY_BYTES,
  LINK_SECRET_BYTES,
  NONCE_BYTES,
  NONCE_PREFIX_BYTES,
  toBase64Url,
  totalChunks,
} from '../../shared/format.js';

/**
 * このプロジェクトのみ ADMIN_TOKEN を設定している（vitest.config.ts 参照）。
 * 通常の結合テスト（test/report.test.ts）は ADMIN_TOKEN 未設定を前提に
 * 「管理 API が 404 として振る舞う」ことを確認するため、分離している。
 */
const ORIGIN = 'https://cryptbox.test';
const CHUNK_SIZE = 5 * 1024 * 1024;
const ADMIN_TOKEN = 'test-admin-token';

const json = (body: unknown, headers: Record<string, string> = {}): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json', ...headers },
  body: JSON.stringify(body),
});

const authed = (body: unknown): RequestInit => json(body, { Authorization: `Bearer ${ADMIN_TOKEN}` });

async function uploadBundle(): Promise<{ token: string; bundleId: string }> {
  const linkSecret = randomBytes(LINK_SECRET_BYTES);
  const kdfSalt = randomBytes(KDF_SALT_BYTES);
  const keys = await deriveKeysFromMaterial({ linkSecret, kdfSalt, pwKey: null });
  const authToken = await deriveAuthToken(linkSecret);

  const created = await SELF.fetch(
    `${ORIGIN}/api/uploads`,
    json({ chunkSize: CHUNK_SIZE, files: [{ plainSize: 10 }] }),
  );
  const { uploadToken } = (await created.json()) as { uploadToken: string };

  const plain = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  const cekRaw = randomBytes(KEY_BYTES);
  const cek = await importCek(cekRaw);
  const noncePrefix = randomBytes(NONCE_PREFIX_BYTES);
  const wrapNonce = randomBytes(NONCE_BYTES);
  const metaNonce = randomBytes(NONCE_BYTES);
  const chunks = totalChunks(plain.length, CHUNK_SIZE);
  for (let i = 0; i < chunks; i++) {
    const cipher = await encryptChunk(cek, plain, noncePrefix, i, chunks);
    await SELF.fetch(`${ORIGIN}/api/uploads/${uploadToken}/files/0/parts/${i}`, {
      method: 'PUT',
      body: cipher,
    });
  }

  const completed = await SELF.fetch(
    `${ORIGIN}/api/uploads/${uploadToken}/complete`,
    json({
      expiresIn: 3600,
      maxDownloads: null,
      authHash: await sha256HexBytes(authToken),
      kdfSalt: toBase64Url(kdfSalt),
      hasPassword: false,
      pwSalt: null,
      pwParams: null,
      pwHash: null,
      files: [
        {
          noncePrefix: toBase64Url(noncePrefix),
          wrappedCek: toBase64Url(await wrapCek(keys.kek, cekRaw, wrapNonce)),
          wrapNonce: toBase64Url(wrapNonce),
          metaCipher: toBase64Url(await encryptMeta(cek, { name: 'a.bin', type: '', size: plain.length }, metaNonce)),
          metaNonce: toBase64Url(metaNonce),
        },
      ],
    }),
  );
  const { token } = (await completed.json()) as { token: string };
  return { token, bundleId: await sha256HexOfToken(token) };
}

/** サーバー (src/lib.ts の sha256Hex) は token 文字列をそのまま UTF-8 でハッシュする */
async function sha256HexOfToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

beforeAll(applySchema);
beforeEach(resetTables);

describe('POST /api/admin/takedown（ADMIN_TOKEN 設定済み）', () => {
  it('不正なトークンは 404', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/admin/takedown`, json({ bundleId: 'x'.repeat(64) }, {
      Authorization: 'Bearer wrong-token',
    }));
    expect(response.status).toBe(404);
  });

  it('Authorization ヘッダー無しは 404', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/admin/takedown`, json({ bundleId: 'x'.repeat(64) }));
    expect(response.status).toBe(404);
  });

  it('正しいトークンでバンドルと R2 オブジェクトを削除し、通報を処理済みにする', async () => {
    const { token, bundleId } = await uploadBundle();

    await SELF.fetch(`${ORIGIN}/api/files/${token}/report`, json({ reason: 'malware' }));

    const before = await env.DB.prepare(`SELECT r2_key FROM bundle_files WHERE bundle_id = ?`)
      .bind(bundleId)
      .all<{ r2_key: string }>();
    expect(before.results.length).toBeGreaterThan(0);
    for (const file of before.results) {
      expect(await env.BUCKET.head(file.r2_key)).not.toBeNull();
    }

    const response = await SELF.fetch(`${ORIGIN}/api/admin/takedown`, authed({ bundleId }));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; deleted: boolean };
    expect(body).toEqual({ ok: true, deleted: true });

    const bundleRow = await env.DB.prepare(`SELECT id FROM bundles WHERE id = ?`).bind(bundleId).first();
    expect(bundleRow).toBeNull();
    for (const file of before.results) {
      expect(await env.BUCKET.head(file.r2_key)).toBeNull();
    }

    const report = await env.DB.prepare(`SELECT handled_at FROM reports WHERE bundle_id = ?`)
      .bind(bundleId)
      .first<{ handled_at: number | null }>();
    expect(report?.handled_at).not.toBeNull();
  });

  it('存在しない bundleId は deleted: false を返す', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/admin/takedown`, authed({ bundleId: 'a'.repeat(64) }));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; deleted: boolean };
    expect(body).toEqual({ ok: true, deleted: false });
  });

  it('bundleId の形式が不正なら 400', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/admin/takedown`, authed({ bundleId: 'not-a-hash' }));
    expect(response.status).toBe(400);
  });

  describe('R2 の削除が失敗する場合', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('失敗したキーが残っていれば D1 を消さず ok:false, pending を返す。再実行で消える', async () => {
      const { bundleId } = await uploadBundle();

      const spy = vi.spyOn(env.BUCKET, 'delete').mockRejectedValueOnce(new Error('R2 down'));

      const response = await SELF.fetch(`${ORIGIN}/api/admin/takedown`, authed({ bundleId }));
      expect(response.status).toBe(200);
      const body = (await response.json()) as { ok: boolean; deleted: boolean; pending?: string[] };
      expect(body.ok).toBe(false);
      expect(body.deleted).toBe(false);
      expect(body.pending?.length).toBeGreaterThan(0);

      // D1 行はまだ残っている（冪等に再実行できる）
      const bundleRow = await env.DB.prepare(`SELECT id FROM bundles WHERE id = ?`).bind(bundleId).first();
      expect(bundleRow).not.toBeNull();

      spy.mockRestore();
      const retry = await SELF.fetch(`${ORIGIN}/api/admin/takedown`, authed({ bundleId }));
      expect(retry.status).toBe(200);
      const retryBody = (await retry.json()) as { ok: boolean; deleted: boolean };
      expect(retryBody).toEqual({ ok: true, deleted: true });

      const gone = await env.DB.prepare(`SELECT id FROM bundles WHERE id = ?`).bind(bundleId).first();
      expect(gone).toBeNull();
    });
  });
});

describe('GET /api/admin/reports（ADMIN_TOKEN 設定済み）', () => {
  it('認証が無ければ 404', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/admin/reports`);
    expect(response.status).toBe(404);
  });

  it('新しい順に未処理の通報を返す（count も含む）', async () => {
    await SELF.fetch(`${ORIGIN}/api/files/token-a/report`, json({ reason: 'malware' }));
    await SELF.fetch(`${ORIGIN}/api/files/token-b/report`, json({ reason: 'illegal' }));
    await SELF.fetch(`${ORIGIN}/api/files/token-b/report`, json({ reason: 'illegal' }));

    const response = await SELF.fetch(`${ORIGIN}/api/admin/reports?limit=50`, {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      reports: Array<{ bundleId: string; reason: string; reportedAt: number; count: number }>;
    };
    expect(body.reports).toHaveLength(2);
    expect(body.reports[0]!.reason).toBe('illegal');
    expect(body.reports[0]!.count).toBe(2);
    expect(body.reports[1]!.reason).toBe('malware');
    expect(body.reports[1]!.count).toBe(1);
  });

  it('処理済みの通報は返さない', async () => {
    const { token, bundleId } = await uploadBundle();
    await SELF.fetch(`${ORIGIN}/api/files/${token}/report`, json({ reason: 'malware' }));
    await SELF.fetch(`${ORIGIN}/api/admin/takedown`, authed({ bundleId }));

    const response = await SELF.fetch(`${ORIGIN}/api/admin/reports`, {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    const body = (await response.json()) as { reports: unknown[] };
    expect(body.reports).toHaveLength(0);
  });
});
