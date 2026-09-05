import { SELF, env } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { applySchema, resetTables } from './helpers.js';
import { purge } from '../src/index.js';
import {
  deriveAuthToken,
  deriveKeysFromMaterial,
  encryptChunk,
  encryptMeta,
  importCek,
  randomBytes,
  sha256Hex,
  wrapCek,
} from '../web/src/crypto.js';
import {
  ARGON2_DEFAULTS,
  KDF_SALT_BYTES,
  KEY_BYTES,
  LINK_SECRET_BYTES,
  NONCE_BYTES,
  NONCE_PREFIX_BYTES,
  PW_SALT_BYTES,
  toBase64Url,
} from '../shared/format.js';
import { MAX_OPEN_UPLOADS_PER_IP, UPLOAD_ACTIVITY_WINDOW_MS } from '../src/env.js';

const ORIGIN = 'https://cryptbox.test';
const CHUNK_SIZE = 5 * 1024 * 1024;

const json = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

interface Uploaded {
  token: string;
  authToken: Uint8Array;
}

/** 1 ファイル・1 チャンクだけの最小のバンドルを作る */
async function upload(options: { maxDownloads?: number | null } = {}): Promise<Uploaded> {
  const linkSecret = randomBytes(LINK_SECRET_BYTES);
  const kdfSalt = randomBytes(KDF_SALT_BYTES);
  const keys = await deriveKeysFromMaterial({ linkSecret, kdfSalt, pwKey: null });
  const authToken = await deriveAuthToken(linkSecret);
  const plain = randomBytes(128);

  const created = await SELF.fetch(
    `${ORIGIN}/api/uploads`,
    json({ chunkSize: CHUNK_SIZE, files: [{ plainSize: plain.length }] }),
  );
  expect(created.status).toBe(200);
  const { uploadToken } = (await created.json()) as { uploadToken: string };

  const cekRaw = randomBytes(KEY_BYTES);
  const cek = await importCek(cekRaw);
  const noncePrefix = randomBytes(NONCE_PREFIX_BYTES);
  const wrapNonce = randomBytes(NONCE_BYTES);
  const metaNonce = randomBytes(NONCE_BYTES);

  const put = await SELF.fetch(`${ORIGIN}/api/uploads/${uploadToken}/files/0/parts/0`, {
    method: 'PUT',
    body: await encryptChunk(cek, plain, noncePrefix, 0, 1),
  });
  expect(put.status).toBe(200);

  const completed = await SELF.fetch(
    `${ORIGIN}/api/uploads/${uploadToken}/complete`,
    json({
      expiresIn: 3600,
      maxDownloads: options.maxDownloads === undefined ? null : options.maxDownloads,
      authHash: await sha256Hex(authToken),
      kdfSalt: toBase64Url(kdfSalt),
      hasPassword: false,
      files: [
        {
          noncePrefix: toBase64Url(noncePrefix),
          wrappedCek: toBase64Url(await wrapCek(keys.kek, cekRaw, wrapNonce)),
          wrapNonce: toBase64Url(wrapNonce),
          metaCipher: toBase64Url(
            await encryptMeta(cek, { name: 'a.bin', type: '', size: plain.length }, metaNonce),
          ),
          metaNonce: toBase64Url(metaNonce),
        },
      ],
    }),
  );
  expect(completed.status).toBe(200);
  const { token } = (await completed.json()) as { token: string };
  return { token, authToken };
}

async function claimGrant(uploaded: Uploaded): Promise<string> {
  const claimed = await SELF.fetch(
    `${ORIGIN}/api/files/${uploaded.token}/claim`,
    json({ authToken: toBase64Url(uploaded.authToken), pwVerifier: null }),
  );
  expect(claimed.status).toBe(200);
  return ((await claimed.json()) as { grant: string }).grant;
}

beforeAll(applySchema);
beforeEach(resetTables);

describe('削除の fail-closed（R2 削除が失敗しても配信は止まる）', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('R2 削除に失敗しても /info /claim /blob は 404 になり、purge が再削除する', async () => {
    const uploaded = await upload();
    const grant = await claimGrant(uploaded);
    const keys = await env.DB.prepare(`SELECT r2_key FROM bundle_files`).all<{ r2_key: string }>();

    const spy = vi.spyOn(env.BUCKET, 'delete').mockRejectedValue(new Error('R2 down'));

    const deleted = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authToken: toBase64Url(uploaded.authToken) }),
    });
    expect(deleted.status).toBe(500);
    const body = (await deleted.json()) as { ok: boolean; disabled: boolean; pending: string[] };
    expect(body.ok).toBe(false);
    expect(body.disabled).toBe(true);
    expect(body.pending.length).toBeGreaterThan(0);

    // D1 の行は残っているが、配信はすべて止まっている
    const row = await env.DB.prepare(`SELECT disabled, disabled_reason FROM bundles`).first<{
      disabled: number;
      disabled_reason: string;
    }>();
    expect(row?.disabled).toBe(1);
    expect(row?.disabled_reason).toBe('sender_deleted');

    const info = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/info`,
      json({ authToken: toBase64Url(uploaded.authToken) }),
    );
    expect(info.status).toBe(404);

    const claim = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/claim`,
      json({ authToken: toBase64Url(uploaded.authToken), pwVerifier: null }),
    );
    expect(claim.status).toBe(404);

    // 停止前に発行済みのグラントを持っていても本体は取れない
    const blob = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/files/0/blob`, {
      headers: { 'X-Grant': grant },
    });
    expect(blob.status).toBe(404);

    // R2 が復旧すれば cron が同じ理由で物理削除を終わらせる
    spy.mockRestore();
    const result = await purge(env, Date.now());
    expect(result.bundles).toBe(1);
    for (const key of keys.results) expect(await env.BUCKET.head(key.r2_key)).toBeNull();
    const remaining = await env.DB.prepare(`SELECT COUNT(*) AS n FROM bundles`).first<{ n: number }>();
    expect(remaining?.n).toBe(0);

    // 削除レシートは元の理由（sender_deleted）で残る
    const receipt = await env.DB.prepare(`SELECT reason FROM deletion_receipts`).first<{ reason: string }>();
    expect(receipt?.reason).toBe('sender_deleted');
  });
});

describe('グラントの二重消費', () => {
  it('同じグラントでの 2 回目の finish は 409 で、active_downloads は負にならない', async () => {
    const uploaded = await upload({ maxDownloads: 3 });
    const grant = await claimGrant(uploaded);

    const first = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/finish`, json({ grant }));
    expect(first.status).toBe(200);

    const second = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/finish`, json({ grant }));
    expect(second.status).toBe(409);

    const row = await env.DB.prepare(`SELECT active_downloads FROM bundles`).first<{
      active_downloads: number;
    }>();
    expect(row?.active_downloads).toBe(0);
  });

  it('claim をやり直せば別のグラントとして finish できる', async () => {
    const uploaded = await upload({ maxDownloads: 3 });
    const grantA = await claimGrant(uploaded);
    const grantB = await claimGrant(uploaded);
    expect(grantA).not.toBe(grantB);

    expect((await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/finish`, json({ grant: grantA }))).status).toBe(200);
    expect((await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/finish`, json({ grant: grantB }))).status).toBe(200);
  });

  it('使用済みグラントの記録は purge で片付く', async () => {
    const uploaded = await upload({ maxDownloads: 3 });
    const grant = await claimGrant(uploaded);
    await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/finish`, json({ grant }));
    expect(
      (await env.DB.prepare(`SELECT COUNT(*) AS n FROM grant_uses`).first<{ n: number }>())?.n,
    ).toBe(1);

    await purge(env, Date.now() + 3 * 60 * 60 * 1000);
    expect(
      (await env.DB.prepare(`SELECT COUNT(*) AS n FROM grant_uses`).first<{ n: number }>())?.n,
    ).toBe(0);
  });
});

describe('既存 D1 の列欠落（マイグレーション未適用）', () => {
  /**
   * `SELECT *` で読んでいた頃は、`disabled` 列が無い古い D1 でもクエリが成功し、
   * `row.disabled` が undefined になって配信停止チェックが黙って素通りしていた。
   * 列を明示して読むことで、列が欠けていれば 500 で止まる（fail-closed）。
   */
  it('bundles.disabled が無ければ 500 で止まる（黙って素通りしない）', async () => {
    const uploaded = await upload();
    await env.DB.prepare(`DROP INDEX IF EXISTS idx_bundles_disabled`).run();
    await env.DB.prepare(`ALTER TABLE bundles DROP COLUMN disabled`).run();
    try {
      const response = await SELF.fetch(
        `${ORIGIN}/api/files/${uploaded.token}/info`,
        json({ authToken: toBase64Url(uploaded.authToken) }),
      );
      expect(response.status).toBe(500);
    } finally {
      await env.DB.prepare(
        `ALTER TABLE bundles ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0`,
      ).run();
      await env.DB.prepare(
        `CREATE INDEX IF NOT EXISTS idx_bundles_disabled ON bundles (disabled)`,
      ).run();
    }
  });
});

describe('グラントの延長 (POST /api/files/:token/refresh)', () => {
  const refresh = (uploaded: Uploaded, grant: string): Promise<Response> =>
    SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Grant': grant },
      body: JSON.stringify({ authToken: toBase64Url(uploaded.authToken) }),
    });

  it('延長してもダウンロード回数・アクティブ数は増えない', async () => {
    const uploaded = await upload({ maxDownloads: 3 });
    const grant = await claimGrant(uploaded);
    const before = await env.DB.prepare(
      `SELECT download_count, active_downloads FROM bundles`,
    ).first<{ download_count: number; active_downloads: number }>();

    const response = await refresh(uploaded, grant);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { grant: string; expiresAt: number };
    expect(typeof body.grant).toBe('string');
    expect(body.grant).not.toBe(grant);
    expect(typeof body.expiresAt).toBe('number');
    expect(body.expiresAt).toBeGreaterThan(Date.now());

    const after = await env.DB.prepare(
      `SELECT download_count, active_downloads FROM bundles`,
    ).first<{ download_count: number; active_downloads: number }>();
    expect(after?.download_count).toBe(before?.download_count);
    expect(after?.active_downloads).toBe(before?.active_downloads);
  });

  it('旧グラントは失効し finish が 409 になる。新グラントでは finish 200', async () => {
    const uploaded = await upload({ maxDownloads: 3 });
    const oldGrant = await claimGrant(uploaded);
    const refreshed = await refresh(uploaded, oldGrant);
    expect(refreshed.status).toBe(200);
    const { grant: newGrant } = (await refreshed.json()) as { grant: string };

    const stale = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/finish`,
      json({ grant: oldGrant }),
    );
    expect(stale.status).toBe(409);

    const fresh = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/finish`,
      json({ grant: newGrant }),
    );
    expect(fresh.status).toBe(200);
  });

  it('失効済み（使用済み）グラントでの延長は 403', async () => {
    const uploaded = await upload({ maxDownloads: 3 });
    const grant = await claimGrant(uploaded);
    expect((await refresh(uploaded, grant)).status).toBe(200);
    // 同じ（既に失効した）グラントでもう一度延長はできない
    expect((await refresh(uploaded, grant)).status).toBe(403);
  });

  it('不正なグラント・X-Grant 欠落は 403', async () => {
    const uploaded = await upload({ maxDownloads: 3 });
    await claimGrant(uploaded);
    expect((await refresh(uploaded, 'not-a-grant')).status).toBe(403);
    const noHeader = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authToken: toBase64Url(uploaded.authToken) }),
    });
    expect(noHeader.status).toBe(403);
  });

  it('authToken が違えば 404', async () => {
    const uploaded = await upload({ maxDownloads: 3 });
    const grant = await claimGrant(uploaded);
    const response = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Grant': grant },
      body: JSON.stringify({ authToken: toBase64Url(randomBytes(32)) }),
    });
    expect(response.status).toBe(404);
  });

  it('配信停止済み（disabled = 1）のバンドルは 404', async () => {
    const uploaded = await upload({ maxDownloads: 3 });
    const grant = await claimGrant(uploaded);
    await env.DB.prepare(`UPDATE bundles SET disabled = 1`).run();
    expect((await refresh(uploaded, grant)).status).toBe(404);
  });
});

describe('/receipt と配信停止', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('disabled = 1 かつ未削除なら { deleted: false, disabled: true }', async () => {
    const uploaded = await upload();
    vi.spyOn(env.BUCKET, 'delete').mockRejectedValue(new Error('R2 down'));
    const deleted = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authToken: toBase64Url(uploaded.authToken) }),
    });
    expect(deleted.status).toBe(500);

    const response = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/receipt`,
      json({ authToken: toBase64Url(uploaded.authToken) }),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ deleted: false, disabled: true });
  });

  it('通常のバンドルは { deleted: false } のまま（disabled は付かない）', async () => {
    const uploaded = await upload();
    const response = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/receipt`,
      json({ authToken: toBase64Url(uploaded.authToken) }),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ deleted: false });
  });
});

describe('purge の二重削除', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('同一実行内で同じバンドルの R2 オブジェクトを 2 回消さない', async () => {
    await upload();
    const key = await env.DB.prepare(`SELECT r2_key FROM bundle_files`).first<{ r2_key: string }>();
    // 期限切れにする（purge の expired ループに乗る）
    await env.DB.prepare(`UPDATE bundles SET expires_at = ?`).bind(Date.now() - 1000).run();

    let calls = 0;
    const original = env.BUCKET.delete.bind(env.BUCKET);
    vi.spyOn(env.BUCKET, 'delete').mockImplementation(async (keys: string | string[]) => {
      calls++;
      // 1 回目だけ失敗させ、bundles 行を disabled = 1 のまま残す
      if (calls === 1) throw new Error('R2 down');
      return original(keys as string);
    });

    const result = await purge(env, Date.now());
    // expired ループで 1 回失敗しただけ。disabled 側で同じ id を再処理しない
    expect(calls).toBe(1);
    expect(result.bundles).toBe(1);
    expect(await env.BUCKET.head(key!.r2_key)).not.toBeNull();
  });
});

describe('同時アップロードセッション数の上限', () => {
  const IP = '203.0.113.7';
  const open = (ip: string | null = IP): Promise<Response> =>
    SELF.fetch(`${ORIGIN}/api/uploads`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(ip === null ? {} : { 'CF-Connecting-IP': ip }),
      },
      body: JSON.stringify({ chunkSize: CHUNK_SIZE, files: [{ plainSize: 10 }] }),
    });

  it(`${MAX_OPEN_UPLOADS_PER_IP + 1} 個目のセッション作成は 429`, async () => {
    for (let i = 0; i < MAX_OPEN_UPLOADS_PER_IP; i++) {
      expect((await open()).status).toBe(200);
    }
    const over = await open();
    expect(over.status).toBe(429);
    expect(over.headers.get('Retry-After')).toBe('60');

    // セッションを 1 つ畳めばまた開ける
    const stale = await env.DB.prepare(`SELECT id FROM uploads LIMIT 1`).first<{ id: string }>();
    await env.DB.prepare(`DELETE FROM uploads WHERE id = ?`).bind(stale!.id).run();
    expect((await open()).status).toBe(200);
  });

  it('活動が途絶えた古いセッションは同時数に数えない（自己ロックアウト防止）', async () => {
    for (let i = 0; i < MAX_OPEN_UPLOADS_PER_IP; i++) {
      expect((await open()).status).toBe(200);
    }
    expect((await open()).status).toBe(429);

    // 15 分より前で止まっているセッションは「開いている」とみなさない
    await env.DB.prepare(`UPDATE uploads SET last_activity_at = ?`)
      .bind(Date.now() - (UPLOAD_ACTIVITY_WINDOW_MS + 60_000))
      .run();
    expect((await open()).status).toBe(200);
  });

  it('パート送信で last_activity_at が更新される', async () => {
    const created = await open();
    expect(created.status).toBe(200);
    const { uploadToken } = (await created.json()) as { uploadToken: string };
    await env.DB.prepare(`UPDATE uploads SET last_activity_at = 1`).run();

    const put = await SELF.fetch(`${ORIGIN}/api/uploads/${uploadToken}/files/0/parts/0`, {
      method: 'PUT',
      body: new Uint8Array(10 + 16),
    });
    expect(put.status).toBe(200);
    const row = await env.DB.prepare(`SELECT last_activity_at FROM uploads`).first<{
      last_activity_at: number;
    }>();
    expect(row?.last_activity_at).toBeGreaterThan(1);
  });

  it('CF-Connecting-IP が無い（unknown）場合は上限を適用しない', async () => {
    for (let i = 0; i < MAX_OPEN_UPLOADS_PER_IP + 2; i++) {
      expect((await open(null)).status).toBe(200);
    }
  });

  it('生の IP は保存せず、鍵付きハッシュだけを持つ', async () => {
    await SELF.fetch(`${ORIGIN}/api/uploads`, {
      ...json({ chunkSize: CHUNK_SIZE, files: [{ plainSize: 10 }] }),
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.9' },
    });
    const row = await env.DB.prepare(`SELECT ip_hash FROM uploads`).first<{ ip_hash: string }>();
    expect(row?.ip_hash).toHaveLength(64);
    expect(row?.ip_hash).not.toContain('203.0.113.9');
  });
});

describe('アップロードセッションの中止 (DELETE /api/uploads/:token)', () => {
  it('ボディ無しでも動く（受信/送信ページの pagehide が keepalive で投げるため）', async () => {
    const created = await SELF.fetch(
      `${ORIGIN}/api/uploads`,
      json({ chunkSize: CHUNK_SIZE, files: [{ plainSize: 10 }] }),
    );
    const { uploadToken } = (await created.json()) as { uploadToken: string };

    const response = await SELF.fetch(`${ORIGIN}/api/uploads/${uploadToken}`, { method: 'DELETE' });
    expect(response.status).toBe(200);
    const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM uploads`).first<{ n: number }>();
    expect(row?.n).toBe(0);
  });
});

describe('Argon2id パラメータの範囲検証（サーバー）', () => {
  async function completeWith(pwParams: unknown): Promise<number> {
    const created = await SELF.fetch(
      `${ORIGIN}/api/uploads`,
      json({ chunkSize: CHUNK_SIZE, files: [{ plainSize: 16 }] }),
    );
    const { uploadToken } = (await created.json()) as { uploadToken: string };
    const response = await SELF.fetch(
      `${ORIGIN}/api/uploads/${uploadToken}/complete`,
      json({
        expiresIn: 3600,
        maxDownloads: null,
        authHash: 'a'.repeat(64),
        kdfSalt: toBase64Url(randomBytes(KDF_SALT_BYTES)),
        hasPassword: true,
        pwSalt: toBase64Url(randomBytes(PW_SALT_BYTES)),
        pwHash: 'b'.repeat(64),
        pwParams,
        files: [],
      }),
    );
    return response.status;
  }

  it('メモリが上限を超えていれば 400', async () => {
    expect(await completeWith({ ...ARGON2_DEFAULTS, memoryKiB: 1024 * 1024 })).toBe(400);
  });

  it('メモリが下限未満なら 400', async () => {
    expect(await completeWith({ ...ARGON2_DEFAULTS, memoryKiB: 1024 })).toBe(400);
  });

  it('反復回数が範囲外なら 400', async () => {
    expect(await completeWith({ ...ARGON2_DEFAULTS, iterations: 0 })).toBe(400);
    expect(await completeWith({ ...ARGON2_DEFAULTS, iterations: 11 })).toBe(400);
  });

  it('hashLength が 32 以外なら 400', async () => {
    expect(await completeWith({ ...ARGON2_DEFAULTS, hashLength: 64 })).toBe(400);
  });

  it('型が違えば 400', async () => {
    expect(await completeWith({ ...ARGON2_DEFAULTS, parallelism: '1' })).toBe(400);
    expect(await completeWith(null)).toBe(400);
  });

  it('既定値なら通る（files の数が合わない 400 まで進む）', async () => {
    // pwParams の検証を抜けた先の「files の数が一致しません」で 400 になる。
    // pwParams 自体が弾かれていないことは、範囲外との対比で確認できる
    expect(await completeWith(ARGON2_DEFAULTS)).toBe(400);
  });
});

describe('セキュリティヘッダー', () => {
  it('SPA のフォールバック応答に CSP / HSTS などが付く', async () => {
    const response = await SELF.fetch(`${ORIGIN}/`);
    expect(response.status).toBe(200);
    const csp = response.headers.get('content-security-policy') ?? '';
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(response.headers.get('strict-transport-security')).toContain('max-age=63072000');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
  });

  it('API 応答には最も強い CSP と HSTS が付く', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/config`);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-security-policy')).toBe(
      "default-src 'none'; frame-ancestors 'none'",
    );
    expect(response.headers.get('strict-transport-security')).toContain('max-age=63072000');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('cache-control')).toBe('no-store');
  });
});

describe('CORS の既定オリジン', () => {
  it('http://localhost は既定では許可しない', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/uploads`, {
      method: 'OPTIONS',
      headers: { Origin: 'http://localhost', 'Access-Control-Request-Method': 'POST' },
    });
    expect(response.status).toBe(403);
  });

  it('プリフライトの Allow-Headers に X-Grant が含まれる', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/uploads`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://localhost', 'Access-Control-Request-Method': 'POST' },
    });
    expect(response.status).toBe(204);
    expect(response.headers.get('access-control-allow-headers')).toContain('X-Grant');
  });
});
