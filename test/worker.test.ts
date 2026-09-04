import { SELF, env } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { applySchema, resetTables } from './helpers.js';
import { purge } from '../src/index.js';
import {
  decryptChunk,
  decryptMeta,
  deriveAuthToken,
  deriveKeysFromMaterial,
  encryptChunk,
  encryptMeta,
  importCek,
  randomBytes,
  sha256Hex,
  unwrapCek,
  wrapCek,
} from '../web/src/crypto.js';
import {
  KDF_SALT_BYTES,
  KEY_BYTES,
  LINK_SECRET_BYTES,
  NONCE_BYTES,
  NONCE_PREFIX_BYTES,
  PW_SALT_BYTES,
  fromBase64Url,
  toBase64Url,
  totalChunks,
} from '../shared/format.js';
import type { DeletionReceipt } from '../shared/receipt.js';

const ORIGIN = 'https://cryptbox.test';
const CHUNK_SIZE = 5 * 1024 * 1024;

/**
 * workerd は実行時の WebAssembly.compile を禁じているため、この結合テストでは
 * Argon2id の代わりに SHA-256 でパスワードを伸長する。
 * サーバーは伸長方式を一切知らない（受け取るのは検証値のハッシュだけ）ので、
 * ここで検証したいサーバー側の振る舞いは変わらない。
 * Argon2id 自体は test/node/argon2.test.ts で検証している。
 */
const ARGON2_PARAMS = { memoryKiB: 1024, iterations: 1, parallelism: 1, hashLength: 32 };

async function stretch(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const encoded = new TextEncoder().encode(password);
  const input = new Uint8Array(salt.length + encoded.length);
  input.set(salt, 0);
  input.set(encoded, salt.length);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input));
}

interface Uploaded {
  token: string;
  linkSecret: Uint8Array;
  authToken: Uint8Array;
}

const json = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

async function upload(
  contents: Uint8Array[],
  options: { expiresIn?: number; maxDownloads?: number | null; password?: string } = {},
): Promise<Uploaded> {
  const linkSecret = randomBytes(LINK_SECRET_BYTES);
  const kdfSalt = randomBytes(KDF_SALT_BYTES);
  const pwSalt = randomBytes(PW_SALT_BYTES);

  const keys = await deriveKeysFromMaterial({
    linkSecret,
    kdfSalt,
    pwKey: options.password ? await stretch(options.password, pwSalt) : null,
  });
  const authToken = await deriveAuthToken(linkSecret);

  const created = await SELF.fetch(
    `${ORIGIN}/api/uploads`,
    json({ chunkSize: CHUNK_SIZE, files: contents.map((plain) => ({ plainSize: plain.length })) }),
  );
  expect(created.status).toBe(200);
  const { uploadToken } = (await created.json()) as { uploadToken: string };

  const fileMetas: unknown[] = [];
  for (const [fileIndex, plain] of contents.entries()) {
    const cekRaw = randomBytes(KEY_BYTES);
    const cek = await importCek(cekRaw);
    const noncePrefix = randomBytes(NONCE_PREFIX_BYTES);
    const wrapNonce = randomBytes(NONCE_BYTES);
    const metaNonce = randomBytes(NONCE_BYTES);
    const chunks = totalChunks(plain.length, CHUNK_SIZE);

    for (let i = 0; i < chunks; i++) {
      const slice = plain.subarray(i * CHUNK_SIZE, Math.min(plain.length, (i + 1) * CHUNK_SIZE));
      const cipher = await encryptChunk(cek, slice, noncePrefix, i, chunks);
      const put = await SELF.fetch(
        `${ORIGIN}/api/uploads/${uploadToken}/files/${fileIndex}/parts/${i}`,
        { method: 'PUT', body: cipher },
      );
      expect(put.status).toBe(200);
    }

    fileMetas.push({
      noncePrefix: toBase64Url(noncePrefix),
      wrappedCek: toBase64Url(await wrapCek(keys.kek, cekRaw, wrapNonce)),
      wrapNonce: toBase64Url(wrapNonce),
      metaCipher: toBase64Url(
        await encryptMeta(
          cek,
          { name: `サンプル${fileIndex}.bin`, type: '', size: plain.length },
          metaNonce,
        ),
      ),
      metaNonce: toBase64Url(metaNonce),
    });
  }

  const completed = await SELF.fetch(
    `${ORIGIN}/api/uploads/${uploadToken}/complete`,
    json({
      expiresIn: options.expiresIn ?? 3600,
      maxDownloads: options.maxDownloads === undefined ? null : options.maxDownloads,
      authHash: await sha256Hex(authToken),
      kdfSalt: toBase64Url(kdfSalt),
      hasPassword: Boolean(options.password),
      pwSalt: options.password ? toBase64Url(pwSalt) : null,
      pwParams: options.password ? ARGON2_PARAMS : null,
      pwHash: keys.pwVerifier ? await sha256Hex(keys.pwVerifier) : null,
      files: fileMetas,
    }),
  );
  expect(completed.status).toBe(200);
  const { token } = (await completed.json()) as { token: string };
  return { token, linkSecret, authToken };
}

interface RemoteFile {
  index: number;
  plainSize: number;
  chunkSize: number;
  totalChunks: number;
  noncePrefix: string;
  wrappedCek: string;
  wrapNonce: string;
  metaCipher: string;
  metaNonce: string;
}

async function download(uploaded: Uploaded, password?: string): Promise<Uint8Array[]> {
  const infoResponse = await SELF.fetch(
    `${ORIGIN}/api/files/${uploaded.token}/info`,
    json({ authToken: toBase64Url(uploaded.authToken) }),
  );
  expect(infoResponse.status).toBe(200);
  const info = (await infoResponse.json()) as {
    kdfSalt: string;
    pwSalt: string | null;
    files: RemoteFile[];
  };

  const keys = await deriveKeysFromMaterial({
    linkSecret: uploaded.linkSecret,
    kdfSalt: fromBase64Url(info.kdfSalt),
    pwKey: password && info.pwSalt ? await stretch(password, fromBase64Url(info.pwSalt)) : null,
  });

  const claimed = await SELF.fetch(
    `${ORIGIN}/api/files/${uploaded.token}/claim`,
    json({
      authToken: toBase64Url(uploaded.authToken),
      pwVerifier: keys.pwVerifier ? toBase64Url(keys.pwVerifier) : null,
    }),
  );
  expect(claimed.status).toBe(200);
  const { grant } = (await claimed.json()) as { grant: string };

  const restored: Uint8Array[] = [];
  for (const file of info.files) {
    const cek = await importCek(
      await unwrapCek(keys.kek, fromBase64Url(file.wrappedCek), fromBase64Url(file.wrapNonce)),
    );
    const meta = await decryptMeta(
      cek,
      fromBase64Url(file.metaCipher),
      fromBase64Url(file.metaNonce),
    );
    expect(meta.name).toBe(`サンプル${file.index}.bin`);

    const blob = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/files/${file.index}/blob?g=${encodeURIComponent(grant)}`,
    );
    expect(blob.status).toBe(200);
    const cipher = new Uint8Array(await blob.arrayBuffer());

    const noncePrefix = fromBase64Url(file.noncePrefix);
    const out = new Uint8Array(file.plainSize);
    let cipherOffset = 0;
    let plainOffset = 0;
    for (let i = 0; i < file.totalChunks; i++) {
      const plainLength = Math.min(file.chunkSize, file.plainSize - i * file.chunkSize);
      const piece = cipher.subarray(cipherOffset, cipherOffset + plainLength + 16);
      out.set(await decryptChunk(cek, piece, noncePrefix, i, file.totalChunks), plainOffset);
      cipherOffset += piece.length;
      plainOffset += plainLength;
    }
    restored.push(out);
  }
  return restored;
}

beforeAll(applySchema);
beforeEach(resetTables);

describe('アップロードとダウンロードの往復', () => {
  it('複数チャンクのファイルをバイト単位で復元できる', async () => {
    const plain = randomBytes(CHUNK_SIZE + 1234);
    const [restored] = await download(await upload([plain]));
    expect(restored!.length).toBe(plain.length);
    expect(await sha256Hex(restored!)).toBe(await sha256Hex(plain));
  });

  it('1 つのリンクで複数ファイルを送れる', async () => {
    const files = [randomBytes(4096), randomBytes(CHUNK_SIZE + 10), randomBytes(1)];
    const restored = await download(await upload(files));
    expect(restored).toHaveLength(3);
    for (const [index, original] of files.entries()) {
      expect(await sha256Hex(restored[index]!)).toBe(await sha256Hex(original));
    }
  });

  it('空ファイルも扱える', async () => {
    const [restored] = await download(await upload([new Uint8Array(0)]));
    expect(restored!.length).toBe(0);
  });

  it('パスワード付きファイルを往復できる', async () => {
    const plain = randomBytes(2048);
    const uploaded = await upload([plain], { password: 'とても長いパスフレーズ' });
    const [restored] = await download(uploaded, 'とても長いパスフレーズ');
    expect(await sha256Hex(restored!)).toBe(await sha256Hex(plain));
  });
});

describe('アクセス制御', () => {
  it('authToken が違えば 404', async () => {
    const uploaded = await upload([randomBytes(128)]);
    const response = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/info`,
      json({ authToken: toBase64Url(randomBytes(32)) }),
    );
    expect(response.status).toBe(404);
  });

  it('グラント無しでは本体を取得できない', async () => {
    const uploaded = await upload([randomBytes(128)]);
    const response = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/files/0/blob`);
    expect(response.status).toBe(403);
  });

  it('パスワードが違えばダウンロード回数を消費せずに 401', async () => {
    const uploaded = await upload([randomBytes(128)], {
      password: 'ただしいパスワード',
      maxDownloads: 1,
    });
    const response = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/claim`,
      json({
        authToken: toBase64Url(uploaded.authToken),
        pwVerifier: toBase64Url(randomBytes(32)),
      }),
    );
    expect(response.status).toBe(401);

    const row = await env.DB.prepare('SELECT download_count FROM bundles').first<{
      download_count: number;
    }>();
    expect(row?.download_count).toBe(0);
  });

  it('リンクを知っていれば即時削除できる', async () => {
    const uploaded = await upload([randomBytes(256)]);
    const deleted = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authToken: toBase64Url(uploaded.authToken) }),
    });
    expect(deleted.status).toBe(200);

    const after = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/info`,
      json({ authToken: toBase64Url(uploaded.authToken) }),
    );
    expect(after.status).toBe(404);
    const files = await env.DB.prepare('SELECT COUNT(*) AS n FROM bundle_files').first<{ n: number }>();
    expect(files?.n).toBe(0);
  });
});

describe('ダウンロード回数制限', () => {
  it('バンドル単位で数える（ファイル数では減らない）', async () => {
    const uploaded = await upload([randomBytes(128), randomBytes(128)], { maxDownloads: 1 });
    await download(uploaded);

    const row = await env.DB.prepare('SELECT download_count FROM bundles').first<{
      download_count: number;
    }>();
    expect(row?.download_count).toBe(1);

    const second = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/claim`,
      json({ authToken: toBase64Url(uploaded.authToken), pwVerifier: null }),
    );
    expect(second.status).toBe(410);
  });
});

describe('回数到達時の完全削除', () => {
  async function claimGrant(uploaded: Uploaded): Promise<string> {
    const claimed = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/claim`,
      json({ authToken: toBase64Url(uploaded.authToken), pwVerifier: null }),
    );
    expect(claimed.status).toBe(200);
    return ((await claimed.json()) as { grant: string }).grant;
  }

  it('最後の 1 回が finish した瞬間に R2 ごと消え、リンクも無効になる', async () => {
    const uploaded = await upload([randomBytes(256), randomBytes(64)], { maxDownloads: 1 });
    const keys = await env.DB.prepare('SELECT r2_key FROM bundle_files').all<{ r2_key: string }>();
    const grant = await claimGrant(uploaded);

    const finish = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/finish`, json({ grant }));
    expect(finish.status).toBe(200);
    expect(((await finish.json()) as { deleted: boolean }).deleted).toBe(true);

    // R2 のオブジェクトも D1 の行も残っていない
    for (const key of keys.results) expect(await env.BUCKET.head(key.r2_key)).toBeNull();
    const rows = await env.DB.prepare('SELECT COUNT(*) AS n FROM bundles').first<{ n: number }>();
    expect(rows?.n).toBe(0);

    // リンクは無効
    const info = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/info`,
      json({ authToken: toBase64Url(uploaded.authToken) }),
    );
    expect(info.status).toBe(404);
  });

  it('上限に達していなければ finish しても消えない', async () => {
    const uploaded = await upload([randomBytes(128)], { maxDownloads: 2 });
    const grant = await claimGrant(uploaded);
    const finish = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/finish`, json({ grant }));
    expect(((await finish.json()) as { deleted: boolean }).deleted).toBe(false);

    const info = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/info`,
      json({ authToken: toBase64Url(uploaded.authToken) }),
    );
    expect(info.status).toBe(200);
  });

  it('finish が来なくても ping の途絶から猶予時間で purge が消す', async () => {
    const uploaded = await upload([randomBytes(128)], { maxDownloads: 1 });
    const grant = await claimGrant(uploaded);

    // ダウンロード中（ping あり）は消えない
    const ping = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/ping`, json({ grant }));
    expect(ping.status).toBe(200);
    expect((await purge(env, Date.now() + 60_000)).bundles).toBe(0);

    // 途絶から 15 分（既定の猶予）を超えると消える
    expect((await purge(env, Date.now() + 16 * 60_000)).bundles).toBe(1);
  });

  it('偽のグラントでは finish も ping もできない', async () => {
    const uploaded = await upload([randomBytes(128)], { maxDownloads: 1 });
    const finish = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/finish`,
      json({ grant: 'x.y.z' }),
    );
    expect(finish.status).toBe(403);
  });
});

describe('期限切れ時の完全削除', () => {
  it('期限切れリンクへのアクセスで、その場で R2 ごと消える', async () => {
    const uploaded = await upload([randomBytes(256)]);
    const keys = await env.DB.prepare('SELECT r2_key FROM bundle_files').all<{ r2_key: string }>();

    await env.DB.prepare('UPDATE bundles SET expires_at = ?').bind(Date.now() - 1000).run();

    const info = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/info`,
      json({ authToken: toBase64Url(uploaded.authToken) }),
    );
    expect(info.status).toBe(410);

    for (const key of keys.results) expect(await env.BUCKET.head(key.r2_key)).toBeNull();
    const rows = await env.DB.prepare('SELECT COUNT(*) AS n FROM bundles').first<{ n: number }>();
    expect(rows?.n).toBe(0);
  });
});

describe('レンジ取得', () => {
  it('206 と Content-Range を返す', async () => {
    const uploaded = await upload([randomBytes(1000)]);
    const claimed = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/claim`,
      json({ authToken: toBase64Url(uploaded.authToken), pwVerifier: null }),
    );
    const { grant } = (await claimed.json()) as { grant: string };

    const response = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/files/0/blob?g=${encodeURIComponent(grant)}`,
      { headers: { Range: 'bytes=100-199' } },
    );
    expect(response.status).toBe(206);
    expect(response.headers.get('content-range')).toBe(`bytes 100-199/${1000 + 16}`);
    expect((await response.arrayBuffer()).byteLength).toBe(100);
  });
});

describe('自動削除', () => {
  it('期限切れのバンドルは本体ごと消える', async () => {
    const uploaded = await upload([randomBytes(256), randomBytes(256)], { expiresIn: 3600 });
    const keys = await env.DB.prepare('SELECT r2_key FROM bundle_files').all<{ r2_key: string }>();
    expect(keys.results).toHaveLength(2);
    for (const key of keys.results) expect(await env.BUCKET.head(key.r2_key)).not.toBeNull();

    const result = await purge(env, Date.now() + 3601 * 1000);
    expect(result.bundles).toBe(1);
    for (const key of keys.results) expect(await env.BUCKET.head(key.r2_key)).toBeNull();

    const response = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/info`,
      json({ authToken: toBase64Url(uploaded.authToken) }),
    );
    expect(response.status).toBe(404);
  });

  it('放棄されたアップロードセッションも消える', async () => {
    const created = await SELF.fetch(
      `${ORIGIN}/api/uploads`,
      json({ chunkSize: CHUNK_SIZE, files: [{ plainSize: 1024 }] }),
    );
    expect(created.status).toBe(200);

    const result = await purge(env, Date.now() + 25 * 60 * 60 * 1000);
    expect(result.uploads).toBe(1);
    const remaining = await env.DB.prepare('SELECT COUNT(*) AS n FROM uploads').first<{ n: number }>();
    expect(remaining?.n).toBe(0);
  });
});

describe('入力検証', () => {
  it('小さすぎる chunkSize は拒否する', async () => {
    const response = await SELF.fetch(
      `${ORIGIN}/api/uploads`,
      json({ chunkSize: 1024, files: [{ plainSize: 100 }] }),
    );
    expect(response.status).toBe(400);
  });

  it('合計サイズが上限を超えると拒否する', async () => {
    const response = await SELF.fetch(
      `${ORIGIN}/api/uploads`,
      json({
        chunkSize: CHUNK_SIZE,
        files: [{ plainSize: 600 * 1024 * 1024 }, { plainSize: 600 * 1024 * 1024 }],
      }),
    );
    expect(response.status).toBe(400);
  });

  it('ファイル数が 0 なら拒否する', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/uploads`, json({ chunkSize: CHUNK_SIZE, files: [] }));
    expect(response.status).toBe(400);
  });

  it('complete でファイル数が合わなければ拒否する', async () => {
    const created = await SELF.fetch(
      `${ORIGIN}/api/uploads`,
      json({ chunkSize: CHUNK_SIZE, files: [{ plainSize: 10 }] }),
    );
    const { uploadToken } = (await created.json()) as { uploadToken: string };
    const response = await SELF.fetch(
      `${ORIGIN}/api/uploads/${uploadToken}/complete`,
      json({
        expiresIn: 3600,
        maxDownloads: null,
        authHash: 'a'.repeat(64),
        kdfSalt: toBase64Url(randomBytes(KDF_SALT_BYTES)),
        hasPassword: false,
        files: [],
      }),
    );
    expect(response.status).toBe(400);
  });
});

describe('CORS（スマホアプリからの呼び出し）', () => {
  it('Capacitor のオリジンからのプリフライトを許可する', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/uploads`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'capacitor://localhost',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type',
      },
    });
    expect(response.status).toBe(204);
    expect(response.headers.get('access-control-allow-origin')).toBe('capacitor://localhost');
    expect(response.headers.get('access-control-allow-headers')).toContain('Range');
  });

  it('許可リストにないオリジンには CORS ヘッダーを返さない', async () => {
    const preflight = await SELF.fetch(`${ORIGIN}/api/uploads`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' },
    });
    expect(preflight.status).toBe(403);

    const response = await SELF.fetch(`${ORIGIN}/api/uploads`, {
      ...json({ chunkSize: CHUNK_SIZE, files: [{ plainSize: 10 }] }),
      headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' },
    });
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('実リクエストにも Allow-Origin と Expose-Headers を付ける', async () => {
    const response = await SELF.fetch(`${ORIGIN}/api/uploads`, {
      ...json({ chunkSize: CHUNK_SIZE, files: [{ plainSize: 10 }] }),
      headers: { 'Content-Type': 'application/json', Origin: 'https://localhost' },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('access-control-allow-origin')).toBe('https://localhost');
    expect(response.headers.get('access-control-expose-headers')).toContain('Content-Range');
  });
});

describe('削除レシート', () => {
  async function verifyReceipt(receipt: unknown): Promise<boolean> {
    const response = await SELF.fetch(`${ORIGIN}/api/receipts/verify`, json({ receipt }));
    expect(response.status).toBe(200);
    return ((await response.json()) as { valid: boolean }).valid;
  }

  async function fetchReceipt(
    token: string,
    authToken?: Uint8Array,
  ): Promise<{ status: number; body: { deleted: boolean; receipt?: DeletionReceipt } }> {
    const response = await SELF.fetch(
      `${ORIGIN}/api/files/${token}/receipt`,
      json(authToken ? { authToken: toBase64Url(authToken) } : {}),
    );
    return { status: response.status, body: (await response.json()) as never };
  }

  it('回数上限到達の finish はレシートを返し、署名も検証できる', async () => {
    const uploaded = await upload([randomBytes(128), randomBytes(64)], { maxDownloads: 1 });
    const claimed = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/claim`,
      json({ authToken: toBase64Url(uploaded.authToken), pwVerifier: null }),
    );
    const { grant } = (await claimed.json()) as { grant: string };

    const finish = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/finish`, json({ grant }));
    expect(finish.status).toBe(200);
    const body = (await finish.json()) as { deleted: boolean; receipt: DeletionReceipt };
    expect(body.deleted).toBe(true);
    expect(body.receipt.reason).toBe('limit_reached');
    expect(body.receipt.fileCount).toBe(2);
    expect(await verifyReceipt(body.receipt)).toBe(true);
  });

  it('署名や理由を書き換えると検証に失敗する', async () => {
    const uploaded = await upload([randomBytes(64)], { maxDownloads: 1 });
    const claimed = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/claim`,
      json({ authToken: toBase64Url(uploaded.authToken), pwVerifier: null }),
    );
    const { grant } = (await claimed.json()) as { grant: string };
    const finish = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}/finish`, json({ grant }));
    const { receipt } = (await finish.json()) as { receipt: DeletionReceipt };

    const tamperedSignature = { ...receipt, signature: `${receipt.signature.slice(0, -1)}x` };
    expect(await verifyReceipt(tamperedSignature)).toBe(false);

    const tamperedReason = { ...receipt, reason: 'expired' };
    expect(await verifyReceipt(tamperedReason)).toBe(false);
  });

  it('送信者の即時削除は sender_deleted のレシートを残す', async () => {
    const uploaded = await upload([randomBytes(256)]);
    const deleted = await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authToken: toBase64Url(uploaded.authToken) }),
    });
    expect(deleted.status).toBe(200);
    const deletedBody = (await deleted.json()) as { receipt: DeletionReceipt };
    expect(deletedBody.receipt.reason).toBe('sender_deleted');

    const { status, body } = await fetchReceipt(uploaded.token, uploaded.authToken);
    expect(status).toBe(200);
    expect(body.deleted).toBe(true);
    expect(body.receipt!.reason).toBe('sender_deleted');
    expect(await verifyReceipt(body.receipt)).toBe(true);
  });

  it('期限切れへのアクセスは 410 の本文に expired のレシートを含む', async () => {
    const uploaded = await upload([randomBytes(128)]);
    await env.DB.prepare('UPDATE bundles SET expires_at = ?').bind(Date.now() - 1000).run();

    const info = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/info`,
      json({ authToken: toBase64Url(uploaded.authToken) }),
    );
    expect(info.status).toBe(410);
    const infoBody = (await info.json()) as { receipt: DeletionReceipt };
    expect(infoBody.receipt.reason).toBe('expired');
    expect(await verifyReceipt(infoBody.receipt)).toBe(true);
  });

  it('cron 経由の期限切れ削除も expired のレシートを残す', async () => {
    const uploaded = await upload([randomBytes(128)], { expiresIn: 3600 });
    await purge(env, Date.now() + 3601 * 1000);

    const { status, body } = await fetchReceipt(uploaded.token, uploaded.authToken);
    expect(status).toBe(200);
    expect(body.deleted).toBe(true);
    expect(body.receipt!.reason).toBe('expired');
  });

  it('cron 経由の回数上限削除も limit_reached のレシートを残す', async () => {
    const uploaded = await upload([randomBytes(128)], { maxDownloads: 1 });
    const claimed = await SELF.fetch(
      `${ORIGIN}/api/files/${uploaded.token}/claim`,
      json({ authToken: toBase64Url(uploaded.authToken), pwVerifier: null }),
    );
    expect(claimed.status).toBe(200);
    await purge(env, Date.now() + 16 * 60_000);

    const { body } = await fetchReceipt(uploaded.token, uploaded.authToken);
    expect(body.deleted).toBe(true);
    expect(body.receipt!.reason).toBe('limit_reached');
  });

  it('未削除のバンドルは deleted: false、存在しないトークンは 404', async () => {
    const uploaded = await upload([randomBytes(128)]);
    const { status, body } = await fetchReceipt(uploaded.token, uploaded.authToken);
    expect(status).toBe(200);
    expect(body.deleted).toBe(false);

    const missing = await fetchReceipt(toBase64Url(randomBytes(32)), randomBytes(32));
    expect(missing.status).toBe(404);
  });

  it('authToken が無い／不正だと 404（未削除・削除済みいずれも、共有 URL のパスだけでは取れない）', async () => {
    const uploaded = await upload([randomBytes(64)]);

    const noAuth = await fetchReceipt(uploaded.token);
    expect(noAuth.status).toBe(404);
    const wrongAuth = await fetchReceipt(uploaded.token, randomBytes(32));
    expect(wrongAuth.status).toBe(404);

    await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authToken: toBase64Url(uploaded.authToken) }),
    });

    const noAuthDeleted = await fetchReceipt(uploaded.token);
    expect(noAuthDeleted.status).toBe(404);
    const wrongAuthDeleted = await fetchReceipt(uploaded.token, randomBytes(32));
    expect(wrongAuthDeleted.status).toBe(404);
    const rightAuthDeleted = await fetchReceipt(uploaded.token, uploaded.authToken);
    expect(rightAuthDeleted.status).toBe(200);
    expect(rightAuthDeleted.body.deleted).toBe(true);
  });

  it('欠落・型不正なレシートは 400 ではなく valid: false を返す', async () => {
    expect(await verifyReceipt({})).toBe(false);
    expect(await verifyReceipt(null)).toBe(false);
    expect(await verifyReceipt({ version: 2 })).toBe(false);
  });

  it('保持期間を過ぎたレシートは purge で消える', async () => {
    const uploaded = await upload([randomBytes(64)]);
    await SELF.fetch(`${ORIGIN}/api/files/${uploaded.token}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authToken: toBase64Url(uploaded.authToken) }),
    });

    const before = await env.DB.prepare('SELECT COUNT(*) AS n FROM deletion_receipts').first<{
      n: number;
    }>();
    expect(before?.n).toBe(1);

    // 既定の保持期間 (90 日) より手前では消えない
    await purge(env, Date.now() + 89 * 24 * 60 * 60 * 1000);
    const stillThere = await env.DB.prepare('SELECT COUNT(*) AS n FROM deletion_receipts').first<{
      n: number;
    }>();
    expect(stillThere?.n).toBe(1);

    // 保持期間を過ぎると消える
    const result = await purge(env, Date.now() + 91 * 24 * 60 * 60 * 1000);
    expect(result.receipts).toBe(1);
    const after = await env.DB.prepare('SELECT COUNT(*) AS n FROM deletion_receipts').first<{
      n: number;
    }>();
    expect(after?.n).toBe(0);
  });

  it('保持期間切れが 500 件を超えると 1 回の purge では消しきれず、次回 cron に持ち越される', async () => {
    const now = Date.now();
    const deletedAt = now - 91 * 24 * 60 * 60 * 1000; // 保持期間 (既定 90 日) を過ぎている
    const total = 501;
    const writes = Array.from({ length: total }, (_, i) =>
      env.DB.prepare(
        `INSERT INTO deletion_receipts
           (bundle_id, created_at, deleted_at, reason, file_count, total_plain_size, signature, auth_hash)
         VALUES (?, ?, ?, 'sender_deleted', 1, 1, 'sig', 'auth')`,
      ).bind(`bundle-${i}`, deletedAt, deletedAt),
    );
    // D1.batch は一度に大量のステートメントを投げられないので分割する
    for (let i = 0; i < writes.length; i += 100) {
      await env.DB.batch(writes.slice(i, i + 100));
    }

    const countRows = async () =>
      (
        await env.DB.prepare('SELECT COUNT(*) AS n FROM deletion_receipts').first<{ n: number }>()
      )?.n;
    expect(await countRows()).toBe(total);

    const first = await purge(env, now);
    expect(first.receipts).toBe(500);
    expect(await countRows()).toBe(1);

    const second = await purge(env, now);
    expect(second.receipts).toBe(1);
    expect(await countRows()).toBe(0);
  });
});
